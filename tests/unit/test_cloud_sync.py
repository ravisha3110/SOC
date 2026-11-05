"""Unit tests for CyberShield Hybrid Cloud Synchronization Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch
import pytest

from security.cloud_sync import (
    CloudConnectionStatus,
    CloudSyncEngine,
    SyncConflict,
    SyncDirection,
    SyncSummary,
)


def test_conflict_and_summary_serialization() -> None:
    """Verify serialization of SyncConflict and SyncSummary objects."""
    conflict = SyncConflict(
        table_name="url_analysis",
        record_id="u-1",
        local_data={"url": "http://example.com", "risk_score": 10.0},
        cloud_data={"url": "http://example.com", "risk_score": 90.0},
        conflict_reason="Risk score divergence",
    )
    c_dict = conflict.to_dict()
    assert c_dict["table_name"] == "url_analysis"
    assert c_dict["record_id"] == "u-1"
    assert c_dict["conflict_reason"] == "Risk score divergence"

    summary = SyncSummary(
        status="SUCCESS",
        cloud_status=CloudConnectionStatus.ONLINE,
        direction=SyncDirection.BIDIRECTIONAL,
        started_at="2026-11-05T00:00:00Z",
        completed_at="2026-11-05T00:00:01Z",
        records_uploaded=5,
        records_downloaded=2,
        conflicts_detected=1,
        conflicts=[conflict],
        errors=[],
        table_stats={"threats": {"uploaded": 5, "downloaded": 2}},
    )
    s_dict = summary.to_dict()
    assert s_dict["status"] == "SUCCESS"
    assert s_dict["records_uploaded"] == 5
    assert len(s_dict["conflicts"]) == 1


def test_check_cloud_status() -> None:
    """Verify cloud connection status checks under various conditions."""
    mock_sqlite = MagicMock()
    mock_pg = MagicMock()

    # 1. Not configured
    mock_pg.is_configured = False
    engine = CloudSyncEngine(mock_sqlite, mock_pg)
    assert engine.check_cloud_status() == CloudConnectionStatus.NOT_CONFIGURED

    # 2. Configured and online
    mock_pg.is_configured = True
    mock_pg.test_connection.return_value = True
    assert engine.check_cloud_status() == CloudConnectionStatus.ONLINE

    # 3. Configured and offline
    mock_pg.test_connection.return_value = False
    assert engine.check_cloud_status() == CloudConnectionStatus.OFFLINE

    # 4. Exception
    mock_pg.test_connection.side_effect = RuntimeError("Socket timeout")
    assert engine.check_cloud_status() == CloudConnectionStatus.ERROR


def test_get_status_overview() -> None:
    """Verify telemetry overview compilation and counts."""
    mock_sqlite = MagicMock()
    mock_pg = MagicMock()
    mock_pg.is_configured = True
    mock_pg.test_connection.return_value = True
    mock_pg.sanitized_url = "postgresql://user:***@neon.tech/db"

    mock_sqlite.fetch_one.side_effect = [
        {"c": 3},  # scan_history
        {"c": 5},  # threats
        {"c": 2},  # file_integrity
        Exception("DB locked"),  # url_analysis exception handling
        {"c": 1},  # network_logs
    ]

    engine = CloudSyncEngine(mock_sqlite, mock_pg)
    overview = engine.get_status_overview()

    assert overview["cloud_status"] == "ONLINE"
    assert overview["is_connected"] is True
    assert overview["total_local_records"] == 11
    assert "neon.tech" in overview["masked_target_url"]


def test_synchronize_offline_abort() -> None:
    """Verify synchronization aborts safely when cloud is offline, keeping local operations safe."""
    mock_sqlite = MagicMock()
    mock_pg = MagicMock()
    mock_pg.is_configured = True
    mock_pg.test_connection.return_value = False

    engine = CloudSyncEngine(mock_sqlite, mock_pg)
    summary = engine.synchronize()

    assert summary.status == "OFFLINE"
    assert summary.records_uploaded == 0
    assert summary.records_downloaded == 0
    assert any("aborted" in e for e in summary.errors)
    assert engine.last_summary == summary


def test_synchronize_bidirectional_flow() -> None:
    """Verify bidirectional record exchange and idempotency."""
    mock_sqlite = MagicMock()
    mock_pg = MagicMock()
    mock_pg.is_configured = True
    mock_pg.test_connection.return_value = True

    # Tables: scan_history, threats, file_integrity, url_analysis, network_logs
    local_data = {
        "scan_history": [{"id": "s-1", "scan_type": "PORT", "target": "127.0.0.1", "result": "CLEAN", "created_at": "2026-11-05T00:00:00Z"}],
        "threats": [],
        "file_integrity": [],
        "url_analysis": [],
        "network_logs": [],
    }
    cloud_data = {
        "scan_history": [],
        "threats": [{"id": "t-1", "scan_id": "s-1", "threat_type": "XSS", "severity": "HIGH", "description": "DOM XSS", "created_at": "2026-11-05T00:00:00Z"}],
        "file_integrity": [],
        "url_analysis": [],
        "network_logs": [],
    }

    def sqlite_fetch_all(query: str) -> list:
        for t in local_data:
            if f"FROM {t}" in query:
                return local_data[t]
        return []

    def pg_fetch_all(query: str) -> list:
        for t in cloud_data:
            if f"FROM {t}" in query:
                return cloud_data[t]
        return []

    mock_sqlite.fetch_all.side_effect = sqlite_fetch_all
    mock_pg.fetch_all.side_effect = pg_fetch_all
    mock_sqlite.execute.return_value = 1
    mock_pg.execute.return_value = 1

    engine = CloudSyncEngine(mock_sqlite, mock_pg)
    summary = engine.synchronize(direction=SyncDirection.BIDIRECTIONAL)

    assert summary.status == "SUCCESS"
    assert summary.records_uploaded == 1  # s-1 uploaded
    assert summary.records_downloaded == 1  # t-1 downloaded
    assert summary.conflicts_detected == 0
    assert engine.last_sync_time is not None

    # Idempotent second run
    local_data["threats"] = cloud_data["threats"]
    cloud_data["scan_history"] = local_data["scan_history"]

    summary_2 = engine.synchronize()
    assert summary_2.records_uploaded == 0
    assert summary_2.records_downloaded == 0
    assert summary_2.conflicts_detected == 0


def test_synchronize_conflict_detection_and_table_error() -> None:
    """Verify conflict detection on disparate attributes and partial error handling."""
    mock_sqlite = MagicMock()
    mock_pg = MagicMock()
    mock_pg.is_configured = True
    mock_pg.test_connection.return_value = True

    # Same ID in scan_history with different result
    def mock_local_fetch(query: str) -> list:
        if "FROM scan_history" in query:
            return [{"id": "s-conflict", "scan_type": "WEB", "target": "test.com", "result": "MALICIOUS", "created_at": "2026-11-05T00:00:00Z"}]
        return []

    def mock_cloud_fetch(query: str) -> list:
        if "FROM scan_history" in query:
            return [{"id": "s-conflict", "scan_type": "WEB", "target": "test.com", "result": "BENIGN", "created_at": "2026-11-05T00:00:00Z"}]
        return []

    mock_sqlite.fetch_all.side_effect = mock_local_fetch
    mock_pg.fetch_all.side_effect = mock_cloud_fetch

    engine = CloudSyncEngine(mock_sqlite, mock_pg)

    # 1. Upload pass conflict detection
    summary_up = engine.synchronize(direction=SyncDirection.UPLOAD_ONLY)
    assert summary_up.conflicts_detected == 1
    assert summary_up.records_uploaded == 0
    assert len(summary_up.conflicts) == 1
    assert summary_up.conflicts[0].conflict_reason != ""

    # 2. Download pass conflict detection
    summary_dl = engine.synchronize(direction=SyncDirection.DOWNLOAD_ONLY)
    assert summary_dl.conflicts_detected == 1
    assert summary_dl.records_downloaded == 0

    # 3. Partial table error handling
    mock_sqlite.fetch_all.side_effect = RuntimeError("Disk full")
    summary_err = engine.synchronize()
    assert summary_err.status == "PARTIAL"
    assert len(summary_err.errors) > 0


def test_synchronize_retry_and_exhaustion() -> None:
    """Verify retry attempts on connection error."""
    mock_sqlite = MagicMock()
    mock_pg = MagicMock()
    mock_pg.is_configured = True
    mock_pg.test_connection.return_value = True

    engine = CloudSyncEngine(mock_sqlite, mock_pg)
    with patch.object(engine, "_execute_sync", side_effect=Exception("Connection reset")):
        summary = engine.synchronize(max_retries=2, backoff_seconds=0.01)
        assert summary.status == "FAILED"
        assert any("failed after 2 attempts" in e for e in summary.errors)


def test_normalization_and_equality_helpers() -> None:
    """Verify type normalization (Decimals, datetimes) and equality tolerances."""
    now = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)
    raw = {"score": Decimal("85.50"), "time": now, "name": "test"}
    norm = CloudSyncEngine._normalize_record(raw)

    assert isinstance(norm["score"], float)
    assert norm["score"] == 85.5
    assert isinstance(norm["time"], str)

    # Equality check
    r1 = {"val": 10.0001, "time": "2026-11-05T12:00:00Z", "extra": "same"}
    r2 = {"val": 10.0002, "time": "2026-11-05T12:00:00+00:00", "extra": "same"}
    cols = ["val", "time", "extra"]
    assert CloudSyncEngine._are_records_equal(r1, r2, cols) is True

    # Numeric inequality
    assert CloudSyncEngine._are_records_equal({"v": 1.0}, {"v": 2.0}, ["v"]) is False
    # Timestamp inequality
    assert CloudSyncEngine._are_records_equal({"t": "2026-01-01"}, {"t": "2026-02-02"}, ["t"]) is False
    # General inequality
    assert CloudSyncEngine._are_records_equal({"k": None}, {"k": "val"}, ["k"]) is False
