"""Unit tests for Hybrid Cloud Synchronization Desktop GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock
import pytest

from frontend.cloud_sync_view import CloudSyncView
from security.auth import Role, Session
from security.cloud_sync import (
    CloudConnectionStatus,
    CloudSyncEngine,
    SyncConflict,
    SyncDirection,
    SyncSummary,
)


def test_cloud_sync_view_initialization_and_status(tk_root) -> None:
    """Verify initialization and status display under online and offline states."""
    mock_engine = MagicMock(spec=CloudSyncEngine)
    mock_engine.get_status_overview.return_value = {
        "cloud_status": "ONLINE",
        "is_connected": True,
        "masked_target_url": "postgresql://user:***@neon.tech/db",
        "last_synced_at": "2026-11-05T12:00:00Z",
        "total_local_records": 42,
    }
    analyst_session = MagicMock(spec=Session)
    analyst_session.role = Role.ANALYST
    feedback_mock = MagicMock()

    view = CloudSyncView(
        tk_root,
        sync_engine=mock_engine,
        current_session=analyst_session,
        on_feedback=feedback_mock,
    )

    assert "ONLINE" in view.lbl_cloud_status["text"]
    assert "42 Records" in view.lbl_records_count["text"]
    assert "neon.tech" in view.lbl_masked_url["text"]
    feedback_mock.assert_called_with("Cloud status checked: ONLINE")

    # Offline status
    mock_engine.get_status_overview.return_value["cloud_status"] = "OFFLINE"
    view.refresh_status()
    assert "OFFLINE" in view.lbl_cloud_status["text"]

    # Not configured status
    mock_engine.get_status_overview.return_value["cloud_status"] = "NOT_CONFIGURED"
    view.refresh_status()
    assert "NOT CONFIGURED" in view.lbl_cloud_status["text"]

    # Error status
    mock_engine.get_status_overview.return_value["cloud_status"] = "ERROR"
    view.refresh_status()
    assert "CONNECTION ERROR" in view.lbl_cloud_status["text"]


def test_cloud_sync_view_synchronization_action(tk_root) -> None:
    """Verify manual sync trigger, treeview population, conflict display, and errors."""
    mock_engine = MagicMock(spec=CloudSyncEngine)
    mock_engine.get_status_overview.return_value = {
        "cloud_status": "ONLINE",
        "is_connected": True,
        "masked_target_url": "postgresql://user:***@neon.tech/db",
        "last_synced_at": "2026-11-05T12:00:00Z",
        "total_local_records": 10,
    }

    conflict = SyncConflict(
        table_name="url_analysis",
        record_id="u-conf-1",
        local_data={},
        cloud_data={},
        conflict_reason="Risk level disparity",
    )
    mock_engine.synchronize.return_value = SyncSummary(
        status="PARTIAL",
        cloud_status=CloudConnectionStatus.ONLINE,
        direction=SyncDirection.BIDIRECTIONAL,
        started_at="2026-11-05T00:00:00Z",
        completed_at="2026-11-05T00:00:01Z",
        records_uploaded=3,
        records_downloaded=1,
        conflicts_detected=1,
        conflicts=[conflict],
        errors=["Simulated network warning"],
        table_stats={"threats": {"uploaded": 3, "downloaded": 1}},
    )

    admin_session = MagicMock(spec=Session)
    admin_session.role = Role.ADMINISTRATOR
    feedback_mock = MagicMock()

    view = CloudSyncView(
        tk_root,
        sync_engine=mock_engine,
        current_session=admin_session,
        on_feedback=feedback_mock,
    )

    # Trigger Bidirectional Sync
    view._handle_sync(SyncDirection.BIDIRECTIONAL)
    mock_engine.synchronize.assert_called_with(direction=SyncDirection.BIDIRECTIONAL)

    children = view.tree.get_children()
    assert len(children) >= 3  # Table stats row + conflict row + error row
    assert any("Sync PARTIAL" in str(call) for call in feedback_mock.call_args_list)

    # Trigger second sync with zero conflicts to verify clearing and zero-conflict row
    mock_engine.synchronize.return_value = SyncSummary(
        status="COMPLETED",
        cloud_status=CloudConnectionStatus.ONLINE,
        direction=SyncDirection.UPLOAD_ONLY,
        started_at="2026-11-05T00:00:00Z",
        completed_at="2026-11-05T00:00:01Z",
        records_uploaded=5,
        records_downloaded=0,
        conflicts_detected=0,
        conflicts=[],
        errors=[],
        table_stats={"threats": {"uploaded": 5, "downloaded": 0}},
    )
    view._handle_sync(SyncDirection.UPLOAD_ONLY)
    mock_engine.synchronize.assert_called_with(direction=SyncDirection.UPLOAD_ONLY)
    assert any("Zero attribute conflicts" in str(view.tree.item(item)["values"]) for item in view.tree.get_children())


def test_cloud_sync_view_viewer_role_restrictions(tk_root) -> None:
    """Verify read-only restrictions for Viewer role."""
    mock_engine = MagicMock(spec=CloudSyncEngine)
    mock_engine.get_status_overview.return_value = {
        "cloud_status": "ONLINE",
        "is_connected": True,
        "masked_target_url": "[Masked]",
        "last_synced_at": None,
        "total_local_records": 0,
    }
    viewer_session = MagicMock(spec=Session)
    viewer_session.role = Role.VIEWER
    feedback_mock = MagicMock()

    view = CloudSyncView(
        tk_root,
        sync_engine=mock_engine,
        current_session=viewer_session,
        on_feedback=feedback_mock,
    )

    assert str(view.btn_sync_bidirectional["state"]) == "disabled"
    assert str(view.btn_upload["state"]) == "disabled"
    assert str(view.btn_download["state"]) == "disabled"

    # Attempt triggering sync directly
    view._handle_sync(SyncDirection.UPLOAD_ONLY)
    mock_engine.synchronize.assert_not_called()
    assert any("Permission denied" in str(call) for call in feedback_mock.call_args_list)
