"""CyberShield Hybrid Cloud Synchronization Engine.

Coordinates bi-directional synchronization between local offline SQLite storage
and cloud Neon PostgreSQL database while maintaining strict privacy boundaries:
- Zero credential synchronization (users, hashes, sessions are strictly kept local).
- Stable record IDs and idempotent operations.
- Non-destructive conflict detection.
- Offline-first resilience allowing full local functionality when cloud is unreachable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import time
from typing import Any, Protocol

from database.exceptions import DatabaseConnectionError, DatabaseError
from database.postgres_manager import PostgresManager, sanitize_db_url
from database.sqlite_manager import SQLiteManager


class CloudConnectionStatus(str, Enum):
    """Status of cloud Neon PostgreSQL connectivity."""

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    ERROR = "ERROR"


class SyncDirection(str, Enum):
    """Synchronization direction."""

    BIDIRECTIONAL = "BIDIRECTIONAL"
    UPLOAD_ONLY = "UPLOAD_ONLY"
    DOWNLOAD_ONLY = "DOWNLOAD_ONLY"


@dataclass
class SyncConflict:
    """Represents a data disparity detected between local and cloud states."""

    table_name: str
    record_id: str
    local_data: dict[str, Any]
    cloud_data: dict[str, Any]
    conflict_reason: str
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize conflict details."""
        return {
            "table_name": self.table_name,
            "record_id": self.record_id,
            "conflict_reason": self.conflict_reason,
            "detected_at": self.detected_at,
            "local_data": self.local_data,
            "cloud_data": self.cloud_data,
        }


@dataclass
class SyncSummary:
    """Audit summary of an executed synchronization batch."""

    status: str  # SUCCESS, PARTIAL, OFFLINE, FAILED
    cloud_status: CloudConnectionStatus
    direction: SyncDirection
    started_at: str
    completed_at: str
    records_uploaded: int = 0
    records_downloaded: int = 0
    conflicts_detected: int = 0
    conflicts: list[SyncConflict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    table_stats: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize sync summary to JSON-safe dictionary."""
        return {
            "status": self.status,
            "cloud_status": self.cloud_status.value,
            "direction": self.direction.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "records_uploaded": self.records_uploaded,
            "records_downloaded": self.records_downloaded,
            "conflicts_detected": self.conflicts_detected,
            "conflicts": [c.to_dict() for c in self.conflicts],
            "errors": self.errors,
            "table_stats": self.table_stats,
        }


# Tables eligible for cloud synchronization (users/credentials are STRICTLY EXCLUDED)
SYNC_TABLE_COLUMNS: dict[str, list[str]] = {
    "scan_history": ["id", "scan_type", "target", "result", "created_at"],
    "threats": ["id", "scan_id", "threat_type", "severity", "description", "created_at"],
    "file_integrity": ["id", "file_name", "file_hash", "created_at"],
    "url_analysis": ["id", "url", "risk_score", "risk_level", "created_at"],
    "network_logs": ["id", "local_address", "remote_address", "connection_status", "created_at"],
}


class CloudSyncEngine:
    """Orchestrates resilient, privacy-preserving hybrid database synchronization."""

    def __init__(
        self,
        sqlite_manager: SQLiteManager,
        postgres_manager: PostgresManager,
    ) -> None:
        self.sqlite = sqlite_manager
        self.postgres = postgres_manager
        self.last_sync_time: str | None = None
        self.last_summary: SyncSummary | None = None

    def check_cloud_status(self, timeout_seconds: int = 3) -> CloudConnectionStatus:
        """Probe cloud database reachability."""
        if not self.postgres.is_configured:
            return CloudConnectionStatus.NOT_CONFIGURED
        try:
            connected = self.postgres.test_connection(timeout_seconds=timeout_seconds)
            return CloudConnectionStatus.ONLINE if connected else CloudConnectionStatus.OFFLINE
        except Exception:
            return CloudConnectionStatus.ERROR

    def get_status_overview(self) -> dict[str, Any]:
        """Compile a fast telemetry overview of cloud connectivity and pending local records."""
        cloud_status = self.check_cloud_status()
        pending_local_count = 0

        for table in SYNC_TABLE_COLUMNS:
            try:
                res = self.sqlite.fetch_one(f"SELECT COUNT(*) AS c FROM {table};")
                if res:
                    pending_local_count += int(res.get("c", 0))
            except Exception:
                pass

        return {
            "cloud_status": cloud_status.value,
            "is_connected": cloud_status == CloudConnectionStatus.ONLINE,
            "masked_target_url": self.postgres.sanitized_url,
            "last_synced_at": self.last_sync_time,
            "total_local_records": pending_local_count,
        }

    def synchronize(
        self,
        direction: SyncDirection = SyncDirection.BIDIRECTIONAL,
        max_retries: int = 3,
        backoff_seconds: float = 0.5,
    ) -> SyncSummary:
        """Execute synchronization between SQLite and Neon PostgreSQL with retry handling.

        Args:
            direction: Bidirectional, upload-only, or download-only.
            max_retries: Retry attempts for transient network issues.
            backoff_seconds: Initial backoff delay between retries.

        Returns:
            SyncSummary: Detailed audit result with upload/download counts and conflicts.
        """
        start_time = datetime.now(timezone.utc).isoformat()
        cloud_status = self.check_cloud_status()

        if cloud_status != CloudConnectionStatus.ONLINE:
            summary = SyncSummary(
                status="OFFLINE" if cloud_status == CloudConnectionStatus.OFFLINE else "FAILED",
                cloud_status=cloud_status,
                direction=direction,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc).isoformat(),
                errors=[
                    f"Cloud synchronization aborted: Neon PostgreSQL is {cloud_status.value}. Local operations remain fully functional."
                ],
            )
            self.last_summary = summary
            return summary

        # Attempt synchronization with retry loop
        last_exc: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                summary = self._execute_sync(direction, start_time)
                self.last_sync_time = summary.completed_at
                self.last_summary = summary
                return summary
            except (DatabaseConnectionError, Exception) as exc:
                last_exc = exc
                if attempt < max_retries:
                    time.sleep(backoff_seconds * attempt)

        # Retries exhausted
        summary = SyncSummary(
            status="FAILED",
            cloud_status=CloudConnectionStatus.ERROR,
            direction=direction,
            started_at=start_time,
            completed_at=datetime.now(timezone.utc).isoformat(),
            errors=[f"Synchronization failed after {max_retries} attempts: {last_exc}"],
        )
        self.last_summary = summary
        return summary

    def _execute_sync(self, direction: SyncDirection, start_time: str) -> SyncSummary:
        """Internal worker executing table-by-table record exchange."""
        uploaded = 0
        downloaded = 0
        conflicts: list[SyncConflict] = []
        errors: list[str] = []
        table_stats: dict[str, dict[str, int]] = {}

        for table_name, columns in SYNC_TABLE_COLUMNS.items():
            t_uploaded = 0
            t_downloaded = 0
            col_list_str = ", ".join(columns)
            placeholders_sqlite = ", ".join(["?"] * len(columns))
            placeholders_pg = ", ".join(["%s"] * len(columns))

            try:
                # 1. Fetch Local and Cloud Records for this table
                local_rows = self.sqlite.fetch_all(f"SELECT {col_list_str} FROM {table_name};")
                cloud_rows = self.postgres.fetch_all(f"SELECT {col_list_str} FROM {table_name};")

                local_by_id = {row["id"]: self._normalize_record(row) for row in local_rows}
                cloud_by_id = {row["id"]: self._normalize_record(row) for row in cloud_rows}

                # 2. UPLOAD: Local -> Cloud
                if direction in (SyncDirection.UPLOAD_ONLY, SyncDirection.BIDIRECTIONAL):
                    for r_id, l_rec in local_by_id.items():
                        if r_id not in cloud_by_id:
                            # Insert into Cloud Neon
                            vals = [l_rec[c] for c in columns]
                            insert_query = f"INSERT INTO {table_name} ({col_list_str}) VALUES ({placeholders_pg});"
                            self.postgres.execute(insert_query, vals)
                            t_uploaded += 1
                        else:
                            # Existing record: check for conflict
                            c_rec = cloud_by_id[r_id]
                            if not self._are_records_equal(l_rec, c_rec, columns):
                                conflicts.append(
                                    SyncConflict(
                                        table_name=table_name,
                                        record_id=r_id,
                                        local_data=l_rec,
                                        cloud_data=c_rec,
                                        conflict_reason="Attribute discrepancy detected between local and cloud record.",
                                    )
                                )

                # 3. DOWNLOAD: Cloud -> Local
                if direction in (SyncDirection.DOWNLOAD_ONLY, SyncDirection.BIDIRECTIONAL):
                    for r_id, c_rec in cloud_by_id.items():
                        if r_id not in local_by_id:
                            # Insert into Local SQLite
                            vals = [c_rec[c] for c in columns]
                            insert_query = f"INSERT INTO {table_name} ({col_list_str}) VALUES ({placeholders_sqlite});"
                            self.sqlite.execute(insert_query, vals)
                            t_downloaded += 1
                        else:
                            # If already in local, conflict was already detected in upload pass if bidirectional
                            if direction == SyncDirection.DOWNLOAD_ONLY:
                                l_rec = local_by_id[r_id]
                                if not self._are_records_equal(l_rec, c_rec, columns):
                                    conflicts.append(
                                        SyncConflict(
                                            table_name=table_name,
                                            record_id=r_id,
                                            local_data=l_rec,
                                            cloud_data=c_rec,
                                            conflict_reason="Attribute discrepancy detected during download pass.",
                                        )
                                    )

                uploaded += t_uploaded
                downloaded += t_downloaded
                table_stats[table_name] = {
                    "uploaded": t_uploaded,
                    "downloaded": t_downloaded,
                }

            except Exception as exc:
                errors.append(f"Error synchronizing table '{table_name}': {exc}")

        status = "SUCCESS" if not errors else "PARTIAL"
        return SyncSummary(
            status=status,
            cloud_status=CloudConnectionStatus.ONLINE,
            direction=direction,
            started_at=start_time,
            completed_at=datetime.now(timezone.utc).isoformat(),
            records_uploaded=uploaded,
            records_downloaded=downloaded,
            conflicts_detected=len(conflicts),
            conflicts=conflicts,
            errors=errors,
            table_stats=table_stats,
        )

    @staticmethod
    def _normalize_record(row: dict[str, Any]) -> dict[str, Any]:
        """Normalize types across SQLite and PostgreSQL (Decimals to floats, datetimes to ISO strings)."""
        normalized: dict[str, Any] = {}
        for k, v in row.items():
            if isinstance(v, Decimal):
                normalized[k] = float(v)
            elif isinstance(v, datetime):
                normalized[k] = v.isoformat()
            else:
                normalized[k] = v
        return normalized

    @staticmethod
    def _are_records_equal(rec1: dict[str, Any], rec2: dict[str, Any], columns: list[str]) -> bool:
        """Compare two records for value equality across common columns."""
        for col in columns:
            v1 = rec1.get(col)
            v2 = rec2.get(col)
            # Compare numbers with tolerance
            if isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                if abs(v1 - v2) > 0.001:
                    return False
            # Compare string representations for timestamps
            elif isinstance(v1, str) and isinstance(v2, str):
                if v1.replace("Z", "+00:00") != v2.replace("Z", "+00:00"):
                    return False
            elif v1 != v2:
                return False
        return True

