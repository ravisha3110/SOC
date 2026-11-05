"""Scan History Repository.

Records and retrieves historical security scans executed across all modules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid


class DatabaseExecutor(Protocol):
    def execute(self, query: str, params: tuple | list = ()) -> int: ...
    def fetch_one(self, query: str, params: tuple | list = ()) -> dict[str, Any] | None: ...
    def fetch_all(self, query: str, params: tuple | list = ()) -> list[dict[str, Any]]: ...


class ScanRepository:
    """Data access repository for scan_history table."""

    def __init__(self, db: DatabaseExecutor) -> None:
        self.db = db

    def create(
        self,
        scan_type: str,
        target: str,
        result: str,
        scan_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Create a new scan history entry.

        Args:
            scan_type: Category identifier (e.g., PORT_SCAN, FIM, URL_CHECK).
            target: Inspection target (IP, port, file path, URL).
            result: Detailed findings string or serialized JSON summary.
            scan_id: Optional explicit UUID string.
            created_at: Optional ISO-8601 timestamp string.

        Returns:
            dict: The created scan history record.
        """
        record_id = scan_id or str(uuid.uuid4())
        created_time = created_at or datetime.now(timezone.utc).isoformat()

        query = "INSERT INTO scan_history (id, scan_type, target, result, created_at) VALUES (?, ?, ?, ?, ?);"
        self.db.execute(query, (record_id, scan_type, target, result, created_time))
        return self.get_by_id(record_id) or {
            "id": record_id,
            "scan_type": scan_type,
            "target": target,
            "result": result,
            "created_at": created_time,
        }

    def get_by_id(self, scan_id: str) -> dict[str, Any] | None:
        """Fetch scan history record by ID."""
        query = "SELECT id, scan_type, target, result, created_at FROM scan_history WHERE id = ?;"
        return self.db.fetch_one(query, (scan_id,))

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """List recent scan records up to limit."""
        query = "SELECT id, scan_type, target, result, created_at FROM scan_history ORDER BY created_at DESC LIMIT ?;"
        return self.db.fetch_all(query, (limit,))

    def delete(self, scan_id: str) -> bool:
        """Delete scan record by ID."""
        query = "DELETE FROM scan_history WHERE id = ?;"
        affected = self.db.execute(query, (scan_id,))
        return affected > 0

