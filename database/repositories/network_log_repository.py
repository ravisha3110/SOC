"""Network Log Repository.

Stores active and historical network connection events.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid


class DatabaseExecutor(Protocol):
    def execute(self, query: str, params: tuple | list = ()) -> int: ...
    def fetch_one(self, query: str, params: tuple | list = ()) -> dict[str, Any] | None: ...
    def fetch_all(self, query: str, params: tuple | list = ()) -> list[dict[str, Any]]: ...


class NetworkLogRepository:
    """Data access repository for network_logs table."""

    def __init__(self, db: DatabaseExecutor) -> None:
        self.db = db

    def create(
        self,
        local_address: str,
        remote_address: str,
        connection_status: str,
        log_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Record a network connection event.

        Args:
            local_address: Local IP and port (e.g. 127.0.0.1:54321).
            remote_address: Remote destination IP and port.
            connection_status: State (ESTABLISHED, SYN_SENT, TIME_WAIT, BLOCKED).
            log_id: Optional explicit UUID string.
            created_at: Optional ISO-8601 timestamp string.

        Returns:
            dict: The created network log record.
        """
        rec_id = log_id or str(uuid.uuid4())
        created_time = created_at or datetime.now(timezone.utc).isoformat()

        query = (
            "INSERT INTO network_logs (id, local_address, remote_address, connection_status, created_at) "
            "VALUES (?, ?, ?, ?, ?);"
        )
        self.db.execute(query, (rec_id, local_address, remote_address, connection_status.upper(), created_time))
        return self.get_by_id(rec_id) or {
            "id": rec_id,
            "local_address": local_address,
            "remote_address": remote_address,
            "connection_status": connection_status.upper(),
            "created_at": created_time,
        }

    def get_by_id(self, log_id: str) -> dict[str, Any] | None:
        """Fetch network log record by ID."""
        query = (
            "SELECT id, local_address, remote_address, connection_status, created_at "
            "FROM network_logs WHERE id = ?;"
        )
        return self.db.fetch_one(query, (log_id,))

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """List network log records up to limit."""
        query = (
            "SELECT id, local_address, remote_address, connection_status, created_at "
            "FROM network_logs ORDER BY created_at DESC LIMIT ?;"
        )
        return self.db.fetch_all(query, (limit,))

    def delete(self, log_id: str) -> bool:
        """Delete network log record by ID."""
        query = "DELETE FROM network_logs WHERE id = ?;"
        affected = self.db.execute(query, (log_id,))
        return affected > 0

