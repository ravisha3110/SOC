"""File Integrity Repository.

Tracks cryptographic hashes and baseline records for monitored system files.
Notice: Does NOT store original file contents, strictly cryptographic hashes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid


class DatabaseExecutor(Protocol):
    def execute(self, query: str, params: tuple | list = ()) -> int: ...
    def fetch_one(self, query: str, params: tuple | list = ()) -> dict[str, Any] | None: ...
    def fetch_all(self, query: str, params: tuple | list = ()) -> list[dict[str, Any]]: ...


class FileIntegrityRepository:
    """Data access repository for file_integrity table."""

    def __init__(self, db: DatabaseExecutor) -> None:
        self.db = db

    def create(
        self,
        file_name: str,
        file_hash: str,
        record_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Create a new file integrity baseline entry.

        Args:
            file_name: Relative path or identifier of the monitored file.
            file_hash: Cryptographic hash checksum (e.g. SHA-256).
            record_id: Optional explicit UUID string.
            created_at: Optional ISO-8601 timestamp string.

        Returns:
            dict: The created file integrity record.
        """
        rec_id = record_id or str(uuid.uuid4())
        created_time = created_at or datetime.now(timezone.utc).isoformat()

        query = "INSERT INTO file_integrity (id, file_name, file_hash, created_at) VALUES (?, ?, ?, ?);"
        self.db.execute(query, (rec_id, file_name, file_hash, created_time))
        return self.get_by_id(rec_id) or {
            "id": rec_id,
            "file_name": file_name,
            "file_hash": file_hash,
            "created_at": created_time,
        }

    def get_by_id(self, record_id: str) -> dict[str, Any] | None:
        """Fetch record by ID."""
        query = "SELECT id, file_name, file_hash, created_at FROM file_integrity WHERE id = ?;"
        return self.db.fetch_one(query, (record_id,))

    def get_by_hash(self, file_hash: str) -> dict[str, Any] | None:
        """Fetch file record by cryptographic hash value."""
        query = "SELECT id, file_name, file_hash, created_at FROM file_integrity WHERE file_hash = ?;"
        return self.db.fetch_one(query, (file_hash,))

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all file integrity baseline records."""
        query = "SELECT id, file_name, file_hash, created_at FROM file_integrity ORDER BY created_at DESC LIMIT ?;"
        return self.db.fetch_all(query, (limit,))

    def delete(self, record_id: str) -> bool:
        """Delete baseline record by ID."""
        query = "DELETE FROM file_integrity WHERE id = ?;"
        affected = self.db.execute(query, (record_id,))
        return affected > 0

