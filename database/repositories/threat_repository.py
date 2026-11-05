"""Threat Repository.

Manages security threat findings linked to parent scan history records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid


class DatabaseExecutor(Protocol):
    def execute(self, query: str, params: tuple | list = ()) -> int: ...
    def fetch_one(self, query: str, params: tuple | list = ()) -> dict[str, Any] | None: ...
    def fetch_all(self, query: str, params: tuple | list = ()) -> list[dict[str, Any]]: ...


class ThreatRepository:
    """Data access repository for threats table."""

    def __init__(self, db: DatabaseExecutor) -> None:
        self.db = db

    def create(
        self,
        scan_id: str,
        threat_type: str,
        severity: str,
        description: str,
        threat_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Create a new threat finding linked to a scan history record.

        Args:
            scan_id: UUID of the parent scan_history entry.
            threat_type: Threat category (e.g., BRUTE_FORCE, CVE, HASH_MISMATCH).
            severity: CVSS severity level (CRITICAL, HIGH, MEDIUM, LOW).
            description: Detailed technical explanation.
            threat_id: Optional explicit UUID string.
            created_at: Optional ISO-8601 timestamp string.

        Returns:
            dict: The created threat record.
        """
        record_id = threat_id or str(uuid.uuid4())
        created_time = created_at or datetime.now(timezone.utc).isoformat()

        query = (
            "INSERT INTO threats (id, scan_id, threat_type, severity, description, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?);"
        )
        self.db.execute(query, (record_id, scan_id, threat_type, severity.upper(), description, created_time))
        return self.get_by_id(record_id) or {
            "id": record_id,
            "scan_id": scan_id,
            "threat_type": threat_type,
            "severity": severity.upper(),
            "description": description,
            "created_at": created_time,
        }

    def get_by_id(self, threat_id: str) -> dict[str, Any] | None:
        """Fetch threat finding by primary key ID."""
        query = "SELECT id, scan_id, threat_type, severity, description, created_at FROM threats WHERE id = ?;"
        return self.db.fetch_one(query, (threat_id,))

    def list_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """List all threat findings associated with a specific scan ID."""
        query = (
            "SELECT id, scan_id, threat_type, severity, description, created_at "
            "FROM threats WHERE scan_id = ? ORDER BY created_at DESC;"
        )
        return self.db.fetch_all(query, (scan_id,))

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all threat findings up to limit."""
        query = (
            "SELECT id, scan_id, threat_type, severity, description, created_at "
            "FROM threats ORDER BY created_at DESC LIMIT ?;"
        )
        return self.db.fetch_all(query, (limit,))

    def delete(self, threat_id: str) -> bool:
        """Delete threat record by ID."""
        query = "DELETE FROM threats WHERE id = ?;"
        affected = self.db.execute(query, (threat_id,))
        return affected > 0

