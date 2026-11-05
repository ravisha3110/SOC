"""URL Analysis Repository.

Stores and queries safety assessments and threat ratings for inspected URLs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid


class DatabaseExecutor(Protocol):
    def execute(self, query: str, params: tuple | list = ()) -> int: ...
    def fetch_one(self, query: str, params: tuple | list = ()) -> dict[str, Any] | None: ...
    def fetch_all(self, query: str, params: tuple | list = ()) -> list[dict[str, Any]]: ...


class URLAnalysisRepository:
    """Data access repository for url_analysis table."""

    def __init__(self, db: DatabaseExecutor) -> None:
        self.db = db

    def create(
        self,
        url: str,
        risk_score: float,
        risk_level: str,
        analysis_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Create a new URL analysis record.

        Args:
            url: Target URL string.
            risk_score: Numeric score between 0.0 and 100.0.
            risk_level: Classification (SAFE, SUSPICIOUS, MALICIOUS).
            analysis_id: Optional explicit UUID string.
            created_at: Optional ISO-8601 timestamp string.

        Returns:
            dict: The created URL analysis record.
        """
        rec_id = analysis_id or str(uuid.uuid4())
        created_time = created_at or datetime.now(timezone.utc).isoformat()

        query = "INSERT INTO url_analysis (id, url, risk_score, risk_level, created_at) VALUES (?, ?, ?, ?, ?);"
        self.db.execute(query, (rec_id, url.strip(), float(risk_score), risk_level.upper(), created_time))
        return self.get_by_id(rec_id) or {
            "id": rec_id,
            "url": url.strip(),
            "risk_score": float(risk_score),
            "risk_level": risk_level.upper(),
            "created_at": created_time,
        }

    def get_by_id(self, analysis_id: str) -> dict[str, Any] | None:
        """Fetch analysis record by ID."""
        query = "SELECT id, url, risk_score, risk_level, created_at FROM url_analysis WHERE id = ?;"
        return self.db.fetch_one(query, (analysis_id,))

    def get_by_url(self, url: str) -> dict[str, Any] | None:
        """Fetch analysis record by target URL."""
        query = "SELECT id, url, risk_score, risk_level, created_at FROM url_analysis WHERE url = ?;"
        return self.db.fetch_one(query, (url.strip(),))

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all URL analysis records up to limit."""
        query = "SELECT id, url, risk_score, risk_level, created_at FROM url_analysis ORDER BY created_at DESC LIMIT ?;"
        return self.db.fetch_all(query, (limit,))

    def delete(self, analysis_id: str) -> bool:
        """Delete analysis record by ID."""
        query = "DELETE FROM url_analysis WHERE id = ?;"
        affected = self.db.execute(query, (analysis_id,))
        return affected > 0

