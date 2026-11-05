"""Integration tests for URL Security Analyzer with SQLite repository."""

from __future__ import annotations

from pathlib import Path

import pytest

from database.repositories.url_analysis_repository import URLAnalysisRepository
from database.sqlite_manager import SQLiteManager
from security.url_analyzer import URLRiskLevel, URLSecurityAnalyzer


@pytest.fixture
def sqlite_db(tmp_path: Path) -> SQLiteManager:
    """Fixture providing initialized SQLite database."""
    db_path = tmp_path / "test_url.db"
    manager = SQLiteManager(db_path=db_path)
    manager.initialize_database()
    yield manager
    manager.close()


def test_url_analyzer_sqlite_repository_persistence(sqlite_db: SQLiteManager) -> None:
    """Verify URLSecurityAnalyzer writes evaluation results directly to SQLite repository."""
    repo = URLAnalysisRepository(sqlite_db)
    analyzer = URLSecurityAnalyzer(repository=repo)

    test_url = "http://192.168.1.50/admin/login"
    result = analyzer.analyze(test_url)

    assert result.risk_score >= 45.0
    assert result.risk_level in (URLRiskLevel.HIGH, URLRiskLevel.CRITICAL)

    # Fetch from SQLite database
    persisted = repo.get_by_url(test_url)
    assert persisted is not None
    assert persisted["url"] == test_url
    assert persisted["risk_score"] == result.risk_score
    assert persisted["risk_level"] == result.risk_level.value

    # List all
    all_recs = repo.list_all()
    assert len(all_recs) == 1
    assert all_recs[0]["url"] == test_url

