"""Integration tests for Threat Analytics & Reports with full SQLite repository suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from database.repositories.file_integrity_repository import FileIntegrityRepository
from database.repositories.network_log_repository import NetworkLogRepository
from database.repositories.scan_repository import ScanRepository
from database.repositories.threat_repository import ThreatRepository
from database.repositories.url_analysis_repository import URLAnalysisRepository
from database.sqlite_manager import SQLiteManager
from security.threat_analytics import ThreatAnalyticsEngine


@pytest.fixture
def sqlite_db(tmp_path: Path) -> SQLiteManager:
    """Fixture providing initialized SQLite database."""
    db_path = tmp_path / "test_analytics.db"
    manager = SQLiteManager(db_path=db_path)
    manager.initialize_database()
    yield manager
    manager.close()


def test_threat_analytics_engine_full_sqlite_integration(sqlite_db: SQLiteManager, tmp_path: Path) -> None:
    """Verify ThreatAnalyticsEngine compiles real database data across all tables."""
    scan_repo = ScanRepository(sqlite_db)
    threat_repo = ThreatRepository(sqlite_db)
    file_repo = FileIntegrityRepository(sqlite_db)
    url_repo = URLAnalysisRepository(sqlite_db)
    net_repo = NetworkLogRepository(sqlite_db)

    # 1. Populate sample data
    scan1 = scan_repo.create(scan_type="PORT_SCAN", target="192.168.1.1", result="Port 22 Open")
    scan2 = scan_repo.create(scan_type="FILE_INTEGRITY", target="/etc/hosts", result="Tamper Detected")

    threat_repo.create(
        scan_id=scan1["id"],
        threat_type="UNAUTHORIZED_SERVICE",
        severity="HIGH",
        description="SSH port exposed to public network",
    )
    threat_repo.create(
        scan_id=scan2["id"],
        threat_type="FILE_MODIFIED",
        severity="CRITICAL",
        description="Hosts file redirected to rogue DNS",
    )

    file_repo.create(file_name="core_binary.exe", file_hash="11223344556677889900")
    file_repo.create(file_name="security_config.yaml", file_hash="aabbccddeeff00112233")

    url_repo.create(url="https://legitimate.org", risk_score=10.0, risk_level="LOW")
    url_repo.create(url="http://192.168.1.1@phishing.xyz", risk_score=95.0, risk_level="CRITICAL")

    net_repo.create(local_address="127.0.0.1:8000", remote_address="*:*", connection_status="LISTEN")
    net_repo.create(local_address="10.0.0.5:50123", remote_address="1.1.1.1:443", connection_status="ESTABLISHED")

    # 2. Compile analytics
    engine = ThreatAnalyticsEngine(
        scan_repo=scan_repo,
        threat_repo=threat_repo,
        file_repo=file_repo,
        url_repo=url_repo,
        network_repo=net_repo,
    )

    summary = engine.compile_summary()

    assert summary.total_scans == 2
    assert summary.total_threats == 2
    assert summary.threats_by_severity["CRITICAL"] == 1
    assert summary.threats_by_severity["HIGH"] == 1
    assert summary.file_integrity_stats["total_baselines"] == 2
    assert summary.url_risk_stats["total_analyzed"] == 2
    assert summary.url_risk_stats["CRITICAL"] == 1
    assert summary.network_stats["total_logged"] == 2
    assert summary.network_stats["established"] == 1
    assert summary.network_stats["listen"] == 1

    # 3. Generate report
    report = engine.generate_report(title="Full Integration Audit", analyst_name="Test Analyst")
    assert report.summary.total_threats == 2
    assert any("CRITICAL" in r for r in report.recommendations)

    # 4. Export report files
    csv_out = tmp_path / "integration_report.csv"
    html_out = tmp_path / "integration_report.html"

    report.export_csv_to_file(csv_out)
    report.export_html_to_file(html_out)

    assert csv_out.exists()
    assert html_out.exists()
    assert "Hosts file redirected to rogue DNS" in csv_out.read_text(encoding="utf-8")
    assert "Hosts file redirected to rogue DNS" in html_out.read_text(encoding="utf-8")

