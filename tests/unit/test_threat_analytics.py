"""Unit tests for Threat Analytics & Security Reporting Engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from security.threat_analytics import (
    SecurityReport,
    ThreatAnalyticsEngine,
    ThreatAnalyticsSummary,
)


def test_threat_analytics_summary_serialization() -> None:
    """Verify to_dict serialization of ThreatAnalyticsSummary."""
    summary = ThreatAnalyticsSummary(
        total_scans=12,
        total_threats=3,
        threats_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
    )
    d = summary.to_dict()
    assert d["total_scans"] == 12
    assert d["total_threats"] == 3
    assert d["threats_by_severity"]["CRITICAL"] == 1


def test_compile_summary_with_mock_repositories() -> None:
    """Verify aggregation across all 5 security repositories."""
    scan_repo = MagicMock()
    scan_repo.list_all.return_value = [
        {"id": "s1", "scan_type": "FIM", "target": "/etc", "result": "clean"},
        {"id": "s2", "scan_type": "URL_CHECK", "target": "https://a.com", "result": "safe"},
    ]

    threat_repo = MagicMock()
    threat_repo.list_all.return_value = [
        {"id": "t1", "threat_type": "BRUTE_FORCE", "severity": "CRITICAL", "description": "SSH attack"},
        {"id": "t2", "threat_type": "HASH_MISMATCH", "severity": "HIGH", "description": "Binary modified"},
    ]

    file_repo = MagicMock()
    file_repo.list_all.return_value = [
        {"id": "f1", "file_name": "app.py", "file_hash": "abc"},
        {"id": "f2", "file_name": "config.json", "file_hash": "def"},
    ]

    url_repo = MagicMock()
    url_repo.list_all.return_value = [
        {"id": "u1", "url": "http://bad.xyz", "risk_score": 85.0, "risk_level": "CRITICAL"},
        {"id": "u2", "url": "https://good.com", "risk_score": 10.0, "risk_level": "LOW"},
    ]

    network_repo = MagicMock()
    network_repo.list_all.return_value = [
        {"id": "n1", "local_address": "127.0.0.1:80", "remote_address": "*:*", "connection_status": "LISTEN"},
        {"id": "n2", "local_address": "10.0.0.1:1234", "remote_address": "1.1.1.1:443", "connection_status": "ESTABLISHED"},
    ]

    engine = ThreatAnalyticsEngine(
        scan_repo=scan_repo,
        threat_repo=threat_repo,
        file_repo=file_repo,
        url_repo=url_repo,
        network_repo=network_repo,
    )

    summary = engine.compile_summary()

    assert summary.total_scans == 2
    assert summary.total_threats == 2
    assert summary.threats_by_severity["CRITICAL"] == 1
    assert summary.threats_by_severity["HIGH"] == 1
    assert summary.file_integrity_stats["total_baselines"] == 2
    assert summary.url_risk_stats["total_analyzed"] == 2
    assert summary.url_risk_stats["CRITICAL"] == 1
    assert summary.url_risk_stats["LOW"] == 1
    assert summary.network_stats["total_logged"] == 2
    assert summary.network_stats["established"] == 1
    assert summary.network_stats["listen"] == 1


def test_compile_summary_with_no_repositories() -> None:
    """Verify engine handles uninitialized repositories gracefully."""
    engine = ThreatAnalyticsEngine()
    summary = engine.compile_summary()

    assert summary.total_scans == 0
    assert summary.total_threats == 0
    assert summary.file_integrity_stats["total_baselines"] == 0
    assert summary.url_risk_stats["total_analyzed"] == 0
    assert summary.network_stats["total_logged"] == 0


def test_generate_report_and_exports(tmp_path: Path) -> None:
    """Verify generating report and exporting CSV and HTML files."""
    summary = ThreatAnalyticsSummary(
        total_scans=5,
        total_threats=1,
        threats_by_severity={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        recent_findings=[
            {"id": "threat-uuid-1", "threat_type": "TAMPER", "severity": "CRITICAL", "description": "Modified hosts file", "created_at": "2026-11-05T12:00:00Z"}
        ],
    )

    report = SecurityReport(
        title="Custom SOC Audit",
        analyst_name="Agent Antigravity",
        summary=summary,
        recommendations=["Investigate critical tamper incident immediately."],
    )

    # 1. Verify CSV content
    csv_str = report.to_csv()
    assert "CYBERSHIELD SECURITY EXECUTIVE REPORT" in csv_str
    assert "Custom SOC Audit" in csv_str
    assert "Agent Antigravity" in csv_str
    assert "threat-uuid-1" in csv_str

    # Export CSV to file
    csv_path = tmp_path / "report.csv"
    report.export_csv_to_file(csv_path)
    assert csv_path.exists()
    assert len(csv_path.read_text(encoding="utf-8")) > 50

    # 2. Verify HTML content
    html_str = report.to_html()
    assert "<!DOCTYPE html>" in html_str
    assert "Custom SOC Audit" in html_str
    assert "threat-uuid-1" in html_str
    assert "Investigate critical tamper incident" in html_str

    # Export HTML to file
    html_path = tmp_path / "report.html"
    report.export_html_to_file(html_path)
    assert html_path.exists()
    assert len(html_path.read_text(encoding="utf-8")) > 100


def test_generate_report_default_recommendations() -> None:
    """Verify default recommendations when no threats are detected."""
    engine = ThreatAnalyticsEngine()
    report = engine.generate_report()

    assert len(report.recommendations) > 0
    assert any("baseline cryptographic hashes" in r for r in report.recommendations)


def test_generate_report_with_clean_baseline() -> None:
    """Verify default routine recommendations when baselines exist and zero threats."""
    file_repo = MagicMock()
    file_repo.list_all.return_value = [{"id": "f1", "file_name": "app.py", "file_hash": "hash"}]
    engine = ThreatAnalyticsEngine(file_repo=file_repo)
    report = engine.generate_report()

    assert any("routine SOC monitoring" in r for r in report.recommendations)


def test_compile_summary_with_custom_severity_and_risk_levels() -> None:
    """Verify compiling custom severities and unknown risk levels."""
    threat_repo = MagicMock()
    threat_repo.list_all.return_value = [
        {"id": "t1", "threat_type": "UNKNOWN", "severity": "SPECIAL_CUSTOM", "description": "Custom"},
    ]
    url_repo = MagicMock()
    url_repo.list_all.return_value = [
        {"id": "u1", "url": "https://test.com", "risk_level": "SUSPICIOUS_CUSTOM"},
    ]
    engine = ThreatAnalyticsEngine(threat_repo=threat_repo, url_repo=url_repo)
    summary = engine.compile_summary()

    assert summary.threats_by_severity.get("SPECIAL_CUSTOM") == 1
    assert summary.url_risk_stats.get("SUSPICIOUS_CUSTOM") == 1

