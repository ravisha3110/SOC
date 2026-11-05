"""Unit tests for Security Reports Desktop GUI View."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

from frontend.reports_view import ReportsView
from security.threat_analytics import (
    SecurityReport,
    ThreatAnalyticsEngine,
    ThreatAnalyticsSummary,
)


@pytest.fixture
def tk_root() -> tk.Tk:
    """Fixture providing a hidden Tk root for GUI testing."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


def test_reports_view_initialization_and_preview(tk_root: tk.Tk) -> None:
    """Verify initialization, configuration entry fields, and live preview rendering."""
    feedback_mock = MagicMock()
    mock_engine = MagicMock()
    mock_engine.generate_report.return_value = SecurityReport(
        title="Test Report",
        analyst_name="Test Analyst",
        summary=ThreatAnalyticsSummary(total_scans=10, total_threats=2),
        recommendations=["Action item 1", "Action item 2"],
    )

    view = ReportsView(tk_root, engine=mock_engine, on_feedback=feedback_mock)

    assert view.btn_preview is not None
    assert view.btn_export_html is not None
    assert view.btn_export_csv is not None
    assert view.current_report is not None

    # Test regenerating preview (destroy existing children)
    view.generate_and_preview()
    event = MagicMock()
    event.width = 900
    view._on_canvas_configure(event)
    view._on_frame_configure(event)


def test_reports_view_export_html_dialog(tk_root: tk.Tk, tmp_path: Path) -> None:
    """Verify exporting HTML report via file dialog."""
    feedback_mock = MagicMock()
    mock_engine = MagicMock()
    mock_engine.generate_report.return_value = SecurityReport(
        title="HTML Test",
        analyst_name="Analyst A",
        summary=ThreatAnalyticsSummary(),
    )

    view = ReportsView(tk_root, engine=mock_engine, on_feedback=feedback_mock)
    view.current_report = None
    target_file = tmp_path / "test_out.html"

    with patch("tkinter.filedialog.asksaveasfilename", return_value=str(target_file)):
        view.export_html_dialog()
        assert target_file.exists()
        assert any("HTML Report exported successfully" in call[0][0] for call in feedback_mock.call_args_list)

    # When dialog canceled
    with patch("tkinter.filedialog.asksaveasfilename", return_value=""):
        view.export_html_dialog()


def test_reports_view_export_csv_dialog(tk_root: tk.Tk, tmp_path: Path) -> None:
    """Verify exporting CSV findings report via file dialog."""
    feedback_mock = MagicMock()
    mock_engine = MagicMock()
    mock_engine.generate_report.return_value = SecurityReport(
        title="CSV Test",
        analyst_name="Analyst B",
        summary=ThreatAnalyticsSummary(),
    )

    view = ReportsView(tk_root, engine=mock_engine, on_feedback=feedback_mock)
    view.current_report = None
    target_file = tmp_path / "test_out.csv"

    with patch("tkinter.filedialog.asksaveasfilename", return_value=str(target_file)):
        view.export_csv_dialog()
        assert target_file.exists()
        assert any("CSV Report exported successfully" in call[0][0] for call in feedback_mock.call_args_list)

    # When dialog canceled
    with patch("tkinter.filedialog.asksaveasfilename", return_value=""):
        view.export_csv_dialog()

