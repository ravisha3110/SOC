"""Unit tests for Threat Analytics Desktop GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from frontend.threat_analytics_view import ThreatAnalyticsView
from security.threat_analytics import (
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


def test_threat_analytics_view_initialization_and_rendering(tk_root: tk.Tk) -> None:
    """Verify initialization, rendering of metrics, severity bar, and treeview."""
    feedback_mock = MagicMock()
    mock_engine = MagicMock()
    mock_engine.compile_summary.return_value = ThreatAnalyticsSummary(
        total_scans=15,
        total_threats=4,
        threats_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
        file_integrity_stats={"total_baselines": 6},
        url_risk_stats={"total_analyzed": 5},
        recent_findings=[
            {"id": "t-1", "threat_type": "INJECTION", "severity": "CRITICAL", "description": "SQL attempt", "created_at": "2026-11-05"},
        ],
    )

    view = ThreatAnalyticsView(tk_root, engine=mock_engine, on_feedback=feedback_mock)

    assert view.btn_refresh is not None
    assert view.tree is not None

    # Test canvas configure bindings
    event = MagicMock()
    event.width = 900
    view._on_canvas_configure(event)
    view._on_frame_configure(event)

    # Trigger severity bar draw
    view.canvas_bar.draw_sev(MagicMock(width=500, height=12))
    view.canvas_bar.draw_sev(MagicMock(width=1, height=12))
    tk_root.update_idletasks()

    children = view.tree.get_children()
    assert len(children) == 1
    feedback_mock.assert_called_with("Threat analytics updated: 4 threats, 15 scans compiled.")


def test_threat_analytics_view_recalculate(tk_root: tk.Tk) -> None:
    """Verify refresh button recalculates metrics."""
    mock_engine = MagicMock()
    mock_engine.compile_summary.return_value = ThreatAnalyticsSummary()

    view = ThreatAnalyticsView(tk_root, engine=mock_engine)
    view.refresh_analytics()
    assert mock_engine.compile_summary.call_count == 2  # initial + refresh

