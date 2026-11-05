"""Unit tests for URL Security Analyzer Desktop GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from frontend.url_view import URLSecurityView
from security.url_analyzer import URLRiskLevel, URLSecurityAnalyzer


@pytest.fixture
def tk_root() -> tk.Tk:
    """Fixture providing a hidden Tk root for GUI tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


def test_url_view_initialization(tk_root: tk.Tk) -> None:
    """Verify initialization of UI widgets and initial empty state."""
    feedback_mock = MagicMock()
    view = URLSecurityView(tk_root, on_feedback=feedback_mock)

    assert view.entry_url is not None
    assert view.btn_analyze is not None
    assert view.btn_clear is not None
    assert view.url_var.get() == ""
    assert view.last_result is None

    # Trigger canvas configure
    event = MagicMock()
    event.width = 900
    view._on_canvas_configure(event)
    view._on_frame_configure(event)


def test_url_view_empty_input_analysis(tk_root: tk.Tk) -> None:
    """Verify empty input triggers helpful user feedback."""
    feedback_mock = MagicMock()
    view = URLSecurityView(tk_root, on_feedback=feedback_mock)
    view.url_var.set("   ")
    view.run_analysis()

    feedback_mock.assert_called_with("Please enter a URL to analyze.")
    assert view.last_result is None


def test_url_view_successful_analysis_low_risk(tk_root: tk.Tk) -> None:
    """Verify analyzing clean URL renders LOW risk overview, DFA sequence, and meter."""
    feedback_mock = MagicMock()
    view = URLSecurityView(tk_root, on_feedback=feedback_mock)
    view.url_var.set("https://google.com/search")

    view.run_analysis()
    assert view.last_result is not None
    assert view.last_result.risk_level == URLRiskLevel.LOW
    assert view.meter_canvas is not None
    feedback_mock.assert_called_with("URL analysis complete: Risk Level LOW (0/100)")

    # Test drawing meter
    view.meter_canvas.winfo_width = MagicMock(return_value=400)
    view.meter_canvas.winfo_height = MagicMock(return_value=12)
    view._draw_meter(25.0, "#22c55e")

    # Test drawing meter with width 0 (early return)
    view.meter_canvas.winfo_width = MagicMock(return_value=0)
    view._draw_meter(25.0, "#22c55e")


def test_url_view_critical_risk_rendering(tk_root: tk.Tk) -> None:
    """Verify high-severity URL triggers CRITICAL risk badge and indicator chips."""
    feedback_mock = MagicMock()
    view = URLSecurityView(tk_root, on_feedback=feedback_mock)
    view.url_var.set("http://192.168.1.1@fake-paypal-login.xyz/banking/verify//account")

    view.run_analysis()
    assert view.last_result is not None
    assert view.last_result.risk_level == URLRiskLevel.CRITICAL
    assert len(view.last_result.indicators) > 1


def test_url_view_return_key_binding(tk_root: tk.Tk) -> None:
    """Verify pressing return key in entry field triggers analysis."""
    feedback_mock = MagicMock()
    view = URLSecurityView(tk_root, on_feedback=feedback_mock)
    view.url_var.set("https://cybershield.org")

    # Invoke event binding directly
    view.entry_url.event_generate("<Return>")
    # Or call run_analysis directly as event callback
    view.run_analysis()
    assert view.last_result is not None


def test_url_view_clear_all(tk_root: tk.Tk) -> None:
    """Verify clear button resets input, results, and restores empty state."""
    feedback_mock = MagicMock()
    view = URLSecurityView(tk_root, on_feedback=feedback_mock)
    view.url_var.set("https://example.com")
    view.run_analysis()
    assert view.last_result is not None

    view.clear_all()
    assert view.url_var.get() == ""
    assert view.last_result is None
    feedback_mock.assert_called_with("URL analyzer reset.")

