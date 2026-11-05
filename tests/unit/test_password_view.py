"""Unit tests for CyberShield Password Security Analyzer GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock
import pytest

from frontend.password_view import (
    PasswordSecurityView,
    STRENGTH_COLORS,
)
from security.password_analyzer import (
    PasswordAnalyzer,
    PasswordStrength,
)


@pytest.fixture
def password_view(tk_root):
    """Provide an isolated PasswordSecurityView instance attached to a test window."""
    feedback_mock = MagicMock()
    view = PasswordSecurityView(tk_root, on_feedback=feedback_mock)
    view.pack(fill=tk.BOTH, expand=True)
    tk_root.update_idletasks()
    yield view
    try:
        view.destroy()
    except Exception:
        pass


def test_password_view_initial_state(password_view: PasswordSecurityView) -> None:
    """Verify clean initial state on view mount."""
    assert password_view.password_var.get() == ""
    assert password_view.password_entry.cget("show") == "•"
    assert password_view.is_password_visible is False
    assert password_view.toggle_btn.cget("text") == "👁 Show"
    assert password_view.validation_lbl.cget("text") == ""
    assert password_view.last_result is None


def test_password_visibility_toggle(password_view: PasswordSecurityView) -> None:
    """Verify interactive toggle between masked bullets and visible text."""
    # Toggle to visible
    password_view.toggle_password_visibility()
    assert password_view.is_password_visible is True
    assert password_view.password_entry.cget("show") == ""
    assert password_view.toggle_btn.cget("text") == "🙈 Hide"

    # Toggle back to masked
    password_view.toggle_password_visibility()
    assert password_view.is_password_visible is False
    assert password_view.password_entry.cget("show") == "•"
    assert password_view.toggle_btn.cget("text") == "👁 Show"


def test_password_view_empty_input_validation(password_view: PasswordSecurityView) -> None:
    """Verify validation feedback when attempting analysis with an empty input."""
    password_view.password_var.set("")
    password_view.run_analysis()

    assert "Please enter a password" in password_view.validation_lbl.cget("text")
    assert password_view.last_result is None
    password_view.on_feedback.assert_called_with("Password analysis halted: Input field is empty.")


def test_password_view_clear_functionality(password_view: PasswordSecurityView) -> None:
    """Verify Clear button wipes input and resets result panels."""
    password_view.password_var.set("TestPassword123!")
    password_view.run_analysis()
    assert password_view.last_result is not None

    password_view.clear_input()
    assert password_view.password_var.get() == ""
    assert password_view.validation_lbl.cget("text") == ""
    assert password_view.last_result is None
    password_view.on_feedback.assert_called_with("Password input and analysis metrics cleared.")


def test_password_view_return_key_trigger(password_view: PasswordSecurityView) -> None:
    """Verify pressing Enter in entry executes analysis."""
    password_view.password_var.set("SimpleSecret99!")
    password_view._on_entry_return(None)
    password_view.update_idletasks()

    assert password_view.last_result is not None
    assert password_view.last_result.length == len("SimpleSecret99!")


def test_password_view_empty_recommendations_fallback(password_view: PasswordSecurityView) -> None:
    """Verify clean rendering when a result has empty recommendations."""
    from security.password_analyzer import PasswordAnalysisResult
    empty_rec_result = PasswordAnalysisResult(
        strength="VERY_STRONG",
        score=100,
        length=20,
        character_diversity=4,
        character_categories={"lowercase": True, "uppercase": True, "digits": True, "symbols": True},
        shannon_entropy_bits=80.0,
        estimated_pool_entropy_bits=120.0,
        dictionary_match=False,
        detected_patterns=[],
        recommendations=[],
    )
    password_view._render_analysis_results(empty_rec_result)
    assert password_view.results_container.winfo_children() is not None


@pytest.mark.parametrize(
    ("test_password", "expected_strength", "expected_score_min", "expected_score_max"),
    [
        ("123456", PasswordStrength.VERY_WEAK.value, 0, 15),
        ("dr@g0n", PasswordStrength.WEAK.value, 15, 30),
        ("Cobalt#77", PasswordStrength.MODERATE.value, 40, 59),
        ("Correct-Horse-Battery-Staple-2026!", PasswordStrength.STRONG.value, 60, 70),
        ("X7$kQ9@mP2&wL8*vN4^rT1", PasswordStrength.VERY_STRONG.value, 85, 100),
    ],
)
def test_password_view_all_five_strength_tiers(
    password_view: PasswordSecurityView,
    test_password: str,
    expected_strength: str,
    expected_score_min: int,
    expected_score_max: int,
) -> None:
    """Verify full GUI rendering for all five strength classifications."""
    password_view.password_var.set(test_password)
    password_view.run_analysis()

    result = password_view.last_result
    assert result is not None
    assert result.strength == expected_strength
    assert expected_score_min <= result.score <= expected_score_max

    # Check GUI components rendered
    assert hasattr(password_view, "strength_badge")
    assert expected_strength.replace("_", " ") in password_view.strength_badge.cget("text")
    assert f"{result.score} / 100" in password_view.score_lbl.cget("text")
    assert f"{result.length} characters" in password_view.length_lbl.cget("text")
    assert f"{result.character_diversity} of 4 classes" in password_view.diversity_lbl.cget("text")
    assert f"{result.shannon_entropy_bits:.2f} bits" in password_view.shannon_lbl.cget("text")
    assert f"{result.estimated_pool_entropy_bits:.2f} bits" in password_view.pool_lbl.cget("text")


def test_password_view_length_status_thresholds(password_view: PasswordSecurityView) -> None:
    """Verify length status badge text across length ranges."""
    # 1. Excessively short (<8)
    password_view.password_var.set("Ab1!")
    password_view.run_analysis()
    assert password_view.last_result is not None
    assert password_view.last_result.length == 4

    # 2. Acceptable minimum (8-11)
    password_view.password_var.set("MyPass12!")
    password_view.run_analysis()
    assert password_view.last_result is not None
    assert password_view.last_result.length == 9

    # 3. Meets recommended (>=12)
    password_view.password_var.set("MySuperPassphrase123!")
    password_view.run_analysis()
    assert password_view.last_result is not None
    assert password_view.last_result.length >= 12


def test_password_view_dictionary_match_and_patterns_rendering(password_view: PasswordSecurityView) -> None:
    """Verify dictionary match badge and pattern chips appear in UI."""
    # Dictionary match with patterns
    password_view.password_var.set("password123")
    password_view.run_analysis()

    assert password_view.last_result.dictionary_match is True
    assert "MATCH FOUND" in password_view.dict_badge.cget("text")

    # Clean password without patterns
    password_view.password_var.set("X7$kQ9@mP2&wL8*vN4^rT1")
    password_view.run_analysis()
    assert password_view.last_result.dictionary_match is False
    assert "No exact common dictionary match" in password_view.dict_badge.cget("text")


def test_password_view_canvas_scroll_bindings(password_view: PasswordSecurityView) -> None:
    """Verify canvas configure handlers execute cleanly."""
    mock_canvas_event = MagicMock()
    mock_canvas_event.width = 1100
    password_view._on_canvas_configure(mock_canvas_event)

    mock_frame_event = MagicMock()
    password_view._on_frame_configure(mock_frame_event)


def test_password_view_exception_handling(password_view: PasswordSecurityView) -> None:
    """Verify graceful handling when analysis engine raises an unexpected error."""
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.side_effect = RuntimeError("Simulated internal fault")

    password_view.analyzer = mock_analyzer
    password_view.password_var.set("SomePassword123")
    password_view.run_analysis()

    assert "Analysis error encountered: RuntimeError" in password_view.validation_lbl.cget("text")
