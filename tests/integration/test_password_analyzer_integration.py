"""Integration tests for CyberShield Password Security Analyzer core engine."""

from __future__ import annotations

import socket
from unittest.mock import patch
import pytest

from security import (
    PasswordAnalysisResult,
    PasswordAnalyzer,
    PasswordStrength,
)


def test_public_package_exports() -> None:
    """Verify that security package exports expected analyzer symbols."""
    import security

    assert hasattr(security, "PasswordAnalyzer")
    assert hasattr(security, "PasswordAnalysisResult")
    assert hasattr(security, "PasswordStrength")


def test_complete_analysis_pipeline_integration() -> None:
    """Verify end-to-end integration of length, diversity, entropy, dictionary, and patterns."""
    analyzer = PasswordAnalyzer()

    # Synthetic password with deliberate mixed signals:
    # 16 chars, mixed diversity, but contains sequential numbers "123" and keyboard walk "qwe"
    synthetic_input = "P@ss123#qweSecure"
    result = analyzer.analyze(synthetic_input)

    assert isinstance(result, PasswordAnalysisResult)
    assert result.length == 17
    assert result.character_diversity == 4
    assert result.character_categories["lowercase"] is True
    assert result.character_categories["uppercase"] is True
    assert result.character_categories["digits"] is True
    assert result.character_categories["symbols"] is True

    # Patterns detected in the integrated analysis
    assert "sequential_numeric" in result.detected_patterns
    assert "keyboard_walk" in result.detected_patterns

    # Recommendations must advise fixing the detected patterns
    recs_text = " ".join(result.recommendations).lower()
    assert "sequential" in recs_text or "keyboard" in recs_text

    # Serialization check
    serialized = result.to_dict()
    assert isinstance(serialized, dict)
    assert serialized["length"] == 17
    assert serialized["character_diversity"] == 4


def test_multiple_independent_analyses_isolation() -> None:
    """Verify that multiple consecutive analyses on the same instance are strictly isolated."""
    analyzer = PasswordAnalyzer()

    # Analysis 1: Weak dictionary
    res1 = analyzer.analyze("password")
    assert res1.strength == PasswordStrength.VERY_WEAK.value
    assert res1.dictionary_match is True

    # Analysis 2: Very Strong passphrase with uncommon words
    res2 = analyzer.analyze("krypton-xylophone-quartz-zenith-8351!")
    assert res2.strength == PasswordStrength.VERY_STRONG.value
    assert res2.dictionary_match is False
    assert len(res2.detected_patterns) == 0

    # Analysis 3: Empty input
    res3 = analyzer.analyze("")
    assert res3.score == 0
    assert res3.strength == PasswordStrength.VERY_WEAK.value

    # Analysis 4: Repeat of Analysis 2 produces identical pure result
    res4 = analyzer.analyze("krypton-xylophone-quartz-zenith-8351!")
    assert res4.score == res2.score
    assert res4.shannon_entropy_bits == res2.shannon_entropy_bits


def test_zero_network_calls_during_analysis() -> None:
    """Verify that the analyzer executes completely offline with zero socket/network operations."""
    analyzer = PasswordAnalyzer()

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("Network socket connection attempted during password analysis!")

    with patch.object(socket.socket, "connect", side_effect=forbidden_connect):
        result = analyzer.analyze("AnyComplex$Test1234!")
        assert isinstance(result, PasswordAnalysisResult)
        assert result.length == 20


def test_zero_database_calls_during_analysis() -> None:
    """Verify that the analyzer does not query or persist to SQLite or PostgreSQL."""
    analyzer = PasswordAnalyzer()

    with patch("database.sqlite_manager.SQLiteManager.execute", side_effect=AssertionError("SQLite called")):
        with patch("database.postgres_manager.PostgresManager.execute", side_effect=AssertionError("Postgres called")):
            result = analyzer.analyze("IsolatedExecution#2026")
            assert isinstance(result, PasswordAnalysisResult)
            assert result.length == 22

