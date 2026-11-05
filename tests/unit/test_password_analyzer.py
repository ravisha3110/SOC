"""Unit tests for CyberShield Password Security Analyzer core engine."""

from __future__ import annotations

import math
import pytest

from security.password_analyzer import (
    PasswordAnalysisResult,
    PasswordAnalyzer,
    PasswordStrength,
)


def test_analyzer_rejects_non_string_types() -> None:
    """Verify that analyzer raises TypeError on invalid types without leaking input."""
    analyzer = PasswordAnalyzer()
    invalid_inputs = [None, 123456, ["secret"], {"pass": "word"}, 45.67, True]

    for item in invalid_inputs:
        with pytest.raises(TypeError) as exc_info:
            analyzer.analyze(item)  # type: ignore[arg-type]
        # Verify the exception message is sanitized and does not leak input details
        assert "Password input must be a string" in str(exc_info.value)


def test_analyzer_empty_input_handling() -> None:
    """Verify safe and predictable handling of empty string input."""
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze("")

    assert isinstance(result, PasswordAnalysisResult)
    assert result.strength == PasswordStrength.VERY_WEAK.value
    assert result.score == 0
    assert result.length == 0
    assert result.character_diversity == 0
    assert result.shannon_entropy_bits == 0.0
    assert result.estimated_pool_entropy_bits == 0.0
    assert result.dictionary_match is False
    assert "empty_input" in result.detected_patterns
    assert any("empty" in r.lower() for r in result.recommendations)


def test_analyzer_excessively_short_passwords() -> None:
    """Verify that very short passwords cannot attain high strength classifications."""
    analyzer = PasswordAnalyzer()

    # 3-char password with mixed characters
    result_short_mixed = analyzer.analyze("A1!")
    assert result_short_mixed.length == 3
    assert result_short_mixed.strength in (
        PasswordStrength.VERY_WEAK.value,
        PasswordStrength.WEAK.value,
    )
    assert result_short_mixed.score <= 35

    # 7-char password
    result_seven = analyzer.analyze("Abc12!x")
    assert result_seven.length == 7
    assert result_seven.strength in (
        PasswordStrength.VERY_WEAK.value,
        PasswordStrength.WEAK.value,
    )
    assert result_seven.score <= 35


def test_analyzer_long_passwords() -> None:
    """Verify that long, unpredictable passwords achieve high scores."""
    analyzer = PasswordAnalyzer()
    # 32-character high entropy passphrase
    long_pass = "V3ry$tr0ng-P@ssphr@se-W1th-M@ny-C#ars!"
    result = analyzer.analyze(long_pass)

    assert result.length == len(long_pass)
    assert result.strength in (
        PasswordStrength.STRONG.value,
        PasswordStrength.VERY_STRONG.value,
    )
    assert result.score >= 80
    assert result.character_diversity == 4


def test_character_diversity_categories() -> None:
    """Verify that each character class is correctly and independently identified."""
    analyzer = PasswordAnalyzer()

    # Lowercase only
    res_lower = analyzer.analyze("abcdefghijk")
    assert res_lower.character_categories["lowercase"] is True
    assert res_lower.character_categories["uppercase"] is False
    assert res_lower.character_categories["digits"] is False
    assert res_lower.character_categories["symbols"] is False
    assert res_lower.character_diversity == 1

    # Uppercase only
    res_upper = analyzer.analyze("ABCDEFGHIJK")
    assert res_upper.character_categories["lowercase"] is False
    assert res_upper.character_categories["uppercase"] is True
    assert res_upper.character_categories["digits"] is False
    assert res_upper.character_categories["symbols"] is False
    assert res_upper.character_diversity == 1

    # Digits only
    res_digits = analyzer.analyze("987654321012")
    assert res_digits.character_categories["lowercase"] is False
    assert res_digits.character_categories["uppercase"] is False
    assert res_digits.character_categories["digits"] is True
    assert res_digits.character_categories["symbols"] is False
    assert res_digits.character_diversity == 1

    # Symbols only
    res_symbols = analyzer.analyze("!@#$%^&*()-+")
    assert res_symbols.character_categories["lowercase"] is False
    assert res_symbols.character_categories["uppercase"] is False
    assert res_symbols.character_categories["digits"] is False
    assert res_symbols.character_categories["symbols"] is True
    assert res_symbols.character_diversity == 1

    # Mixed all 4 categories
    res_mixed = analyzer.analyze("K9#m$L2@vP8*qR4&")
    assert res_mixed.character_diversity == 4
    assert all(res_mixed.character_categories.values())


def test_unicode_character_handling() -> None:
    """Verify robust recognition and pool entropy calculation for Unicode characters."""
    analyzer = PasswordAnalyzer()

    # Accented letters and symbols: 'é', 'ñ', 'ü', '★', '€'
    unicode_pass = "Pässwörd★2026€ñ"
    result = analyzer.analyze(unicode_pass)

    assert result.length == len(unicode_pass)
    assert result.character_categories["lowercase"] is True
    assert result.character_categories["uppercase"] is True
    assert result.character_categories["digits"] is True
    assert result.character_categories["symbols"] is True
    assert result.estimated_pool_entropy_bits > 0.0


def test_shannon_entropy_calculation() -> None:
    """Verify Shannon entropy mathematics and low-entropy detection for repeated characters."""
    analyzer = PasswordAnalyzer()

    # Case 1: Monotypic password has 0 bits of Shannon entropy
    res_mono = analyzer.analyze("aaaaaaaaaaaa")
    assert res_mono.shannon_entropy_bits == 0.0
    assert res_mono.strength == PasswordStrength.VERY_WEAK.value

    # Case 2: 4 distinct characters repeated equally has 2 bits per char -> 16 total bits
    res_uniform = analyzer.analyze("abcdabcdabcdabcd")
    expected_bits = round(16 * math.log2(4), 2)  # 16 * 2.0 = 32.0
    assert res_uniform.shannon_entropy_bits == expected_bits

    # Shannon vs Pool entropy distinction
    assert res_uniform.shannon_entropy_bits != res_uniform.estimated_pool_entropy_bits


def test_dictionary_match_detection() -> None:
    """Verify case-insensitive matching against bundled common passwords."""
    analyzer = PasswordAnalyzer()

    # Exact common dictionary passwords
    for common in ["password", "123456", "admin", "dragon", "welcome"]:
        res = analyzer.analyze(common)
        assert res.dictionary_match is True
        assert "common_dictionary_word" in res.detected_patterns
        assert res.strength == PasswordStrength.VERY_WEAK.value
        assert res.score <= 10

    # Case-insensitive
    res_upper_dict = analyzer.analyze("PASSWORD")
    assert res_upper_dict.dictionary_match is True
    assert res_upper_dict.strength == PasswordStrength.VERY_WEAK.value


def test_pattern_detection_repeated_characters() -> None:
    """Verify detection of 3+ consecutive identical characters."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("Secret1111Key")
    assert "repeated_characters" in res.detected_patterns


def test_pattern_detection_repeated_sequences() -> None:
    """Verify detection of repeated syllables or sequences."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("testtesttest2026")
    assert "repeated_sequences" in res.detected_patterns


def test_pattern_detection_sequential_numeric() -> None:
    """Verify detection of ascending or descending sequential numbers."""
    analyzer = PasswordAnalyzer()

    res_asc = analyzer.analyze("SecureKey1234")
    assert "sequential_numeric" in res_asc.detected_patterns

    res_desc = analyzer.analyze("SecureKey9876")
    assert "sequential_numeric" in res_desc.detected_patterns

    # Dispersed digits should NOT falsely trigger sequential numeric
    res_non_seq = analyzer.analyze("S1e2c3u4r5e6K7e8y9")
    assert "sequential_numeric" not in res_non_seq.detected_patterns


def test_pattern_detection_sequential_alphabetic() -> None:
    """Verify detection of ascending or descending alphabetical runs."""
    analyzer = PasswordAnalyzer()

    res_asc = analyzer.analyze("MyPasscode-abcd-99")
    assert "sequential_alphabetic" in res_asc.detected_patterns

    res_desc = analyzer.analyze("MyPasscode-dcba-99")
    assert "sequential_alphabetic" in res_desc.detected_patterns


def test_pattern_detection_keyboard_walk() -> None:
    """Verify detection of QWERTY keyboard sequences."""
    analyzer = PasswordAnalyzer()

    res_qwe = analyzer.analyze("Super#qwertz#99")
    assert "keyboard_walk" in res_qwe.detected_patterns

    res_asdf = analyzer.analyze("Key!asdfgh!2026")
    assert "keyboard_walk" in res_asdf.detected_patterns


def test_pattern_detection_leet_substitution() -> None:
    """Verify detection of common l33t-speak dictionary masks."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("dr@g0n")
    assert "leet_substitution" in res.detected_patterns
    assert res.strength == PasswordStrength.WEAK.value
    assert res.score <= 20


def test_recognizable_common_multiword_phrase() -> None:
    """Verify that recognizable multiword phrases with predictable years are penalized and not VERY_STRONG."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("Correct-Horse-Battery-Staple-2026!")

    assert "common_multiword_phrase" in res.detected_patterns
    assert "predictable_year" in res.detected_patterns
    # Must NOT be VERY_STRONG solely due to length
    assert res.strength != PasswordStrength.VERY_STRONG.value
    assert res.strength == PasswordStrength.STRONG.value
    assert res.score <= 65
    assert any("recognizable" in r.lower() for r in res.recommendations)
    assert any("calendar" in r.lower() or "year" in r.lower() for r in res.recommendations)

    # Shorter multiword phrases of common words should be MODERATE or WEAK
    res_mod = analyzer.analyze("dragon-ninja-1")
    assert "common_multiword_phrase" in res_mod.detected_patterns
    assert res_mod.strength == PasswordStrength.MODERATE.value

    res_weak = analyzer.analyze("dragon-ninja")
    assert "common_multiword_phrase" in res_weak.detected_patterns
    assert res_weak.strength == PasswordStrength.WEAK.value


def test_word_separator_year_pattern() -> None:
    """Verify detection and penalization of word + separator + year structures."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("Password-2026!")

    assert "predictable_year" in res.detected_patterns
    assert "word_number_combination" in res.detected_patterns
    assert res.strength == PasswordStrength.WEAK.value
    assert res.score <= 35


def test_seasonal_word_year_pattern() -> None:
    """Verify detection and capping of seasonal or month words combined with years."""
    analyzer = PasswordAnalyzer()

    res_summer = analyzer.analyze("Summer2026")
    assert "seasonal_year_pattern" in res_summer.detected_patterns
    assert "predictable_year" in res_summer.detected_patterns
    assert res_summer.strength in (PasswordStrength.VERY_WEAK.value, PasswordStrength.WEAK.value)
    assert res_summer.score <= 35

    res_winter = analyzer.analyze("Winter-2025!")
    assert "seasonal_year_pattern" in res_winter.detected_patterns
    assert "predictable_year" in res_winter.detected_patterns
    assert res_winter.strength != PasswordStrength.VERY_STRONG.value
    assert res_winter.strength != PasswordStrength.STRONG.value


def test_common_word_number_pattern() -> None:
    """Verify detection of single dictionary word followed by numbers."""
    analyzer = PasswordAnalyzer()

    # Short word + number
    res_short = analyzer.analyze("Tiger99")
    assert "word_number_combination" in res_short.detected_patterns
    assert res_short.strength == PasswordStrength.WEAK.value
    assert res_short.score <= 35

    # Long word + number with non-year digits
    res_long = analyzer.analyze("Shadow78319024")
    assert "word_number_combination" in res_long.detected_patterns
    assert res_long.score <= 50
    assert res_long.strength in (PasswordStrength.MODERATE.value, PasswordStrength.WEAK.value)


def test_uncommon_long_passphrase_not_automatically_rejected() -> None:
    """Verify that long passphrases with uncommon words are NOT penalized or rejected."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("krypton-xylophone-quartz-zenith-8351!")

    assert "common_multiword_phrase" not in res.detected_patterns
    assert "predictable_year" not in res.detected_patterns
    assert res.strength == PasswordStrength.VERY_STRONG.value
    assert res.score >= 80


def test_random_looking_synthetic_password() -> None:
    """Verify that truly random-looking synthetic passwords achieve highest tier."""
    analyzer = PasswordAnalyzer()
    res = analyzer.analyze("X7$kQ9@mP2&wL8*vN4^rT1")

    assert res.strength == PasswordStrength.VERY_STRONG.value
    assert res.score >= 90
    assert len(res.detected_patterns) == 0


def test_all_five_strength_classifications() -> None:
    """Verify that every tier of the 5-tier classification is attainable with appropriate inputs."""
    analyzer = PasswordAnalyzer()

    # 1. VERY_WEAK (dictionary match and keyboard-walk penalized below 20)
    res_vw_dict = analyzer.analyze("123456")
    assert res_vw_dict.strength == PasswordStrength.VERY_WEAK.value

    res_vw_walk = analyzer.analyze("asdfghjk")
    assert res_vw_walk.strength == PasswordStrength.VERY_WEAK.value
    assert res_vw_walk.score < 20

    # 2. WEAK (leet substituted dictionary mask)
    res_w = analyzer.analyze("dr@g0n")
    assert res_w.strength == PasswordStrength.WEAK.value

    # 3. MODERATE (moderate length, 3-4 categories, score ~40-59)
    res_m = analyzer.analyze("Cobalt#77")
    assert res_m.strength == PasswordStrength.MODERATE.value

    # 4. STRONG (good length, multiword passphrase with capped score 65)
    res_s = analyzer.analyze("Correct-Horse-Battery-Staple-2026!")
    assert res_s.strength == PasswordStrength.STRONG.value

    # 5. VERY_STRONG (long, complex, high-entropy random sequence)
    res_vs = analyzer.analyze("X7$kQ9@mP2&wL8*vN4^rT1")
    assert res_vs.strength == PasswordStrength.VERY_STRONG.value


def test_password_privacy_and_no_retention() -> None:
    """Verify that the analyzer does not store or expose raw passwords."""
    analyzer = PasswordAnalyzer()
    synthetic_pass = "Temporary-Test-Pass-9988!"
    result = analyzer.analyze(synthetic_pass)

    # 1. Result object does not contain the password string
    assert not hasattr(result, "password")
    assert not hasattr(result, "raw_password")
    assert not hasattr(result, "plaintext")
    assert synthetic_pass not in str(result)
    assert synthetic_pass not in repr(result)

    # 2. Dictionary conversion does not expose password
    res_dict = result.to_dict()
    assert "password" not in res_dict
    assert synthetic_pass not in str(res_dict)

    # 3. Analyzer instance does not retain password
    assert not hasattr(analyzer, "password")
    assert not hasattr(analyzer, "last_password")


def test_custom_thresholds_and_wordlist() -> None:
    """Verify that analyzer honors custom configured thresholds and wordlist."""
    custom_dict = frozenset(["mycompanysecret"])
    custom_analyzer = PasswordAnalyzer(
        min_recommended_length=16,
        excessively_short_length=10,
        common_passwords=custom_dict,
    )

    # Custom wordlist match
    res_custom_dict = custom_analyzer.analyze("mycompanysecret")
    assert res_custom_dict.dictionary_match is True
    assert res_custom_dict.strength == PasswordStrength.VERY_WEAK.value

    # Standard dictionary word not in custom list should not be flagged as dictionary match
    res_std = custom_analyzer.analyze("123456")
    assert res_std.dictionary_match is False
