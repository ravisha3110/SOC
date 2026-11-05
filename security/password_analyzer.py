"""CyberShield Password Security Analyzer — Core Analysis Engine.

Provides multi-signal evaluation of password strength using:
- Configurable length checks (minimum recommended and excessively short thresholds)
- Character diversity detection across 4 categories + Unicode awareness
- Observed Shannon entropy H(X) = -sum(p * log2(p)) in bits
- Theoretical character pool entropy L * log2(R) in bits
- Local common password dictionary verification (zero network calls)
- Multiword phrase detection, word-separator-word structures, and predictable year patterns
- Structural pattern detection (repeated characters, repeated sequences, sequential numeric,
  sequential alphabetic, keyboard walks, seasonal patterns, and l33t substitutions)
- Multi-signal scoring and 5-tier classification:
  VERY_WEAK, WEAK, MODERATE, STRONG, VERY_STRONG

Strict Security Compliance:
- Never prints, logs, or stores raw passwords.
- Never includes passwords in exceptions, attributes, or result objects.
- Operates 100% offline with zero external network or database dependencies.
- No password persistence or caching.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
import math
import re
from typing import Any, Sequence

from security.wordlists import (
    COMMON_PASSWORDS,
    KEYBOARD_ROWS,
    LEET_SUBSTITUTIONS,
    SEASONS_AND_MONTHS,
)


class PasswordStrength(str, Enum):
    """Five-tier password strength classifications."""

    VERY_WEAK = "VERY_WEAK"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERY_STRONG = "VERY_STRONG"


@dataclass(frozen=True)
class PasswordAnalysisResult:
    """Immutable, privacy-safe structured analysis result.

    Notice: Does NOT contain raw password, reversible hashes, or persistent identifiers.
    Safe for UI rendering, logging, and diagnostics.
    """

    strength: str
    score: int
    length: int
    character_diversity: int
    character_categories: dict[str, bool]
    shannon_entropy_bits: float
    estimated_pool_entropy_bits: float
    dictionary_match: bool
    detected_patterns: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "strength": self.strength,
            "score": self.score,
            "length": self.length,
            "character_diversity": self.character_diversity,
            "character_categories": dict(self.character_categories),
            "shannon_entropy_bits": self.shannon_entropy_bits,
            "estimated_pool_entropy_bits": self.estimated_pool_entropy_bits,
            "dictionary_match": self.dictionary_match,
            "detected_patterns": list(self.detected_patterns),
            "recommendations": list(self.recommendations),
        }


class PasswordAnalyzer:
    """Standalone, multi-signal Password Security Analysis Engine."""

    def __init__(
        self,
        min_recommended_length: int = 12,
        excessively_short_length: int = 8,
        common_passwords: frozenset[str] | set[str] | None = None,
    ) -> None:
        """Initialize analyzer with configurable thresholds and wordlist.

        Args:
            min_recommended_length: Recommended minimum length (default 12).
            excessively_short_length: Threshold below which passwords are weak (default 8).
            common_passwords: Optional custom wordlist for demonstration dictionary checks.
        """
        self.min_recommended_length = min_recommended_length
        self.excessively_short_length = excessively_short_length
        self.common_passwords = (
            common_passwords if common_passwords is not None else COMMON_PASSWORDS
        )

    def analyze(self, password: str) -> PasswordAnalysisResult:
        """Analyze password security strength across multiple objective signals.

        Args:
            password: Input password string.

        Returns:
            PasswordAnalysisResult: Safe structured result without raw password.

        Raises:
            TypeError: If password is not a string.
        """
        if not isinstance(password, str):
            raise TypeError("Password input must be a string")

        length = len(password)

        # Handle empty input safely
        if length == 0:
            return PasswordAnalysisResult(
                strength=PasswordStrength.VERY_WEAK.value,
                score=0,
                length=0,
                character_diversity=0,
                character_categories={
                    "lowercase": False,
                    "uppercase": False,
                    "digits": False,
                    "symbols": False,
                },
                shannon_entropy_bits=0.0,
                estimated_pool_entropy_bits=0.0,
                dictionary_match=False,
                detected_patterns=["empty_input"],
                recommendations=[
                    "Password cannot be empty. Please enter a password with at least 12 characters."
                ],
            )

        # 1. Character diversity analysis
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        character_categories = {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digit,
            "symbols": has_symbol,
        }
        character_diversity = sum(character_categories.values())

        # 2. Empirical Shannon entropy estimation
        # H(X) = -sum(p * log2(p)) measures internal symbol distribution unpredictability.
        # Multiplying by length assumes an i.i.d. source of those unigrams.
        # It does NOT account for human linguistic patterns or dictionaries.
        counts = Counter(password)
        h_per_char = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
        shannon_entropy_bits = round(length * h_per_char, 2)

        # 3. Theoretical character-pool entropy estimation
        # L * log2(R) assumes uniform random selection across the active character set.
        # Real attackers do NOT guess uniformly at random; this is a combinatorial baseline.
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += 33
        if any(ord(c) > 127 for c in password):
            pool_size += 128

        estimated_pool_entropy_bits = (
            round(length * math.log2(pool_size), 2) if pool_size > 0 else 0.0
        )

        # 4. Dictionary match verification
        clean_lower = password.strip().lower()
        dictionary_match = clean_lower in self.common_passwords

        # 5. Pattern detection
        detected_patterns: list[str] = []
        if dictionary_match:
            detected_patterns.append("common_dictionary_word")

        # Repeated characters (e.g., 'aaa', '1111')
        if re.search(r"(.)\1{2,}", password):
            detected_patterns.append("repeated_characters")

        # Repeated sequences (e.g., 'abcabc', 'passpass')
        if re.search(r"(.{2,})\1+", clean_lower):
            detected_patterns.append("repeated_sequences")

        # Sequential numeric patterns (e.g., '123', '987' within contiguous digits)
        if self._has_sequential_digits(password):
            detected_patterns.append("sequential_numeric")

        # Sequential alphabetic patterns (e.g., 'abc', 'cba', 'xyz')
        if self._has_sequential_letters(password):
            detected_patterns.append("sequential_alphabetic")

        # Keyboard walks (e.g., 'qwe', 'asd', 'zxc')
        if self._has_keyboard_walk(clean_lower):
            detected_patterns.append("keyboard_walk")

        # L33t speak substitutions
        normalized_leet = "".join(LEET_SUBSTITUTIONS.get(c, c) for c in clean_lower)
        is_leet_match = (
            normalized_leet != clean_lower
            and (normalized_leet in self.common_passwords)
        )
        if is_leet_match:
            detected_patterns.append("leet_substitution")

        # Phrase, year, seasonal, and word-number patterns
        phrase_patterns = self._detect_phrase_patterns(password, clean_lower)
        detected_patterns.extend(phrase_patterns)

        # 6. Multi-signal scoring calculation (0-100)
        score = self._calculate_score(
            length=length,
            character_diversity=character_diversity,
            shannon_entropy_bits=shannon_entropy_bits,
            dictionary_match=dictionary_match,
            is_leet_match=is_leet_match,
            detected_patterns=detected_patterns,
        )

        # 7. Strength classification from final score
        strength = self._classify_strength(
            score=score,
            length=length,
            dictionary_match=dictionary_match,
            is_leet_match=is_leet_match,
            shannon_entropy_bits=shannon_entropy_bits,
            detected_patterns=detected_patterns,
        )

        # 8. Actionable recommendations
        recommendations = self._build_recommendations(
            length=length,
            character_categories=character_categories,
            dictionary_match=dictionary_match,
            detected_patterns=detected_patterns,
            strength=strength,
        )

        return PasswordAnalysisResult(
            strength=strength.value,
            score=score,
            length=length,
            character_diversity=character_diversity,
            character_categories=character_categories,
            shannon_entropy_bits=shannon_entropy_bits,
            estimated_pool_entropy_bits=estimated_pool_entropy_bits,
            dictionary_match=dictionary_match,
            detected_patterns=detected_patterns,
            recommendations=recommendations,
        )

    def _detect_phrase_patterns(self, password: str, clean_lower: str) -> list[str]:
        """Detect multiword phrases, predictable years, seasonal patterns, and word+number structures."""
        patterns: list[str] = []

        # 1. Predictable year pattern (1900-2099), especially as suffix or separated token
        has_year_suffix = bool(re.search(r"(?:19|20)\d{2}[^a-zA-Z0-9]*$", password))
        has_year_token = bool(re.search(r"(?:^|[^a-zA-Z0-9])(?:19|20)\d{2}(?:[^a-zA-Z0-9]|$)", password))
        if has_year_suffix or has_year_token:
            patterns.append("predictable_year")

        # 2. Seasonal / month name combined with year (e.g. Summer2026, Winter-2024!)
        seasonal_year = bool(
            re.search(
                r"(?:spring|summer|autumn|fall|winter|january|february|march|april|may|june|july|august|september|october|november|december)[^a-zA-Z0-9]*(?:19|20)\d{2}",
                clean_lower,
            )
            or re.search(
                r"(?:19|20)\d{2}[^a-zA-Z0-9]*(?:spring|summer|autumn|fall|winter|january|february|march|april|may|june|july|august|september|october|november|december)",
                clean_lower,
            )
        )
        if seasonal_year:
            patterns.append("seasonal_year_pattern")

        # 3. Common word + number pattern (e.g. Password123, Tiger99, Summer2026)
        word_num_match = re.fullmatch(r"([a-zA-Z]+)[^a-zA-Z0-9]*(\d+)[^a-zA-Z0-9]*", password)
        if word_num_match:
            word_part = word_num_match.group(1).lower()
            if word_part in self.common_passwords or word_part in SEASONS_AND_MONTHS:
                patterns.append("word_number_combination")

        # 4. Common multiword phrase (2 or more tokens matching common dictionary words)
        word_tokens = [t.lower() for t in re.split(r"[^a-zA-Z]+", password) if len(t) >= 3]
        if len(word_tokens) >= 2:
            matching_words = [
                w for w in word_tokens if w in self.common_passwords or w in SEASONS_AND_MONTHS
            ]
            if len(matching_words) >= 2:
                patterns.append("common_multiword_phrase")

        return patterns

    def _calculate_score(
        self,
        length: int,
        character_diversity: int,
        shannon_entropy_bits: float,
        dictionary_match: bool,
        is_leet_match: bool,
        detected_patterns: Sequence[str],
    ) -> int:
        """Calculate weighted score from 0 to 100 based on objective signals."""
        # A. Base score from length
        if length < self.excessively_short_length:
            score = length * 4  # 0 to 28
        elif length < self.min_recommended_length:
            score = 28 + (length - (self.excessively_short_length - 1)) * 5  # 33 to 48
        elif length <= 16:
            score = 48 + (length - (self.min_recommended_length - 1)) * 5  # 53 to 73
        else:
            score = 73 + min(length - 16, 10) * 2  # up to 93

        # B. Character diversity bonus
        diversity_bonuses = {0: 0, 1: 0, 2: 6, 3: 12, 4: 18}
        score += diversity_bonuses.get(character_diversity, 0)

        # C. Shannon entropy adjustments
        if shannon_entropy_bits < 15.0 and length >= 6:
            score -= 15  # Heavy penalty for low entropy / extreme character repetition
        elif shannon_entropy_bits >= 45.0:
            score += 5

        # D. Pattern penalties
        if "repeated_characters" in detected_patterns:
            score -= 12
        if "repeated_sequences" in detected_patterns:
            score -= 15
        if "sequential_numeric" in detected_patterns:
            score -= 10
        if "sequential_alphabetic" in detected_patterns:
            score -= 10
        if "keyboard_walk" in detected_patterns:
            score -= 15
        if "leet_substitution" in detected_patterns:
            score -= 15
        if "predictable_year" in detected_patterns:
            score -= 12
        if "seasonal_year_pattern" in detected_patterns:
            score -= 18
        if "word_number_combination" in detected_patterns:
            score -= 14
        if "common_multiword_phrase" in detected_patterns:
            score -= 22

        # E. Strict capping rules
        if dictionary_match:
            score = min(score, 10)
        elif is_leet_match:
            score = min(score, 20)
        elif "seasonal_year_pattern" in detected_patterns:
            score = min(score, 45)
        elif "word_number_combination" in detected_patterns:
            if "predictable_year" in detected_patterns or length < self.min_recommended_length:
                score = min(score, 35)
            else:
                score = min(score, 50)
        elif "common_multiword_phrase" in detected_patterns:
            max_allowed = 65 if "predictable_year" in detected_patterns else 70
            score = min(score, max_allowed)
        elif length < self.excessively_short_length:
            score = min(score, 35)
        elif shannon_entropy_bits < 10.0 and length >= 8:
            score = min(score, 15)

        return max(0, min(100, score))

    def _classify_strength(
        self,
        score: int,
        length: int,
        dictionary_match: bool,
        is_leet_match: bool,
        shannon_entropy_bits: float,
        detected_patterns: Sequence[str] = (),
    ) -> PasswordStrength:
        """Map score and security constraints to 5-tier classification."""
        if dictionary_match or (shannon_entropy_bits < 10.0 and length >= 8):
            return PasswordStrength.VERY_WEAK

        if is_leet_match or length < self.excessively_short_length:
            return PasswordStrength.WEAK if score >= 20 else PasswordStrength.VERY_WEAK

        if "seasonal_year_pattern" in detected_patterns:
            return PasswordStrength.MODERATE if score >= 40 else PasswordStrength.WEAK

        if "word_number_combination" in detected_patterns:
            if "predictable_year" in detected_patterns or score < 40:
                return PasswordStrength.WEAK if score >= 20 else PasswordStrength.VERY_WEAK

        if "common_multiword_phrase" in detected_patterns:
            # Common multiword phrases cannot receive VERY_STRONG
            if score >= 60:
                return PasswordStrength.STRONG
            elif score >= 40:
                return PasswordStrength.MODERATE
            return PasswordStrength.WEAK

        if score < 20:
            return PasswordStrength.VERY_WEAK
        if score < 40:
            return PasswordStrength.WEAK
        if score < 60:
            return PasswordStrength.MODERATE
        if score < 80:
            return PasswordStrength.STRONG
        return PasswordStrength.VERY_STRONG

    def _build_recommendations(
        self,
        length: int,
        character_categories: dict[str, bool],
        dictionary_match: bool,
        detected_patterns: Sequence[str],
        strength: PasswordStrength,
    ) -> list[str]:
        """Generate human-readable actionable guidance for strengthening the password."""
        recs: list[str] = []

        if dictionary_match:
            recs.append("This password matches a known common dictionary word. Choose an unpredictable passphrase.")

        if "common_multiword_phrase" in detected_patterns:
            recs.append("This passphrase consists of recognizable common words. Consider using less predictable or randomized words.")

        if "predictable_year" in detected_patterns:
            recs.append("Avoid appending predictable calendar years (e.g. 2024–2026) to passwords or passphrases.")

        if "seasonal_year_pattern" in detected_patterns:
            recs.append("Avoid combining season or month names with calendar years (e.g., Summer2026).")

        if "word_number_combination" in detected_patterns:
            recs.append("Avoid simple word-plus-number patterns (e.g., Password123 or Tiger99).")

        if "leet_substitution" in detected_patterns:
            recs.append("Avoid predictable character substitutions (e.g. '@' for 'a', '0' for 'o'); modern crackers reverse these easily.")

        if length < self.min_recommended_length:
            recs.append(f"Increase password length to at least {self.min_recommended_length} characters.")

        if not character_categories.get("uppercase"):
            recs.append("Add uppercase letters (A-Z).")

        if not character_categories.get("lowercase"):
            recs.append("Add lowercase letters (a-z).")

        if not character_categories.get("digits"):
            recs.append("Add numeric digits (0-9).")

        if not character_categories.get("symbols"):
            recs.append("Add special characters or punctuation (!@#$%^&*).")

        if "repeated_characters" in detected_patterns:
            recs.append("Avoid repeating the same character multiple times in a row.")

        if "repeated_sequences" in detected_patterns:
            recs.append("Avoid repeating character sequences or syllables.")

        if "sequential_numeric" in detected_patterns:
            recs.append("Avoid sequential number patterns (e.g. 123, 789).")

        if "sequential_alphabetic" in detected_patterns:
            recs.append("Avoid sequential alphabetical patterns (e.g. abc, xyz).")

        if "keyboard_walk" in detected_patterns:
            recs.append("Avoid keyboard walk patterns (e.g. qwerty, asdfgh).")

        if not recs and strength in (PasswordStrength.STRONG, PasswordStrength.VERY_STRONG):
            recs.append("Your password demonstrates strong length, character diversity, and high unpredictability.")

        return recs

    @staticmethod
    def _has_sequential_digits(text: str) -> bool:
        """Check for contiguous sequential numeric runs of 3+ digits (e.g., 123, 987)."""
        digit_runs = re.findall(r"\d{3,}", text)
        for run in digit_runs:
            for i in range(len(run) - 2):
                d0, d1, d2 = int(run[i]), int(run[i + 1]), int(run[i + 2])
                if (d1 == d0 + 1 and d2 == d1 + 1) or (d1 == d0 - 1 and d2 == d1 - 1):
                    return True
        return False

    @staticmethod
    def _has_sequential_letters(text: str) -> bool:
        """Check for contiguous sequential alphabetic runs of 3+ letters (e.g., abc, cba)."""
        letter_runs = re.findall(r"[a-zA-Z]{3,}", text)
        for run in letter_runs:
            lowered = run.lower()
            for i in range(len(lowered) - 2):
                c0, c1, c2 = ord(lowered[i]), ord(lowered[i + 1]), ord(lowered[i + 2])
                if (c1 == c0 + 1 and c2 == c1 + 1) or (c1 == c0 - 1 and c2 == c1 - 1):
                    return True
        return False

    @staticmethod
    def _has_keyboard_walk(clean_lower: str) -> bool:
        """Check for contiguous keyboard patterns of 3+ keys on QWERTY rows."""
        for row in KEYBOARD_ROWS:
            for i in range(len(row) - 2):
                seq_fwd = row[i : i + 3]
                seq_rev = seq_fwd[::-1]
                if seq_fwd in clean_lower or seq_rev in clean_lower:
                    return True
        return False
