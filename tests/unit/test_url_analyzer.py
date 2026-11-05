"""Unit tests for URL Security Analyzer and DFA Engine."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from security.url_analyzer import (
    DFAResult,
    RiskIndicator,
    URLAnalysisResult,
    URLAutomaton,
    URLRiskLevel,
    URLSecurityAnalyzer,
)


# =============================================================================
# 1. DFA Automaton Tests
# =============================================================================

def test_dfa_valid_https_url() -> None:
    """Verify DFA accepts standard valid HTTPS URL."""
    dfa = URLAutomaton()
    result = dfa.process("https://example.com/index.html")

    assert result.is_accepted is True
    assert result.final_state == URLAutomaton.STATE_PATH
    assert result.transitions_count > 0
    assert "successfully validated" in result.explanation


def test_dfa_valid_url_with_port_query_fragment() -> None:
    """Verify DFA accepts complex URL with port, query, and fragment."""
    dfa = URLAutomaton()
    result = dfa.process("http://localhost:8080/api/v1?search=test#section2")

    assert result.is_accepted is True
    assert result.final_state == URLAutomaton.STATE_FRAGMENT
    assert result.transitions_count > 0


def test_dfa_rejects_empty_and_non_string() -> None:
    """Verify DFA rejects empty string and non-string inputs safely."""
    dfa = URLAutomaton()
    res1 = dfa.process("")
    assert res1.is_accepted is False
    assert res1.final_state == URLAutomaton.STATE_REJECT

    res2 = dfa.process(None)  # type: ignore[arg-type]
    assert res2.is_accepted is False
    assert res2.final_state == URLAutomaton.STATE_REJECT


def test_dfa_rejects_malformed_url() -> None:
    """Verify DFA transitions to REJECT for missing scheme or invalid syntax."""
    dfa = URLAutomaton()
    res = dfa.process("://missing-scheme.com")
    assert res.is_accepted is False
    assert res.final_state == URLAutomaton.STATE_REJECT
    assert "rejected" in res.explanation


def test_dfa_rejects_colon_without_double_slash() -> None:
    """Verify DFA rejects scheme followed by colon but no valid slashes."""
    dfa = URLAutomaton()
    res = dfa.process("http:invalid-format")
    assert res.is_accepted is False
    assert res.final_state == URLAutomaton.STATE_REJECT


def test_dfa_edge_state_transitions() -> None:
    """Verify detailed transitions across all intermediate DFA states."""
    dfa = URLAutomaton()

    # Unknown state fallback
    assert dfa._transition("UNKNOWN_STATE", "a", 0) == URLAutomaton.STATE_REJECT

    # Question mark directly after host
    assert dfa.process("https://example.com?query=1").is_accepted is True

    # Hash directly after host
    assert dfa.process("https://example.com#heading").is_accepted is True

    # Question mark and hash directly after port
    assert dfa.process("https://example.com:8080?q=1").is_accepted is True
    assert dfa.process("https://example.com:8080#section").is_accepted is True

    # Hash after path
    assert dfa.process("https://example.com/path#tag").is_accepted is True

    # Hash after query
    assert dfa.process("https://example.com/path?q=1#tag").is_accepted is True

    # Space or invalid chars in various states trigger REJECT
    assert dfa.process("http*//invalid-scheme").is_accepted is False
    assert dfa.process("http:/incomplete").is_accepted is False
    assert dfa.process("http: //space").is_accepted is False
    assert dfa.process("http:// invalid").is_accepted is False
    assert dfa.process("http://exam!ple.com").is_accepted is False
    assert dfa.process("http://example.com:abc").is_accepted is False
    assert dfa.process("http://example.com:8080x").is_accepted is False
    assert dfa.process("http://example.com/path with space").is_accepted is False
    assert dfa.process("http://example.com?q=with space").is_accepted is False
    assert dfa.process("http://example.com#tag with space").is_accepted is False
    assert dfa.process("http://example.com#\n").is_accepted is False


def test_dfa_serialization() -> None:
    """Verify to_dict serialization of DFAResult."""
    dfa = URLAutomaton()
    res = dfa.process("https://cybershield.org")
    d = res.to_dict()
    assert d["is_accepted"] is True
    assert d["final_state"] == URLAutomaton.STATE_HOST
    assert isinstance(d["state_sequence"], list)


# =============================================================================
# 2. Heuristic URL Security Analyzer Tests
# =============================================================================

def test_analyzer_empty_input() -> None:
    """Verify analyzer gracefully handles empty or whitespace input."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("   ")
    assert res.risk_score == 0.0
    assert res.risk_level == URLRiskLevel.LOW
    assert len(res.indicators) == 1
    assert res.indicators[0].name == "Empty Input"


def test_analyzer_clean_https_url() -> None:
    """Verify standard legitimate HTTPS URL receives LOW risk score."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://www.google.com")

    assert res.risk_score <= 25.0
    assert res.risk_level == URLRiskLevel.LOW
    assert any(ind.name == "Clean Heuristic Baseline" for ind in res.indicators)
    assert "Heuristic evaluation only" in res.disclaimer


def test_analyzer_insecure_http_protocol() -> None:
    """Verify plaintext HTTP triggers insecure transport penalty."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("http://example.org/about")

    assert res.risk_score >= 15.0
    assert any("Insecure Transport Protocol" in ind.name for ind in res.indicators)


def test_analyzer_numeric_ip_address() -> None:
    """Verify direct IP address host triggers high severity penalty."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("http://192.168.1.100/admin")

    assert res.risk_score >= 45.0  # HTTP (15) + IP (30)
    assert any("Numeric IP Address Host" in ind.name for ind in res.indicators)


def test_analyzer_suspicious_tld() -> None:
    """Verify commonly abused TLDs (e.g., .xyz, .zip, .tk) trigger penalty."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://account-update.xyz/login")

    assert any(".xyz" in ind.name for ind in res.indicators)
    assert res.risk_score >= 25.0


def test_analyzer_brand_spoofing_in_subdomain() -> None:
    """Verify impersonating a brand in subdomains is flagged with high severity."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://paypal.com.account-verification.attacker-host.cc/login")

    assert any("Brand Spoofing in Subdomain ('paypal')" in ind.name for ind in res.indicators)
    assert res.risk_level in (URLRiskLevel.HIGH, URLRiskLevel.CRITICAL)


def test_analyzer_brand_hyphenation_typosquatting() -> None:
    """Verify hyphenated brand domains are flagged."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://apple-security-check.com/signin")

    assert any("Hyphenated Brand Typosquatting ('apple')" in ind.name for ind in res.indicators)


def test_analyzer_deceptive_at_symbol_authority() -> None:
    """Verify '@' character in URL triggers critical risk alert."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://google.com@phishing-target.com/login")

    assert any("Deceptive '@' Authority Spoofing" in ind.name for ind in res.indicators)
    assert res.risk_score >= 35.0


def test_analyzer_excessive_subdomains() -> None:
    """Verify 3+ levels of subdomains are detected."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://a.b.c.d.suspiciousdomain.com/index")

    assert any("Excessive Subdomain Depth" in ind.name for ind in res.indicators)


def test_analyzer_sensitive_keywords_in_http() -> None:
    """Verify authentication keywords in HTTP or IP context are flagged."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("http://secure-portal.com/banking/login/verify")

    assert any("Sensitive Credential Keywords" in ind.name for ind in res.indicators)


def test_analyzer_excessive_hyphenation() -> None:
    """Verify multiple hyphens in hostname are flagged."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://my-secure-banking-account-login.com")

    assert any("Excessive Hyphenation" in ind.name for ind in res.indicators)


def test_analyzer_long_url() -> None:
    """Verify URLs longer than 75 and 100 characters receive length penalties."""
    analyzer = URLSecurityAnalyzer()
    long_url = "https://example.com/" + "a" * 80
    res_80 = analyzer.analyze(long_url)
    assert any("Elevated URL Length" in ind.name for ind in res_80.indicators)

    very_long_url = "https://example.com/" + "b" * 120
    res_120 = analyzer.analyze(very_long_url)
    assert any("High URL Length" in ind.name for ind in res_120.indicators)


def test_analyzer_obfuscation_and_encoding() -> None:
    """Verify hex %xx encoding or duplicate slashes are detected."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://example.com//portal/%2e%2e/admin")

    assert any("Obfuscated Character Encoding" in ind.name for ind in res.indicators)


def test_analyzer_repository_persistence() -> None:
    """Verify analyzer creates a repository record when repository is provided."""
    mock_repo = MagicMock()
    analyzer = URLSecurityAnalyzer(repository=mock_repo)

    res = analyzer.analyze("https://suspicious-site.tk/login")
    mock_repo.create.assert_called_once_with(
        url="https://suspicious-site.tk/login",
        risk_score=res.risk_score,
        risk_level=res.risk_level.value,
    )


def test_url_analysis_result_serialization() -> None:
    """Verify to_dict serialization of URLAnalysisResult."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("https://google.com")
    d = res.to_dict()

    assert d["url"] == "https://google.com"
    assert d["risk_level"] == "LOW"
    assert "dfa_result" in d
    assert isinstance(d["indicators"], list)
    assert isinstance(d["reasons"], list)
    assert isinstance(d["recommendations"], list)


def test_analyzer_non_standard_scheme_and_syntax_error() -> None:
    """Verify analyzer evaluates non-standard protocol schemes and DFA rejections."""
    analyzer = URLSecurityAnalyzer()

    # Non-standard FTP scheme
    res_ftp = analyzer.analyze("ftp://files.example.org/archive")
    assert any("Non-Standard Protocol Scheme" in ind.name for ind in res_ftp.indicators)

    # Malformed syntax rejected by DFA
    res_bad = analyzer.analyze("https:// invalid url syntax.com")
    assert any("Syntactic Automaton Rejection" in ind.name for ind in res_bad.indicators)


def test_analyzer_critical_risk_level() -> None:
    """Verify multiple critical violations produce a CRITICAL risk level."""
    analyzer = URLSecurityAnalyzer()
    critical_url = "http://192.168.1.1@my-fake-paypal-verify-login.xyz/banking/update//account"
    res = analyzer.analyze(critical_url)

    assert res.risk_level == URLRiskLevel.CRITICAL
    assert res.risk_score >= 76.0


def test_analyzer_regex_ip_fallback() -> None:
    """Verify dotted octet regex fallback triggers IP indicator for out-of-range IP."""
    analyzer = URLSecurityAnalyzer()
    res = analyzer.analyze("http://999.999.999.999/test")
    assert any("Numeric IP Address Host" in ind.name for ind in res.indicators)


