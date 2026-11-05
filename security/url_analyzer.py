"""URL Security Analyzer & Deterministic Finite Automaton (DFA) Engine.

Provides heuristic risk assessment, phishing indicator detection, and formal
syntactic validation using a Deterministic Finite Automaton (DFA) for web URLs.

Key Academic Principles:
- Syntactic Validation vs. Heuristic Threat Analysis:
  * DFA Automaton validates formal URL language grammar according to RFC 3986.
  * Heuristic rules assess risk factors (e.g. suspicious TLDs, IP hosts, brand spoofing).
- Explainable Automaton:
  * Traces state transitions step-by-step for classroom instruction and viva defense.
- Transparent Heuristic Scoring:
  * Normalized score between 0 and 100 with documented weights and actionable advice.
- Strict Network Safety:
  * Zero network sockets, zero DNS queries, and zero HTTP requests; strictly static evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import re
from typing import Any, Protocol
import urllib.parse


class URLRiskLevel(str, Enum):
    """Categorical risk classifications for inspected URLs."""

    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DFATransition:
    """Represents a single state transition in the URL Automaton."""

    from_state: str
    char: str
    to_state: str


@dataclass
class DFAResult:
    """Outcome of running the Deterministic Finite Automaton on a candidate URL.

    Attributes:
        is_accepted: True if the automaton ended in a valid terminal state.
        final_state: The terminal state name.
        transitions_count: Total number of character transitions performed.
        state_sequence: Ordered list of state names visited during traversal.
        explanation: Academic explanation of the automaton outcome.
    """

    is_accepted: bool
    final_state: str
    transitions_count: int
    state_sequence: list[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize DFA result to a dictionary."""
        return {
            "is_accepted": self.is_accepted,
            "final_state": self.final_state,
            "transitions_count": self.transitions_count,
            "state_sequence": self.state_sequence,
            "explanation": self.explanation,
        }


@dataclass
class RiskIndicator:
    """A detected heuristic vulnerability or risk pattern in a URL."""

    name: str
    points: int
    severity: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize indicator to a dictionary."""
        return {
            "name": self.name,
            "points": self.points,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class URLAnalysisResult:
    """Complete evaluation report produced by the URL Security Analyzer.

    Attributes:
        url: Original target URL string.
        risk_score: Normalized composite threat score from 0.0 to 100.0.
        risk_level: Categorical classification (LOW, MODERATE, HIGH, CRITICAL).
        dfa_result: Syntactic validation result from the URL Automaton.
        indicators: List of specific detected risk heuristics.
        reasons: Plain-English explanations justifying the score.
        recommendations: Actionable security recommendations for the analyst.
        timestamp: ISO-8601 UTC timestamp of the analysis.
        disclaimer: Standard heuristic analysis limitation disclosure.
    """

    url: str
    risk_score: float
    risk_level: URLRiskLevel
    dfa_result: DFAResult
    indicators: list[RiskIndicator] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    disclaimer: str = (
        "Heuristic evaluation only. This rating is based on structural and syntactic indicators "
        "and does not constitute a definitive maliciousness verdict or guarantee of safety."
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize analysis result to dictionary for database persistence or UI display."""
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "dfa_result": self.dfa_result.to_dict(),
            "indicators": [ind.to_dict() for ind in self.indicators],
            "reasons": self.reasons,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp,
            "disclaimer": self.disclaimer,
        }


class URLRepositoryProtocol(Protocol):
    """Protocol defining the repository operations required for URL analysis persistence."""

    def create(
        self,
        url: str,
        risk_score: float,
        risk_level: str,
        analysis_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]: ...


class URLAutomaton:
    """Deterministic Finite Automaton (DFA) for URL Structural Validation.

    Formal Language Definition:
    - Alphabet: ASCII characters (alphanumeric, punctuation, standard URL symbols).
    - States:
      * Q0 (START): Initial state before consuming input.
      * Q1 (SCHEME): Reading protocol scheme letters (e.g. 'http', 'https').
      * Q2 (COLON): Matched ':' after scheme.
      * Q3 (SLASH1): Matched first '/' of authority delimiter.
      * Q4 (SLASH2): Matched second '/' of authority delimiter.
      * Q5 (HOST): Reading hostname, domain labels, or IPv4 characters.
      * Q6 (PORT_COLON): Matched ':' after host specifying port.
      * Q7 (PORT): Reading numeric port digits.
      * Q8 (PATH): Reading resource path beginning with '/'.
      * Q9 (QUERY_MARK): Matched '?' beginning query parameters.
      * Q10 (QUERY): Reading query key-value pairs.
      * Q11 (FRAGMENT_HASH): Matched '#' beginning fragment identifier.
      * Q12 (FRAGMENT): Reading fragment string.
      * Q_REJECT (REJECT): Dead/trap state for invalid transitions.
    - Accept States: {HOST, PORT, PATH, QUERY, FRAGMENT}
    """

    STATE_START = "START"
    STATE_SCHEME = "SCHEME"
    STATE_COLON = "COLON"
    STATE_SLASH1 = "SLASH1"
    STATE_SLASH2 = "SLASH2"
    STATE_HOST = "HOST"
    STATE_PORT_COLON = "PORT_COLON"
    STATE_PORT = "PORT"
    STATE_PATH = "PATH"
    STATE_QUERY_MARK = "QUERY_MARK"
    STATE_QUERY = "QUERY"
    STATE_FRAGMENT_HASH = "FRAGMENT_HASH"
    STATE_FRAGMENT = "FRAGMENT"
    STATE_REJECT = "REJECT"

    ACCEPTING_STATES = {
        STATE_HOST,
        STATE_PORT,
        STATE_PATH,
        STATE_QUERY,
        STATE_FRAGMENT,
    }

    def process(self, url: str) -> DFAResult:
        """Run the DFA across the input URL character by character.

        Args:
            url: The candidate URL string to validate.

        Returns:
            DFAResult: Step-by-step transition outcome and accept/reject decision.
        """
        if not url or not isinstance(url, str):
            return DFAResult(
                is_accepted=False,
                final_state=self.STATE_REJECT,
                transitions_count=0,
                state_sequence=[self.STATE_START, self.STATE_REJECT],
                explanation="Input is empty or not a valid string.",
            )

        trimmed = url.strip()
        current_state = self.STATE_START
        state_sequence = [current_state]

        for idx, char in enumerate(trimmed):
            next_state = self._transition(current_state, char, idx)
            current_state = next_state
            state_sequence.append(current_state)
            if current_state == self.STATE_REJECT:
                break

        is_accepted = current_state in self.ACCEPTING_STATES
        if is_accepted:
            explanation = (
                f"URL structure successfully validated by DFA. Terminated in accepting "
                f"state '{current_state}' after {len(trimmed)} transitions."
            )
        else:
            explanation = (
                f"URL syntax rejected by DFA. Stopped in non-accepting state "
                f"'{current_state}'."
            )

        return DFAResult(
            is_accepted=is_accepted,
            final_state=current_state,
            transitions_count=len(state_sequence) - 1,
            state_sequence=state_sequence,
            explanation=explanation,
        )

    def _transition(self, state: str, ch: str, index: int) -> str:
        """Compute the deterministic transition for (state, char)."""
        lower_ch = ch.lower()

        if state == self.STATE_START:
            if lower_ch.isalpha():
                return self.STATE_SCHEME
            return self.STATE_REJECT

        elif state == self.STATE_SCHEME:
            if lower_ch.isalnum() or lower_ch in ("+", "-", "."):
                return self.STATE_SCHEME
            elif lower_ch == ":":
                return self.STATE_COLON
            return self.STATE_REJECT

        elif state == self.STATE_COLON:
            if lower_ch == "/":
                return self.STATE_SLASH1
            return self.STATE_REJECT

        elif state == self.STATE_SLASH1:
            if lower_ch == "/":
                return self.STATE_SLASH2
            return self.STATE_REJECT

        elif state == self.STATE_SLASH2:
            if lower_ch.isalnum() or lower_ch in ("-", "_", "["):
                return self.STATE_HOST
            return self.STATE_REJECT

        elif state == self.STATE_HOST:
            if lower_ch.isalnum() or lower_ch in ("-", "_", ".", "%", "@", "[", "]"):
                return self.STATE_HOST
            elif lower_ch == ":":
                return self.STATE_PORT_COLON
            elif lower_ch == "/":
                return self.STATE_PATH
            elif lower_ch == "?":
                return self.STATE_QUERY_MARK
            elif lower_ch == "#":
                return self.STATE_FRAGMENT_HASH
            return self.STATE_REJECT

        elif state == self.STATE_PORT_COLON:
            if lower_ch.isdigit():
                return self.STATE_PORT
            return self.STATE_REJECT

        elif state == self.STATE_PORT:
            if lower_ch.isdigit():
                return self.STATE_PORT
            elif lower_ch == "/":
                return self.STATE_PATH
            elif lower_ch == "?":
                return self.STATE_QUERY_MARK
            elif lower_ch == "#":
                return self.STATE_FRAGMENT_HASH
            return self.STATE_REJECT

        elif state == self.STATE_PATH:
            if lower_ch == "?":
                return self.STATE_QUERY_MARK
            elif lower_ch == "#":
                return self.STATE_FRAGMENT_HASH
            elif lower_ch.isascii() and not lower_ch.isspace():
                return self.STATE_PATH
            return self.STATE_REJECT

        elif state == self.STATE_QUERY_MARK or state == self.STATE_QUERY:
            if lower_ch == "#":
                return self.STATE_FRAGMENT_HASH
            elif lower_ch.isascii() and not lower_ch.isspace():
                return self.STATE_QUERY
            return self.STATE_REJECT

        elif state == self.STATE_FRAGMENT_HASH or state == self.STATE_FRAGMENT:
            if lower_ch.isascii() and not lower_ch.isspace():
                return self.STATE_FRAGMENT
            return self.STATE_REJECT

        return self.STATE_REJECT


class URLSecurityAnalyzer:
    """Heuristic URL Security Analyzer for phishing and risk scoring.

    Evaluates structural, syntactic, and semantic patterns against known attack
    techniques without performing live network lookups.
    """

    # Commonly abused or high-risk top-level domains in malicious campaigns
    SUSPICIOUS_TLDS = {
        "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work",
        "click", "loan", "buzz", "surf", "link", "live", "country", "stream",
        "gdn", "icu", "cam", "fit", "rest", "party",
    }

    # Brand names commonly targeted by phishing and typosquatting attacks
    TARGET_BRANDS = {
        "paypal", "google", "apple", "microsoft", "amazon", "netflix",
        "chase", "bankofamerica", "wellsfargo", "facebook", "instagram",
        "whatsapp", "dropbox", "binance", "coinbase", "support", "adobe",
    }

    # High-risk keywords commonly found in fraudulent subdomains or paths
    RISKY_KEYWORDS = {
        "login", "signin", "verify", "verification", "secure", "account",
        "banking", "update", "security", "password", "credential", "wallet",
        "admin", "confirm", "confirmation", "recover", "authenticate",
    }

    def __init__(self, repository: URLRepositoryProtocol | None = None) -> None:
        """Initialize the analyzer with an optional database repository."""
        self.repository = repository
        self.automaton = URLAutomaton()

    def analyze(self, raw_url: str) -> URLAnalysisResult:
        """Analyze a URL for security risks, phishing indicators, and syntactic validity.

        Args:
            raw_url: Candidate URL string.

        Returns:
            URLAnalysisResult: Detailed security report.
        """
        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            dfa_empty = self.automaton.process("")
            return URLAnalysisResult(
                url="",
                risk_score=0.0,
                risk_level=URLRiskLevel.LOW,
                dfa_result=dfa_empty,
                indicators=[
                    RiskIndicator(
                        name="Empty Input",
                        points=0,
                        severity="INFO",
                        description="No URL provided for analysis.",
                    )
                ],
                reasons=["Empty input provided; no analysis performed."],
                recommendations=["Enter a valid web URL (e.g. https://example.com) to inspect."],
            )

        target_url = raw_url.strip()

        # Step 1: Run DFA Syntactic Validation
        dfa_res = self.automaton.process(target_url)

        # Step 2: Parse URL components with standard library
        parsed = urllib.parse.urlparse(target_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        indicators: list[RiskIndicator] = []
        reasons: list[str] = []
        recommendations: list[str] = []
        accumulated_score = 0.0

        # Heuristic 1: Syntactic DFA Rejection
        if not dfa_res.is_accepted:
            points = 25
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name="Syntactic Automaton Rejection",
                    points=points,
                    severity="HIGH",
                    description="URL violates formal RFC 3986 grammar syntax.",
                )
            )
            reasons.append("URL syntax failed deterministic finite automaton (DFA) grammar validation.")
            recommendations.append("Verify the URL conforms to standard format (e.g., https://domain.tld/path).")

        # Heuristic 2: Insecure Transport Protocol (HTTP vs HTTPS)
        if scheme == "http":
            points = 15
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name="Insecure Transport Protocol (Plaintext HTTP)",
                    points=points,
                    severity="MEDIUM",
                    description="Connection lacks TLS/SSL encryption, exposing traffic to interception.",
                )
            )
            reasons.append("Transmits unencrypted plaintext HTTP traffic instead of HTTPS.")
            recommendations.append("Enforce HTTPS encryption with valid TLS certificates for data in transit.")
        elif scheme not in ("http", "https") and scheme != "":
            points = 20
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name=f"Non-Standard Protocol Scheme ({scheme.upper()})",
                    points=points,
                    severity="MEDIUM",
                    description="Unusual protocol scheme detected in web address context.",
                )
            )
            reasons.append(f"Uses an unusual scheme '{scheme}:' which may trigger local protocol handlers.")

        # Extract host without port
        host = netloc.split(":")[0] if ":" in netloc else netloc

        # Heuristic 3: Embedded '@' Symbol in Authority (Credential / Host Spoofing)
        if "@" in netloc or "@" in target_url.split("?")[0].split("#")[0]:
            points = 35
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name="Deceptive '@' Authority Spoofing",
                    points=points,
                    severity="CRITICAL",
                    description="Embedded '@' character masks the true destination host from the user.",
                )
            )
            reasons.append("Contains '@' symbol in the authority block, which tricks users into misidentifying the destination host.")
            recommendations.append("Do not navigate to URLs containing '@' symbols in host addresses.")

        # Heuristic 4: Direct IP Address as Host
        clean_host = host.split("@")[-1]  # Get destination host after '@' if present
        is_ip = False
        try:
            ipaddress.ip_address(clean_host)
            is_ip = True
        except ValueError:
            # Check for dotted IPv4 regex or hex IP
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_host):
                is_ip = True

        if is_ip:
            points = 30
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name="Numeric IP Address Host",
                    points=points,
                    severity="HIGH",
                    description="Host is a raw numerical IP address bypassing domain registration.",
                )
            )
            reasons.append(f"Direct IP address '{clean_host}' is used instead of a registered domain name.")
            recommendations.append("Legitimate services rarely use bare IP addresses; verify server ownership before connecting.")

        # Heuristic 5: Suspicious Top-Level Domain (TLD)
        if "." in clean_host and not is_ip:
            parts = clean_host.split(".")
            tld = parts[-1]
            if tld in self.SUSPICIOUS_TLDS:
                points = 25
                accumulated_score += points
                indicators.append(
                    RiskIndicator(
                        name=f"Suspicious Top-Level Domain (.{tld})",
                        points=points,
                        severity="HIGH",
                        description=f"The '.{tld}' TLD exhibits high statistical correlation with malicious phishing campaigns.",
                    )
                )
                reasons.append(f"Domain uses high-risk TLD '.{tld}', commonly utilized in temporary disposable campaigns.")
                recommendations.append("Exercise extreme caution with free, unvetted, or high-abuse top-level domains.")

            # Heuristic 6: Excessive Subdomain Depth (>= 3 subdomains)
            # Example: a.b.c.d.example.com has parts count > 4
            subdomains = parts[:-2] if len(parts) >= 2 else []
            if len(subdomains) >= 3:
                points = 15
                accumulated_score += points
                indicators.append(
                    RiskIndicator(
                        name=f"Excessive Subdomain Depth ({len(subdomains)} levels)",
                        points=points,
                        severity="MEDIUM",
                        description="Unusually deep subdomain hierarchy used to camouflage true domain ownership.",
                    )
                )
                reasons.append(f"Contains {len(subdomains)} subdomain levels ('{'.'.join(subdomains)}'), indicating potential obfuscation.")
                recommendations.append("Inspect the root registered domain rather than misleading prefix labels.")

            # Heuristic 7: Brand Impersonation / Misleading Hostname Structure
            # Example: paypal.com.attacker.com or apple-verify.com
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else clean_host
            subdomain_str = ".".join(subdomains)
            for brand in self.TARGET_BRANDS:
                # Brand in subdomain but not in root domain
                if brand in subdomain_str and brand not in root_domain:
                    points = 30
                    accumulated_score += points
                    indicators.append(
                        RiskIndicator(
                            name=f"Brand Spoofing in Subdomain ('{brand}')",
                            points=points,
                            severity="CRITICAL",
                            description=f"Target brand '{brand}' appears in subdomains of an unrelated root domain '{root_domain}'.",
                        )
                    )
                    reasons.append(f"Impersonates reputable brand '{brand}' inside subdomains while pointing to root '{root_domain}'.")
                    recommendations.append(f"Verify you are visiting the authentic root domain for {brand.capitalize()}.")
                    break
                # Brand in root domain with hyphens: e.g. paypal-security.com
                elif brand in root_domain and root_domain != f"{brand}.com" and "-" in root_domain:
                    points = 20
                    accumulated_score += points
                    indicators.append(
                        RiskIndicator(
                            name=f"Hyphenated Brand Typosquatting ('{brand}')",
                            points=points,
                            severity="HIGH",
                            description=f"Brand name '{brand}' combined with hyphens in root domain '{root_domain}'.",
                        )
                    )
                    reasons.append(f"Suspicious hyphenated brand combination '{root_domain}' detected.")
                    recommendations.append("Check domain registration age and SSL certificate owner.")
                    break

        # Heuristic 8: Sensitive Keywords in Subdomain or Path
        full_path_query = f"{path}?{query}"
        detected_keywords: list[str] = []
        for kw in self.RISKY_KEYWORDS:
            if kw in clean_host or kw in full_path_query:
                detected_keywords.append(kw)

        if len(detected_keywords) >= 2 or (len(detected_keywords) >= 1 and (scheme == "http" or is_ip)):
            points = 20
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name=f"Sensitive Credential Keywords ({', '.join(detected_keywords[:3])})",
                    points=points,
                    severity="HIGH",
                    description="Authentication, banking, or credential keywords detected in high-risk context.",
                )
            )
            reasons.append(f"Contains sensitive credential/authentication keywords: {', '.join(detected_keywords)}.")
            recommendations.append("Never submit passwords or MFA codes to unverified or insecure URLs.")

        # Heuristic 9: Excessive Hyphens in Hostname (>= 3)
        hyphen_count = clean_host.count("-")
        if hyphen_count >= 3:
            points = 15
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name=f"Excessive Hyphenation in Host ({hyphen_count} hyphens)",
                    points=points,
                    severity="MEDIUM",
                    description="Multiple hyphenated tokens frequently indicate automated phishing domain generation.",
                )
            )
            reasons.append(f"Hostname contains {hyphen_count} hyphens, suggesting machine-generated phishing domains.")

        # Heuristic 10: Suspicious URL Length (> 75 chars elevated, > 100 chars high)
        url_len = len(target_url)
        if url_len > 100:
            points = 15
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name=f"High URL Length ({url_len} characters)",
                    points=points,
                    severity="MEDIUM",
                    description="Excessively long URL often used to obscure malicious parameters or push host off-screen.",
                )
            )
            reasons.append(f"URL length ({url_len} characters) is unusually long.")
        elif url_len > 75:
            points = 10
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name=f"Elevated URL Length ({url_len} characters)",
                    points=points,
                    severity="LOW",
                    description="URL is longer than standard navigation links.",
                )
            )

        # Heuristic 11: Obfuscation & URL Encoding (%xx or multiple slashes)
        if "%" in clean_host or "%2e" in target_url.lower() or "%2f" in target_url.lower() or "//" in path:
            points = 15
            accumulated_score += points
            indicators.append(
                RiskIndicator(
                    name="Obfuscated Character Encoding / Multiple Slashes",
                    points=points,
                    severity="MEDIUM",
                    description="Hex encoding (%xx) or duplicate slashes (//) used to evade basic string filters.",
                )
            )
            reasons.append("Detected percent-encoded hex sequences or path traversal attempts.")
            recommendations.append("Decode all encoded characters before evaluating destination authenticity.")

        # Normalize total risk score (0.0 to 100.0)
        final_score = min(100.0, max(0.0, round(accumulated_score, 1)))

        # Categorize into Risk Levels
        if final_score <= 25.0:
            risk_level = URLRiskLevel.LOW
            if not indicators:
                reasons.append("Standard URL structure with HTTPS and no suspicious heuristics triggered.")
                recommendations.append("No immediate structural threats detected. Standard browsing precautions apply.")
        elif final_score <= 50.0:
            risk_level = URLRiskLevel.MODERATE
        elif final_score <= 75.0:
            risk_level = URLRiskLevel.HIGH
        else:
            risk_level = URLRiskLevel.CRITICAL

        # If no indicators triggered at all, add Clean baseline indicator
        if not indicators:
            indicators.append(
                RiskIndicator(
                    name="Clean Heuristic Baseline",
                    points=0,
                    severity="LOW",
                    description="No suspicious syntax, abnormal TLDs, or deceptive patterns detected.",
                )
            )

        result = URLAnalysisResult(
            url=target_url,
            risk_score=final_score,
            risk_level=risk_level,
            dfa_result=dfa_res,
            indicators=indicators,
            reasons=reasons,
            recommendations=recommendations,
        )

        # Persist to database repository if available
        if self.repository is not None:
            self.repository.create(
                url=result.url,
                risk_score=result.risk_score,
                risk_level=result.risk_level.value,
            )

        return result

