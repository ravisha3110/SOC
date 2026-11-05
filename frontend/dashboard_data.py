"""Dashboard Preview Data Provider.

Separates presentation logic from future database persistence (Phase 2+).
All sample data is explicitly tagged as DEMO DATA.
Strict Data Policy: Does NOT claim protection based on unperformed scans,
and explicitly indicates scanning modules are disconnected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class StatItem:
    """Statistic card data model."""

    title: str
    value: str
    change: str
    is_increase: bool
    icon: str
    is_demo: bool = True
    demo_badge: str = "[DEMO DATA]"


@dataclass(frozen=True)
class ActivityRecord:
    """Recent security activity log model."""

    record_id: str
    timestamp: str
    event_type: str
    target: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str
    is_demo: bool = True


@dataclass(frozen=True)
class SeverityCount:
    """Individual severity category count for charts."""

    severity: str
    count: int
    color: str
    percentage: float


@dataclass(frozen=True)
class ThreatSeverityDistribution:
    """Distribution of detected threats across severity tiers."""

    critical: int
    high: int
    medium: int
    low: int
    is_demo: bool = True
    demo_badge: str = "[DEMO DATA]"

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def get_breakdown(self) -> list[SeverityCount]:
        tot = self.total or 1
        return [
            SeverityCount("Critical", self.critical, "#EF4444", round((self.critical / tot) * 100, 1)),
            SeverityCount("High", self.high, "#F59E0B", round((self.high / tot) * 100, 1)),
            SeverityCount("Medium", self.medium, "#A855F7", round((self.medium / tot) * 100, 1)),
            SeverityCount("Low", self.low, "#3B82F6", round((self.low / tot) * 100, 1)),
        ]


@dataclass(frozen=True)
class SystemSecurityStatus:
    """System security operational readiness status."""

    headline: str
    status_level: str  # OFFLINE, DISCONNECTED, PENDING
    is_protected: bool  # Strictly False in Phase 1
    engine_connected: bool  # Strictly False in Phase 1
    summary: str
    notice: str
    is_demo: bool = True


@runtime_checkable
class DashboardDataProvider(Protocol):
    """Interface for dashboard data retrieval (swappable with SQL in Phase 2)."""

    def get_statistics(self) -> list[StatItem]:
        """Fetch high-level overview metrics."""
        ...  # pragma: no cover

    def get_severity_distribution(self) -> ThreatSeverityDistribution:
        """Fetch threat severity distribution counts."""
        ...  # pragma: no cover

    def get_recent_activity(self, limit: int = 5) -> list[ActivityRecord]:
        """Fetch recent security event records."""
        ...  # pragma: no cover

    def get_system_status(self) -> SystemSecurityStatus:
        """Fetch overall system security operational status."""
        ...  # pragma: no cover


class DemoDashboardDataProvider:
    """Preview-data provider for Phase 1 UI validation.

    Provides realistic SOC telemetry mock data, strictly tagged as DEMO DATA.
    Does NOT report active protection or completed scans.
    """

    def get_statistics(self) -> list[StatItem]:
        return [
            StatItem(
                title="Total Security Scans",
                value="1,248",
                change="+12.4%",
                is_increase=True,
                icon="🔍",
                is_demo=True,
            ),
            StatItem(
                title="Threats Detected",
                value="14",
                change="+3 today",
                is_increase=True,
                icon="⚠️",
                is_demo=True,
            ),
            StatItem(
                title="Files Verified",
                value="3,892",
                change="+150 new",
                is_increase=True,
                icon="📁",
                is_demo=True,
            ),
            StatItem(
                title="Network Connections",
                value="57",
                change="-4 active",
                is_increase=False,
                icon="🌐",
                is_demo=True,
            ),
        ]

    def get_severity_distribution(self) -> ThreatSeverityDistribution:
        return ThreatSeverityDistribution(
            critical=2,
            high=5,
            medium=4,
            low=3,
            is_demo=True,
        )

    def get_recent_activity(self, limit: int = 5) -> list[ActivityRecord]:
        sample_activities = [
            ActivityRecord(
                record_id="SEC-901",
                timestamp="16:14:02",
                event_type="Suspicious Outbound TCP",
                target="198.51.100.42:4444",
                severity="CRITICAL",
                status="FLAGGED",
            ),
            ActivityRecord(
                record_id="SEC-902",
                timestamp="15:58:19",
                event_type="SSH Repeated Auth Failure",
                target="192.168.1.105:22",
                severity="HIGH",
                status="BLOCKED",
            ),
            ActivityRecord(
                record_id="SEC-903",
                timestamp="15:32:44",
                event_type="Self-Signed TLS Certificate",
                target="api.internal.local:443",
                severity="MEDIUM",
                status="MONITORED",
            ),
            ActivityRecord(
                record_id="SEC-904",
                timestamp="14:45:10",
                event_type="SHA-256 Checksum Mismatch",
                target="bin/system_helper.dll",
                severity="HIGH",
                status="DETECTED",
            ),
            ActivityRecord(
                record_id="SEC-905",
                timestamp="14:10:05",
                event_type="Insecure HTTP Basic Auth",
                target="10.0.0.12/admin",
                severity="LOW",
                status="NOTIFIED",
            ),
        ]
        return sample_activities[:limit]

    def get_system_status(self) -> SystemSecurityStatus:
        return SystemSecurityStatus(
            headline="SECURITY ENGINES NOT CONNECTED",
            status_level="DISCONNECTED",
            is_protected=False,
            engine_connected=False,
            summary="Real-time security scanner modules and database engines are currently offline.",
            notice=(
                "Phase 1 Preview Mode: Security scanning engines (Port Scanner, Log Auditor, "
                "Crypto Inspector) will be connected during Phase 4. Current data shown is "
                "for interface verification only."
            ),
            is_demo=True,
        )
