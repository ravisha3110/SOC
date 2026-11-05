"""CyberShield Security Package.

Contains syllabus-oriented cybersecurity analysis modules and threat utilities.
"""

from __future__ import annotations

from security.auth import (
    AuthService,
    LoginRateLimiter,
    PasswordHasher,
    Permission,
    Role,
    Session,
    SessionManager,
)
from security.cloud_sync import (
    CloudConnectionStatus,
    CloudSyncEngine,
    SyncConflict,
    SyncDirection,
    SyncSummary,
)
from security.file_integrity import (
    FileIntegrityRecord,
    FileIntegrityScanner,
    IntegrityStatus,
    calculate_sha256,
)
from security.network_monitor import (
    LocalNetworkMonitor,
    NetworkConnectionRecord,
    NetworkSummary,
    SocketProtocol,
)
from security.password_analyzer import (
    PasswordAnalysisResult,
    PasswordAnalyzer,
    PasswordStrength,
)
from security.threat_analytics import (
    SecurityReport,
    ThreatAnalyticsEngine,
    ThreatAnalyticsSummary,
)
from security.url_analyzer import (
    DFAResult,
    RiskIndicator,
    URLAnalysisResult,
    URLAutomaton,
    URLRiskLevel,
    URLSecurityAnalyzer,
)

__all__ = [
    "PasswordAnalyzer",
    "PasswordAnalysisResult",
    "PasswordStrength",
    "FileIntegrityScanner",
    "FileIntegrityRecord",
    "IntegrityStatus",
    "calculate_sha256",
    "URLSecurityAnalyzer",
    "URLAnalysisResult",
    "URLRiskLevel",
    "URLAutomaton",
    "DFAResult",
    "RiskIndicator",
    "LocalNetworkMonitor",
    "NetworkConnectionRecord",
    "NetworkSummary",
    "SocketProtocol",
    "ThreatAnalyticsEngine",
    "ThreatAnalyticsSummary",
    "SecurityReport",
    "Role",
    "Permission",
    "Session",
    "PasswordHasher",
    "LoginRateLimiter",
    "SessionManager",
    "AuthService",
    "CloudConnectionStatus",
    "SyncDirection",
    "SyncConflict",
    "SyncSummary",
    "CloudSyncEngine",
]
