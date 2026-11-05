"""CyberShield Frontend Package.

Contains Tkinter/ttk desktop GUI components, views, styling,
and dashboard widgets for the SOC Threat Analytics platform.
"""

from frontend.auth_view import AuthView
from frontend.cloud_sync_view import CloudSyncView
from frontend.dashboard import CyberShieldApp
from frontend.dashboard_data import (
    ActivityRecord,
    DashboardDataProvider,
    DemoDashboardDataProvider,
    StatItem,
    SystemSecurityStatus,
    ThreatSeverityDistribution,
)
from frontend.file_integrity_view import FileIntegrityView
from frontend.network_view import NetworkActivityView
from frontend.password_view import PasswordSecurityView
from frontend.reports_view import ReportsView
from frontend.sidebar import Sidebar
from frontend.theme import apply_theme
from frontend.threat_analytics_view import ThreatAnalyticsView
from frontend.topbar import TopBar
from frontend.url_view import URLSecurityView
from frontend.user_management_view import UserManagementView

__all__ = [
    "AuthView",
    "CloudSyncView",
    "CyberShieldApp",
    "DashboardDataProvider",
    "DemoDashboardDataProvider",
    "FileIntegrityView",
    "NetworkActivityView",
    "PasswordSecurityView",
    "ReportsView",
    "Sidebar",
    "StatItem",
    "ActivityRecord",
    "ThreatSeverityDistribution",
    "SystemSecurityStatus",
    "ThreatAnalyticsView",
    "TopBar",
    "URLSecurityView",
    "UserManagementView",
    "apply_theme",
]
