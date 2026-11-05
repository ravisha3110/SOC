"""Integration tests for CyberShieldApp dashboard shell and view navigation."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock, patch
import pytest

from config.settings import AppConfig
from frontend.components import PlaceholderView, RecentActivityTable, StatCard
from frontend.dashboard import CyberShieldApp
from frontend.dashboard_data import DemoDashboardDataProvider
from frontend.password_view import PasswordSecurityView


@pytest.fixture
def test_app(tk_root):
    """Create a headless CyberShieldApp instance with isolated test window."""
    config = AppConfig(
        app_name="CyberShield Test",
        app_version="0.1.0",
        environment="testing",
        debug=True,
        theme="dark",
        sqlite_db_path=":memory:",
        neon_database_url="",
        api_host="127.0.0.1",
        api_port=8000,
    )
    provider = DemoDashboardDataProvider()
    app = CyberShieldApp(config=config, data_provider=provider, root=tk_root)

    yield app

    try:
        app.on_close()
    except Exception:
        pass


def test_app_initialization(test_app: CyberShieldApp) -> None:
    """Verify application initializes layout, sidebar, topbar, and dashboard."""
    assert test_app.root is not None
    assert test_app._active_module_id == "dashboard"
    assert test_app.sidebar is not None
    assert test_app.topbar is not None
    assert test_app.viewport is not None
    assert test_app.feedback_lbl is not None


def test_navigation_to_password_security_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to password_security renders the active PasswordSecurityView."""
    test_app.navigate_to("password_security")
    assert test_app._active_module_id == "password_security"
    assert isinstance(test_app._current_view_frame, PasswordSecurityView)
    assert "Password Security Analyzer" in test_app.topbar.title_lbl["text"]
    assert "Password Security Analyzer" in test_app.feedback_lbl["text"]

    # Verify return to dashboard
    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"
    assert not isinstance(test_app._current_view_frame, PasswordSecurityView)


def test_navigation_to_file_integrity_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to file_integrity renders FileIntegrityView."""
    from frontend.file_integrity_view import FileIntegrityView

    test_app.navigate_to("file_integrity")
    assert test_app._active_module_id == "file_integrity"
    assert isinstance(test_app._current_view_frame, FileIntegrityView)
    assert "File Integrity Scanner" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_url_security_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to url_security renders URLSecurityView."""
    from frontend.url_view import URLSecurityView

    test_app.navigate_to("url_security")
    assert test_app._active_module_id == "url_security"
    assert isinstance(test_app._current_view_frame, URLSecurityView)
    assert "URL Security Analyzer" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_network_monitor_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to network_monitor renders NetworkActivityView."""
    from frontend.network_view import NetworkActivityView

    test_app.navigate_to("network_monitor")
    assert test_app._active_module_id == "network_monitor"
    assert isinstance(test_app._current_view_frame, NetworkActivityView)
    assert "Network Activity Monitor" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_threat_analytics_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to threat_analytics renders ThreatAnalyticsView."""
    from frontend.threat_analytics_view import ThreatAnalyticsView

    test_app.navigate_to("threat_analytics")
    assert test_app._active_module_id == "threat_analytics"
    assert isinstance(test_app._current_view_frame, ThreatAnalyticsView)
    assert "Threat Analytics" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_reports_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to reports renders ReportsView."""
    from frontend.reports_view import ReportsView

    test_app.navigate_to("reports")
    assert test_app._active_module_id == "reports"
    assert isinstance(test_app._current_view_frame, ReportsView)
    assert "Security Incident & Executive Reports" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_settings_cloud_sync_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to settings renders CloudSyncView."""
    from frontend.cloud_sync_view import CloudSyncView

    test_app.navigate_to("settings")
    assert test_app._active_module_id == "settings"
    assert isinstance(test_app._current_view_frame, CloudSyncView)
    assert "Hybrid Cloud Synchronization" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_user_management_module(test_app: CyberShieldApp) -> None:
    """Verify navigation to user_management renders UserManagementView."""
    from frontend.user_management_view import UserManagementView

    test_app.navigate_to("user_management")
    assert test_app._active_module_id == "user_management"
    assert isinstance(test_app._current_view_frame, UserManagementView)
    assert "User & Access Control Management" in test_app.topbar.title_lbl["text"]

    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_auth_and_logout_flow(test_app: CyberShieldApp) -> None:
    """Verify auth view navigation, logout, and login callbacks."""
    from frontend.auth_view import AuthView
    from security.auth import Role, Session

    # Trigger logout
    test_app.logout()
    assert test_app.current_session is None
    assert test_app._active_module_id == "auth"
    assert isinstance(test_app._current_view_frame, AuthView)

    # Login callback
    dummy_session = test_app.auth_service.sessions.create_session("u-adm", "admin_test", Role.ADMINISTRATOR)
    test_app.on_login_success(dummy_session)
    assert test_app.current_session == dummy_session
    assert test_app._active_module_id == "dashboard"


def test_navigation_to_unimplemented_modules(test_app: CyberShieldApp) -> None:
    """Verify navigation to planned modules renders PlaceholderView with correct metadata."""
    from frontend.dashboard import MODULE_METADATA
    MODULE_METADATA["planned_future_mod"] = {
        "title": "Future Threat AI",
        "phase": "Phase 99",
        "desc": "Autonomous heuristic scanner",
    }

    try:
        test_app.navigate_to("planned_future_mod")
        assert test_app._active_module_id == "planned_future_mod"
        assert isinstance(test_app._current_view_frame, PlaceholderView)
        assert "Phase 99" in test_app.topbar.subtitle_lbl["text"]
    finally:
        del MODULE_METADATA["planned_future_mod"]

    # Verify navigating back to Dashboard restores Dashboard view
    test_app.navigate_to("dashboard")
    assert test_app._active_module_id == "dashboard"
    assert not isinstance(test_app._current_view_frame, PlaceholderView)


def test_app_init_db_exception_fallback(tk_root, monkeypatch) -> None:
    """Verify CyberShieldApp gracefully handles database initialization exceptions."""
    from database.sqlite_manager import SQLiteManager
    def mock_init_fail(self):
        raise RuntimeError("Simulated DB init error")

    monkeypatch.setattr(SQLiteManager, "initialize_database", mock_init_fail)
    config = AppConfig(
        app_name="CyberShield DB Fail Test",
        app_version="0.1.0",
        environment="testing",
        debug=True,
        theme="dark",
        sqlite_db_path=":memory:",
        neon_database_url="",
        api_host="127.0.0.1",
        api_port=8000,
    )
    fallback_app = CyberShieldApp(config=config, root=tk_root)
    assert fallback_app is not None


def test_dashboard_components_rendering(test_app: CyberShieldApp) -> None:
    """Verify dashboard contains statistic cards, activity table, and status panel."""
    test_app.navigate_to("dashboard")
    test_app.root.update_idletasks()

    # Verify activity table exists and has rows
    assert hasattr(test_app, "activity_table")
    rows = test_app.activity_table.tree.get_children()
    assert len(rows) > 0

    # Trigger canvas configure and mousewheel events
    canvas = [w for w in test_app._current_view_frame.winfo_children() if isinstance(w, tk.Canvas)][0]
    mock_event = MagicMock()
    mock_event.width = 1000
    mock_event.delta = 120
    canvas.event_generate("<Configure>", width=1000, height=800)
    test_app.root.event_generate("<MouseWheel>", delta=120)
    test_app.root.update_idletasks()


def test_quick_actions_feedback(test_app: CyberShieldApp) -> None:
    """Verify clicking quick actions updates feedback banner with helpful message."""
    test_app._handle_quick_action("scan")
    assert "Quick Security Scan" in test_app.feedback_lbl["text"]
    assert "Phase 4" in test_app.feedback_lbl["text"]

    test_app._handle_quick_action("export")
    assert "Export Activity Log" in test_app.feedback_lbl["text"]


def test_search_and_notification_feedback(test_app: CyberShieldApp) -> None:
    """Verify search and notification handlers update the feedback banner."""
    test_app._handle_search("10.0.0.1")
    assert "10.0.0.1" in test_app.feedback_lbl["text"]

    test_app._show_notifications()
    assert "Notifications" in test_app.feedback_lbl["text"]


def test_unknown_module_navigation_handling(test_app: CyberShieldApp) -> None:
    """Verify handling of unknown navigation IDs without crashing."""
    test_app.navigate_to("non_existent_module")
    assert "Unknown module" in test_app.feedback_lbl["text"]


def test_window_close_cleanup(test_app: CyberShieldApp) -> None:
    """Verify on_close unbinds global handlers and destroys the root window."""
    with patch.object(test_app.root, "destroy") as mock_destroy:
        test_app.on_close()
        mock_destroy.assert_called_once()

    # Test error resilience when root is already destroyed
    test_app.on_close()


def test_app_run_call(test_app: CyberShieldApp) -> None:
    """Verify app.run invokes root.mainloop cleanly."""
    with patch.object(test_app.root, "mainloop") as mock_mainloop:
        exit_code = test_app.run()
        assert exit_code == 0
        mock_mainloop.assert_called_once()


def test_dashboard_mousewheel_lifecycle_and_navigation(test_app: CyberShieldApp) -> None:
    """Verify mousewheel bindings are cleanly managed across module navigation and destruction."""
    # 1. Start on dashboard and scroll repeatedly
    test_app.navigate_to("dashboard")
    test_app.root.update_idletasks()
    test_app.root.event_generate("<MouseWheel>", delta=120)
    test_app.root.event_generate("<MouseWheel>", delta=-120)
    test_app.root.event_generate("<MouseWheel>", delta=0)

    # 2. Navigate away to different modules and generate mousewheel events
    modules_to_visit = ["password_security", "file_integrity", "url_security", "settings", "user_management"]
    for mod in modules_to_visit:
        test_app.navigate_to(mod)
        test_app.root.update_idletasks()
        # Scroll while in another module - must not raise or reference destroyed canvas
        test_app.root.event_generate("<MouseWheel>", delta=120)
        test_app.root.event_generate("<MouseWheel>", delta=-120)

    # 3. Return to dashboard and scroll again
    test_app.navigate_to("dashboard")
    test_app.root.update_idletasks()
    test_app.root.event_generate("<MouseWheel>", delta=120)

    # 4. Resize window and scroll
    test_app.root.geometry("1400x900")
    test_app.root.update_idletasks()
    test_app.root.event_generate("<MouseWheel>", delta=-120)

    # 5. Direct test of _on_mousewheel lifecycle handling with destroyed canvas or TclError
    container = test_app._current_view_frame
    canvas = [w for w in container.winfo_children() if isinstance(w, tk.Canvas)][0]
    with patch.object(canvas, "winfo_exists", return_value=False):
        test_app.root.event_generate("<MouseWheel>", delta=120)

    # Re-enter dashboard to re-bind and test TclError branch
    test_app.navigate_to("dashboard")
    test_app.root.update_idletasks()
    container = test_app._current_view_frame
    canvas = [w for w in container.winfo_children() if isinstance(w, tk.Canvas)][0]
    with patch.object(canvas, "yview_scroll", side_effect=tk.TclError("invalid command name")):
        test_app.root.event_generate("<MouseWheel>", delta=120)

    # 6. Test _safe_unbind_mousewheel handles TclError gracefully
    with patch.object(test_app.root, "unbind_all", side_effect=tk.TclError("invalid command name")):
        test_app._safe_unbind_mousewheel()

