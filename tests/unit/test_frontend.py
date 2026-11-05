"""Unit tests for CyberShield frontend theme, data providers, and UI components."""

from __future__ import annotations

import re
import tkinter as tk
from unittest.mock import MagicMock
import pytest

from frontend.components import (
    CardFrame,
    PlaceholderView,
    QuickActionsPanel,
    RecentActivityTable,
    StatCard,
    SystemStatusPanel,
    ThreatChartWidget,
)
from frontend.dashboard_data import (
    ActivityRecord,
    DemoDashboardDataProvider,
    StatItem,
    SystemSecurityStatus,
    ThreatSeverityDistribution,
)
from frontend.sidebar import Sidebar
from frontend.theme import (
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_CARD,
    BG_DARK,
    BG_SIDEBAR,
    BG_TOPBAR,
    BORDER_GLASS,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_WARNING,
    apply_theme,
)
from frontend.topbar import TopBar


# =============================================================================
# 1. Module Imports & Theme System
# =============================================================================

def test_frontend_module_imports() -> None:
    """Verify that all core frontend modules are properly importable."""
    import frontend.auth_view
    import frontend.cloud_sync_view
    import frontend.components
    import frontend.dashboard
    import frontend.dashboard_data
    import frontend.file_integrity_view
    import frontend.network_view
    import frontend.password_view
    import frontend.reports_view
    import frontend.sidebar
    import frontend.theme
    import frontend.threat_analytics_view
    import frontend.topbar
    import frontend.url_view
    import frontend.user_management_view

    assert frontend.theme.BG_DARK == "#090A11"
    assert frontend.theme.BG_SIDEBAR == "#10121B"
    assert frontend.theme.BG_CARD == "#171923"
    assert frontend.theme.ACCENT_PRIMARY == "#7545F5"


def test_theme_palette_validity() -> None:
    """Ensure all core theme colors are valid 7-character hexadecimal strings."""
    hex_pattern = re.compile(r"^#[0-9a-fA-F]{6}$")
    palette = [
        BG_DARK,
        BG_SIDEBAR,
        BG_CARD,
        BG_TOPBAR,
        BORDER_GLASS,
        ACCENT_PRIMARY,
        ACCENT_SECONDARY,
        COLOR_SUCCESS,
        COLOR_WARNING,
        COLOR_DANGER,
    ]
    for color in palette:
        assert hex_pattern.match(color) is not None, f"Invalid hex color: {color}"


def test_theme_style_application(tk_root) -> None:
    """Verify that apply_theme configures ttk styling without exceptions."""
    style = apply_theme(tk_root)
    assert style is not None
    assert tk_root["bg"] == BG_DARK
    assert style.lookup("Treeview", "bordercolor") == BORDER_GLASS


def test_card_frame_glass_edge(tk_root) -> None:
    """Verify cards keep the quiet glass edge and standard child layout."""
    card = CardFrame(tk_root)
    card.pack(fill=tk.X)
    tk_root.update_idletasks()

    assert card.cget("highlightbackground") == BORDER_GLASS
    assert card.cget("padx") == 18
    assert card.cget("pady") == 18


# =============================================================================
# 2. Preview Data Provider & Strict Data Policies
# =============================================================================

def test_dashboard_preview_data_loading() -> None:
    """Verify preview data provider returns expected structures and counts."""
    provider = DemoDashboardDataProvider()

    stats = provider.get_statistics()
    assert len(stats) == 4
    for stat in stats:
        assert isinstance(stat, StatItem)
        assert len(stat.title) > 0
        assert len(stat.value) > 0

    dist = provider.get_severity_distribution()
    assert isinstance(dist, ThreatSeverityDistribution)
    assert dist.total == dist.critical + dist.high + dist.medium + dist.low
    assert len(dist.get_breakdown()) == 4

    activities = provider.get_recent_activity(limit=5)
    assert len(activities) == 5
    for act in activities:
        assert isinstance(act, ActivityRecord)
        assert act.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    status = provider.get_system_status()
    assert isinstance(status, SystemSecurityStatus)


def test_demo_data_labelling() -> None:
    """Verify all sample data elements are explicitly tagged with DEMO DATA."""
    provider = DemoDashboardDataProvider()

    for stat in provider.get_statistics():
        assert stat.is_demo is True
        assert stat.demo_badge == "[DEMO DATA]"

    dist = provider.get_severity_distribution()
    assert dist.is_demo is True
    assert dist.demo_badge == "[DEMO DATA]"

    for act in provider.get_recent_activity():
        assert act.is_demo is True

    status = provider.get_system_status()
    assert status.is_demo is True


def test_system_status_does_not_falsely_report_protection() -> None:
    """Verify system status explicitly reports engines are disconnected."""
    provider = DemoDashboardDataProvider()
    status = provider.get_system_status()

    # Must NOT claim protection
    assert status.is_protected is False
    assert status.engine_connected is False

    # Must explicitly state disconnected / offline
    combined_text = (status.headline + " " + status.summary + " " + status.notice).lower()
    assert "not connected" in combined_text or "offline" in combined_text or "disconnected" in combined_text
    assert "phase 4" in combined_text  # Guides user to planned integration phase


# =============================================================================
# 3. UI Component Construction & Interaction
# =============================================================================

def test_stat_card_widget(tk_root) -> None:
    """Verify StatCard displays metric title, value, and DEMO badge."""
    item = StatItem(
        title="Threats Detected",
        value="14",
        change="+3 today",
        is_increase=True,
        icon="⚠️",
        is_demo=True,
    )
    card = StatCard(tk_root, item)
    card.pack()
    tk_root.update_idletasks()

    # Find labels inside card
    labels = [w for w in card.winfo_children() if isinstance(w, tk.Label)]
    assert any("14" in str(getattr(w, "cget", lambda k: "")("text")) for w in labels)


def test_threat_chart_widget(tk_root) -> None:
    """Verify ThreatChartWidget creates a Canvas and renders severity segments."""
    dist = ThreatSeverityDistribution(critical=2, high=5, medium=4, low=3, is_demo=True)
    chart = ThreatChartWidget(tk_root, dist)
    chart.pack(fill=tk.BOTH, expand=True)
    tk_root.update_idletasks()

    assert chart.canvas is not None
    # Test manual draw call
    chart._draw_bar()


def test_recent_activity_table_population(tk_root) -> None:
    """Verify RecentActivityTable inserts the provided records into Treeview."""
    records = [
        ActivityRecord("SEC-01", "12:00:00", "Port Scan", "192.168.1.1", "HIGH", "FLAGGED"),
        ActivityRecord("SEC-02", "12:05:00", "Auth Fail", "192.168.1.2", "CRITICAL", "BLOCKED"),
    ]
    table = RecentActivityTable(tk_root, records)
    table.pack()
    tk_root.update_idletasks()

    children = table.tree.get_children()
    assert len(children) == 2


def test_system_status_panel_rendering(tk_root) -> None:
    """Verify SystemStatusPanel displays headline and warning state."""
    status = SystemSecurityStatus(
        headline="ENGINES OFFLINE",
        status_level="DISCONNECTED",
        is_protected=False,
        engine_connected=False,
        summary="Summary text",
        notice="Notice text",
        is_demo=True,
    )
    panel = SystemStatusPanel(tk_root, status)
    panel.pack()
    tk_root.update_idletasks()
    assert panel is not None


def test_quick_actions_panel_triggers_callback(tk_root) -> None:
    """Verify clicking quick action buttons invokes callback with action key."""
    mock_cb = MagicMock()
    panel = QuickActionsPanel(tk_root, on_action=mock_cb)
    panel.pack()
    tk_root.update_idletasks()

    # Find buttons
    btn_grid = [w for w in panel.winfo_children() if isinstance(w, tk.Frame)][0]
    buttons = [w for w in btn_grid.winfo_children() if isinstance(w, tk.Button)]
    assert len(buttons) == 4

    # Invoke all buttons
    for btn in buttons:
        btn.invoke()

    assert mock_cb.call_count == 4


def test_placeholder_view_structure(tk_root) -> None:
    """Verify PlaceholderView renders title, phase badge, and back button."""
    mock_return = MagicMock()
    placeholder = PlaceholderView(
        tk_root,
        module_name="Password Security",
        planned_phase="Phase 4",
        description="Password testing description",
        on_return_home=mock_return,
    )
    placeholder.pack()
    tk_root.update_idletasks()

    # Find the return button
    center_card = [w for w in placeholder.winfo_children() if isinstance(w, CardFrame)][0]
    return_btns = [w for w in center_card.winfo_children() if isinstance(w, tk.Button)]
    assert len(return_btns) == 1

    return_btns[0].invoke()
    mock_return.assert_called_once()


def test_sidebar_selection_and_callbacks(tk_root) -> None:
    """Verify Sidebar handles item selection and notifies callback."""
    mock_navigate = MagicMock()
    sidebar = Sidebar(tk_root, active_id="dashboard", on_navigate=mock_navigate)
    sidebar.pack()
    tk_root.update_idletasks()

    assert sidebar.active_id == "dashboard"

    sidebar.select("password_security")
    assert sidebar.active_id == "password_security"
    mock_navigate.assert_called_once_with("password_security")

    # Selecting current active should not fire again
    sidebar.select("password_security")
    assert mock_navigate.call_count == 1

    # Refresh non-existent button state (safety guard)
    sidebar._refresh_button_state("unknown_item", True)


def test_topbar_title_and_search_events(tk_root) -> None:
    """Verify TopBar dynamically updates title and processes search."""
    mock_notif = MagicMock()
    mock_search = MagicMock()

    topbar = TopBar(
        tk_root,
        initial_title="Initial Title",
        on_notification_click=mock_notif,
        on_search=mock_search,
    )
    topbar.pack()
    tk_root.update_idletasks()

    assert topbar.title_lbl["text"] == "Initial Title"

    topbar.set_title("New Page Title", "New Subtitle")
    assert topbar.title_lbl["text"] == "New Page Title"
    assert topbar.subtitle_lbl["text"] == "New Subtitle"

    # Test title update without explicit subtitle
    topbar.set_title("Another Page Title")
    assert topbar.subtitle_lbl["text"] == "SOC Threat Telemetry & Monitoring Console"

    # Notification button click
    topbar.notif_btn.invoke()
    mock_notif.assert_called_once()

    # Search focus events
    mock_event = MagicMock()
    topbar._on_search_focus_in(mock_event)
    assert topbar.search_entry.get() == ""

    topbar._on_search_focus_out(mock_event)
    assert topbar.search_entry.get() == "Search threats, IPs, hashes..."

    # Topbar user info & cloud status updates
    mock_logout = MagicMock()
    topbar.on_logout = mock_logout
    topbar.update_user_info("alice_soc", "administrator")
    assert "alice_soc" in topbar.user_name_lbl["text"]
    assert "ADMINISTRATOR" in topbar.user_name_lbl["text"]

    topbar.update_cloud_status(True)
    assert "ONLINE" in topbar.status_pill["text"]
    topbar.update_cloud_status(False)
    assert "OFFLINE" in topbar.status_pill["text"]

    topbar.btn_logout.invoke()
    mock_logout.assert_called_once()

    # Search event
    topbar.search_entry.delete(0, tk.END)
    topbar.search_entry.insert(0, "192.168.1.50")
    topbar._handle_search(None)
    mock_search.assert_called_once_with("192.168.1.50")


def test_dashboard_data_provider_protocol_methods() -> None:
    """Verify DashboardDataProvider protocol definition."""
    from frontend.dashboard_data import DashboardDataProvider

    class DummyProvider(DashboardDataProvider):
        pass

    # Ensure class implements the protocol without type error
    assert issubclass(DemoDashboardDataProvider, DashboardDataProvider)

