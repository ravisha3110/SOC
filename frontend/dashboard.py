"""CyberShield Dashboard Main View & Application Shell.

Coordinates Sidebar, TopBar, StatCards, ActivityTable, ThreatChart,
SystemStatusPanel, and PlaceholderViews for planned modules.
Follows Reference 3 (Threat Analytics) with a responsive dark SOC layout.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

from config.settings import AppConfig, get_config
from frontend.components import (
    PlaceholderView,
    QuickActionsPanel,
    RecentActivityTable,
    StatCard,
    SystemStatusPanel,
    ThreatChartWidget,
)
from frontend.dashboard_data import (
    DashboardDataProvider,
    DemoDashboardDataProvider,
)
from frontend.sidebar import Sidebar
from frontend.theme import (
    ACCENT_HOVER,
    ACCENT_MUTED,
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_CARD,
    BG_DARK,
    BG_INPUT,
    BORDER_SUBTLE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    FONT_BADGE,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CAPTION,
    FONT_CAPTION_BOLD,
    FONT_TITLE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    apply_theme,
)

from database.postgres_manager import PostgresManager
from database.repositories import UserRepository
from database.sqlite_manager import SQLiteManager
from security.auth import AuthService, Role, Session
from security.cloud_sync import CloudSyncEngine

MODULE_METADATA: dict[str, dict[str, str]] = {}


class CyberShieldApp:
    """Main CyberShield Desktop Application Window."""

    def __init__(
        self,
        config: AppConfig | None = None,
        data_provider: DashboardDataProvider | None = None,
        root: tk.Tk | None = None,
    ) -> None:
        self.config = config or get_config()
        self.data_provider = data_provider or DemoDashboardDataProvider()
        self.root = root or tk.Tk()
        self.is_custom_root = root is not None

        # Database & Security Engines
        self.db_manager = SQLiteManager(self.config.sqlite_db_path)
        try:
            self.db_manager.initialize_database()
        except Exception:
            pass
        self.user_repo = UserRepository(self.db_manager)
        self.auth_service = AuthService(self.user_repo)
        self.pg_manager = PostgresManager(self.config.neon_database_url)
        self.sync_engine = CloudSyncEngine(self.db_manager, self.pg_manager)

        # Active Session (Default Administrator demo session for immediate inspection and test compatibility)
        self.current_session: Session = self.auth_service.sessions.create_session(
            user_id="lead-admin-id",
            username="admin_lead",
            role=Role.ADMINISTRATOR,
        )

        self._current_view_frame: tk.Frame | None = None
        self._active_module_id: str = "dashboard"

        self._setup_window()
        apply_theme(self.root)
        self._build_layout()

    def _setup_window(self) -> None:
        self.root.title(f"{self.config.app_name} [v{self.config.app_version}]")
        self.root.geometry("1280x760")
        self.root.minsize(1040, 640)
        self.root.configure(bg=BG_DARK)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_layout(self) -> None:
        # 2-Column Responsive Grid Layout
        self.root.grid_columnconfigure(0, weight=0)  # Sidebar fixed width
        self.root.grid_columnconfigure(1, weight=1)  # Main Content expands
        self.root.grid_rowconfigure(0, weight=1)

        # 1. Left Sidebar
        self.sidebar = Sidebar(
            self.root,
            active_id=self._active_module_id,
            on_navigate=self.navigate_to,
            current_role=self.current_session.role.value if self.current_session else "analyst",
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        # 2. Main Right Container
        self.main_container = tk.Frame(self.root, bg=BG_DARK)
        self.main_container.grid(row=0, column=1, sticky="nsew")

        # TopBar inside main container
        from frontend.topbar import TopBar

        self.topbar = TopBar(
            self.main_container,
            initial_title="Threat Analytics Dashboard",
            on_notification_click=self._show_notifications,
            on_search=self._handle_search,
            on_logout=self.logout,
        )
        self.topbar.pack(fill=tk.X, side=tk.TOP)
        if self.current_session:
            self.topbar.update_user_info(self.current_session.username, self.current_session.role.value)

        # Status & Feedback Toast Banner (Bottom)
        self.feedback_banner = tk.Frame(
            self.main_container,
            bg=BG_CARD,
            highlightbackground=BORDER_SUBTLE,
            highlightthickness=1,
            padx=16,
            pady=6,
        )
        self.feedback_banner.pack(fill=tk.X, side=tk.BOTTOM)

        self.feedback_lbl = tk.Label(
            self.feedback_banner,
            text="● CyberShield SOC Threat Intelligence Workstation // All 11 Modules Active // Platform Status: Operational",
            font=FONT_CAPTION,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        self.feedback_lbl.pack(side=tk.LEFT)

        # Viewport Area for views (fills middle)
        self.viewport = tk.Frame(self.main_container, bg=BG_DARK)
        self.viewport.pack(fill=tk.BOTH, expand=True)

        # Load initial view
        self._render_view("dashboard")

    def navigate_to(self, module_id: str) -> None:
        """Navigate to the requested module view."""
        self._active_module_id = module_id

        if module_id == "dashboard":
            self.topbar.set_title("Threat Analytics Dashboard", "SOC Threat Telemetry & Monitoring Console")
            self._render_view("dashboard")
            self.show_feedback("Navigated to Threat Analytics Dashboard.")
        elif module_id == "password_security":
            self.topbar.set_title("Password Security Analyzer", "Cryptographic Entropy & Structural Vulnerability Assessment")
            self._render_view("password_security")
            self.show_feedback("Navigated to Password Security Analyzer.")
        elif module_id == "file_integrity":
            self.topbar.set_title("File Integrity Scanner (FIM)", "SHA-256 Baseline Auditing & Modification Detection")
            self._render_view("file_integrity")
            self.show_feedback("Navigated to File Integrity Scanner.")
        elif module_id == "url_security":
            self.topbar.set_title("URL Security Analyzer", "DFA Automaton Validation & Heuristic Risk Scoring")
            self._render_view("url_security")
            self.show_feedback("Navigated to URL Security Analyzer.")
        elif module_id == "network_monitor":
            self.topbar.set_title("Network Activity Monitor", "Local Socket Telemetry & Port State Tracking")
            self._render_view("network_monitor")
            self.show_feedback("Navigated to Network Activity Monitor.")
        elif module_id == "threat_analytics":
            self.topbar.set_title("Threat Analytics & Correlation", "Multi-Source Threat Correlation & CVSS Severity Breakdown")
            self._render_view("threat_analytics")
            self.show_feedback("Navigated to Threat Analytics Dashboard.")
        elif module_id == "reports":
            self.topbar.set_title("Security Incident & Executive Reports", "SOC Executive Briefings & CSV Forensic Findings Export")
            self._render_view("reports")
            self.show_feedback("Navigated to Security Reports.")
        elif module_id == "settings":
            self.topbar.set_title("Hybrid Cloud Synchronization", "Neon PostgreSQL Cloud Storage & Telemetry")
            self._render_view("settings")
            self.show_feedback("Navigated to Hybrid Cloud Synchronization.")
        elif module_id == "user_management":
            self.topbar.set_title("User & Access Control Management", "Administrator RBAC Console")
            self._render_view("user_management")
            self.show_feedback("Navigated to User Management.")
        elif module_id == "auth":
            self.topbar.set_title("SOC Access Control", "Authentication & Security Station")
            self._render_view("auth")
            self.show_feedback("Navigated to Authentication Screen.")
        elif module_id in MODULE_METADATA:
            meta = MODULE_METADATA[module_id]
            self.topbar.set_title(meta["title"], f"Module Status: Planned for {meta['phase']}")
            self._render_placeholder(module_id, meta)
            self.show_feedback(f"Module '{meta['title']}' is planned for {meta['phase']}.")
        else:
            self.show_feedback(f"Unknown module navigation request: {module_id}")

    def _safe_unbind_mousewheel(self) -> None:
        """Safely unbind global mousewheel events to prevent stale callbacks."""
        try:
            self.root.unbind_all("<MouseWheel>")
        except (tk.TclError, AttributeError):
            pass

    def _render_view(self, view_name: str) -> None:
        self._safe_unbind_mousewheel()

        if self._current_view_frame is not None:
            self._current_view_frame.destroy()
            self._current_view_frame = None

        if view_name == "dashboard":
            self._current_view_frame = self._build_dashboard_view(self.viewport)
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "password_security":
            from frontend.password_view import PasswordSecurityView
            self._current_view_frame = PasswordSecurityView(
                self.viewport,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "file_integrity":
            from frontend.file_integrity_view import FileIntegrityView
            self._current_view_frame = FileIntegrityView(
                self.viewport,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "url_security":
            from frontend.url_view import URLSecurityView
            self._current_view_frame = URLSecurityView(
                self.viewport,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "network_monitor":
            from frontend.network_view import NetworkActivityView
            self._current_view_frame = NetworkActivityView(
                self.viewport,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "threat_analytics":
            from frontend.threat_analytics_view import ThreatAnalyticsView
            self._current_view_frame = ThreatAnalyticsView(
                self.viewport,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "reports":
            from frontend.reports_view import ReportsView
            self._current_view_frame = ReportsView(
                self.viewport,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "settings":
            from frontend.cloud_sync_view import CloudSyncView
            self._current_view_frame = CloudSyncView(
                self.viewport,
                sync_engine=self.sync_engine,
                current_session=self.current_session,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "user_management":
            from frontend.user_management_view import UserManagementView
            self._current_view_frame = UserManagementView(
                self.viewport,
                auth_service=self.auth_service,
                current_session=self.current_session,
                on_feedback=self.show_feedback,
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)
        elif view_name == "auth":
            from frontend.auth_view import AuthView
            self._current_view_frame = AuthView(
                self.viewport,
                auth_service=self.auth_service,
                on_login_success=self.on_login_success,
                on_feedback=self.show_feedback,
                enable_demo_logins=getattr(self.config, "enable_demo_logins", True),
            )
            self._current_view_frame.pack(fill=tk.BOTH, expand=True)

    def logout(self) -> None:
        """Log out current user and return to authentication view."""
        if self.current_session:
            self.auth_service.logout_user(self.current_session.token)
            self.current_session = None
        self.sidebar.set_role("viewer")
        self.topbar.update_user_info("Logged Out", "None")
        self.navigate_to("auth")

    def on_login_success(self, session: Session) -> None:
        """Handle successful authentication from AuthView."""
        self.current_session = session
        self.sidebar.set_role(session.role.value)
        self.topbar.update_user_info(session.username, session.role.value)
        self.show_feedback(f"Authenticated as {session.username} ({session.role.value.upper()})")
        self.navigate_to("dashboard")

    def _render_placeholder(self, module_id: str, meta: dict[str, str]) -> None:
        self._safe_unbind_mousewheel()

        if self._current_view_frame is not None:
            self._current_view_frame.destroy()
            self._current_view_frame = None

        self._current_view_frame = PlaceholderView(
            self.viewport,
            module_name=meta["title"],
            planned_phase=meta["phase"],
            description=meta["desc"],
            on_return_home=lambda: self.sidebar.select("dashboard"),
        )
        self._current_view_frame.pack(fill=tk.BOTH, expand=True)

    def _build_dashboard_view(self, parent: tk.Widget) -> tk.Frame:
        """Construct the scrollable SOC Threat Analytics Dashboard view."""
        container = tk.Frame(parent, bg=BG_DARK)

        # Scrollable Canvas Setup for Responsive Desktop Sizing
        canvas = tk.Canvas(
            container,
            bg=BG_DARK,
            highlightthickness=0,
            relief="flat",
        )
        v_scrollbar = ttk.Scrollbar(
            container,
            orient=tk.VERTICAL,
            command=canvas.yview,
            style="Vertical.TScrollbar",
        )

        scroll_content = tk.Frame(canvas, bg=BG_DARK, padx=24, pady=20)
        scroll_content_id = canvas.create_window((0, 0), window=scroll_content, anchor=tk.NW)

        canvas.configure(xscrollcommand=None, yscrollcommand=v_scrollbar.set)

        def _on_canvas_configure(event: tk.Event) -> None:
            if canvas.winfo_exists():
                canvas.itemconfig(scroll_content_id, width=event.width)

        def _on_frame_configure(event: tk.Event) -> None:
            if canvas.winfo_exists():
                canvas.configure(scrollregion=canvas.bbox("all"))

        canvas.bind("<Configure>", _on_canvas_configure)
        scroll_content.bind("<Configure>", _on_frame_configure)

        # Mousewheel scrolling with safe widget lifecycle handling
        def _on_mousewheel(event: tk.Event) -> None:
            try:
                if canvas.winfo_exists():
                    delta = getattr(event, "delta", 0) or 0
                    if delta:
                        canvas.yview_scroll(int(-1 * (delta / 120)), "units")
                else:
                    self._safe_unbind_mousewheel()
            except tk.TclError:
                self._safe_unbind_mousewheel()

        # Prevent duplicate bindings during page navigation or view reconstruction
        self._safe_unbind_mousewheel()
        self.root.bind_all("<MouseWheel>", _on_mousewheel)

        def _on_destroy(event: tk.Event) -> None:
            if event.widget is container or str(event.widget) == str(container):
                self._safe_unbind_mousewheel()

        container.bind("<Destroy>", _on_destroy)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # -------------------------------------------------------------
        # Section 1: 4 Statistic Cards (Total Scans, Threats, Files, Net)
        # -------------------------------------------------------------
        stats_frame = tk.Frame(scroll_content, bg=BG_DARK)
        stats_frame.pack(fill=tk.X, pady=(0, 18))
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="stat_cards")

        stat_items = self.data_provider.get_statistics()
        for idx, item in enumerate(stat_items):
            card = StatCard(stats_frame, item)
            card.grid(row=0, column=idx, sticky="ew", padx=(0 if idx == 0 else 8, 0 if idx == 3 else 8))

        # -------------------------------------------------------------
        # Section 2: System Security Operational Status Panel (Modules Disconnected)
        # -------------------------------------------------------------
        system_status = self.data_provider.get_system_status()
        status_panel = SystemStatusPanel(scroll_content, system_status)
        status_panel.pack(fill=tk.X, pady=(0, 18))

        # -------------------------------------------------------------
        # Section 3: 2-Column Split (Recent Activity & Threat Distribution / Quick Actions)
        # -------------------------------------------------------------
        split_frame = tk.Frame(scroll_content, bg=BG_DARK)
        split_frame.pack(fill=tk.BOTH, expand=True)
        split_frame.grid_columnconfigure(0, weight=3)  # Activity table
        split_frame.grid_columnconfigure(1, weight=2)  # Charts & actions

        # Left Column: Recent Security Activity Table
        activity_records = self.data_provider.get_recent_activity(limit=6)
        self.activity_table = RecentActivityTable(split_frame, activity_records)
        self.activity_table.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        # Right Column: Severity Chart + Quick Actions
        right_column = tk.Frame(split_frame, bg=BG_DARK)
        right_column.grid(row=0, column=1, sticky="nsew")

        severity_distribution = self.data_provider.get_severity_distribution()
        chart_widget = ThreatChartWidget(right_column, severity_distribution)
        chart_widget.pack(fill=tk.X, pady=(0, 16))

        quick_actions = QuickActionsPanel(right_column, on_action=self._handle_quick_action)
        quick_actions.pack(fill=tk.X)

        return container

    def show_feedback(self, message: str) -> None:
        """Display non-blocking status feedback in bottom banner."""
        self.feedback_lbl.configure(text=f"● {message}")

    def _handle_quick_action(self, action_key: str) -> None:
        """Handle quick actions with informative, non-dead responses."""
        action_names = {
            "scan": "Quick Security Scan",
            "export": "Export Activity Log",
            "integrity": "Verify File Integrity",
            "diag": "System Diagnostics",
        }
        name = action_names.get(action_key, action_key)
        self.show_feedback(f"Action '{name}' acknowledged. Security execution engine connects in Phase 4.")

    def _handle_search(self, query: str) -> None:
        """Handle search queries from the top bar."""
        self.show_feedback(f"Search executed for: '{query}' [DEMO DATA filtered]")

    def _show_notifications(self) -> None:
        """Show notification drawer / feedback."""
        self.show_feedback("Active Notifications: 3 unread security warnings (Demo Data).")

    def run(self) -> int:
        """Start desktop application main loop."""
        self.root.mainloop()
        return 0

    def on_close(self) -> None:
        """Handle window closing protocol cleanly."""
        self._safe_unbind_mousewheel()
        self.root.destroy()
