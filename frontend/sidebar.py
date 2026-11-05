"""Sidebar Navigation Component.

Provides consistent, dark-themed navigation for CyberShield.
Supports switching between Dashboard and syllabus-oriented security modules.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable

from frontend.theme import (
    ACCENT_HOVER,
    ACCENT_MUTED,
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_INPUT,
    BG_SIDEBAR,
    BG_SIDEBAR_ACTIVE,
    BG_SIDEBAR_HOVER,
    BORDER_SUBTLE,
    FONT_BADGE,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CAPTION,
    FONT_CAPTION_BOLD,
    FONT_SECTION_HEADER,
    FONT_SUBTITLE,
    FONT_TITLE,
    TEXT_DIMMED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)

NAV_ITEMS = [
    ("dashboard", "Dashboard", "📊"),
    ("password_security", "Password Security", "🔑"),
    ("file_integrity", "File Integrity", "📁"),
    ("url_security", "URL Security", "🔗"),
    ("network_monitor", "Network Monitor", "🌐"),
    ("threat_analytics", "Threat Analytics", "⚡"),
    ("reports", "Security Reports", "📄"),
    ("settings", "Cloud Sync", "☁️"),
    ("user_management", "User Management", "👥"),
]


class Sidebar(tk.Frame):
    """Left navigation sidebar with modern SOC styling and active-state tracking."""

    def __init__(
        self,
        master: tk.Misc,
        active_id: str = "dashboard",
        on_navigate: Callable[[str], None] | None = None,
        current_role: str = "analyst",
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=BG_SIDEBAR,
            width=240,
            highlightbackground=BORDER_SUBTLE,
            highlightthickness=1,
            **kwargs,
        )
        self.active_id = active_id
        self.on_navigate = on_navigate
        self.current_role = current_role
        self._buttons: dict[str, tk.Frame] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        # Prevent auto-shrinking below preferred width
        self.pack_propagate(False)

        # Brand / Logo Header
        brand_frame = tk.Frame(self, bg=BG_SIDEBAR, padx=16, pady=20)
        brand_frame.pack(fill=tk.X)

        logo_row = tk.Frame(brand_frame, bg=BG_SIDEBAR)
        logo_row.pack(fill=tk.X)

        shield_icon = tk.Label(
            logo_row,
            text="🛡️",
            font=("Segoe UI", 16),
            bg=BG_SIDEBAR,
            fg=ACCENT_SECONDARY,
        )
        shield_icon.pack(side=tk.LEFT, padx=(0, 8))

        brand_title = tk.Label(
            logo_row,
            text="CyberShield",
            font=FONT_TITLE,
            bg=BG_SIDEBAR,
            fg=TEXT_PRIMARY,
        )
        brand_title.pack(side=tk.LEFT)

        brand_subtitle = tk.Label(
            brand_frame,
            text="SOC THREAT ANALYTICS",
            font=FONT_BADGE,
            bg=BG_SIDEBAR,
            fg=ACCENT_SECONDARY,
        )
        brand_subtitle.pack(anchor=tk.W, pady=(4, 0))

        # Divider
        divider = tk.Frame(self, bg=BORDER_SUBTLE, height=1)
        divider.pack(fill=tk.X, padx=12, pady=(0, 12))

        # Section Label
        section_lbl = tk.Label(
            self,
            text="CORE PLATFORM",
            font=FONT_BADGE,
            bg=BG_SIDEBAR,
            fg=TEXT_DIMMED,
            padx=16,
        )
        section_lbl.pack(anchor=tk.W, pady=(0, 6))

        # Navigation Items
        self.nav_container = tk.Frame(self, bg=BG_SIDEBAR)
        self.nav_container.pack(fill=tk.BOTH, expand=True, padx=8)

        for item_id, label, icon in NAV_ITEMS:
            self._create_nav_button(item_id, label, icon)
        self.set_role(self.current_role)

        # Bottom System Info Footer
        footer = tk.Frame(
            self,
            bg=BG_INPUT,
            padx=12,
            pady=12,
            highlightbackground=BORDER_SUBTLE,
            highlightthickness=1,
        )
        footer.pack(fill=tk.X, padx=10, pady=12)

        env_pill = tk.Label(
            footer,
            text="● PREVIEW ACTIVE",
            font=FONT_BADGE,
            bg=BG_INPUT,
            fg=ACCENT_SECONDARY,
        )
        env_pill.pack(anchor=tk.W)

        footer_text = tk.Label(
            footer,
            text="Phase 1: Desktop Shell\nSecurity modules in Phase 4",
            font=FONT_CAPTION,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            justify=tk.LEFT,
        )
        footer_text.pack(anchor=tk.W, pady=(4, 0))

    def _create_nav_button(self, item_id: str, label: str, icon: str) -> None:
        is_active = item_id == self.active_id

        btn_frame = tk.Frame(
            self.nav_container,
            bg=BG_SIDEBAR_ACTIVE if is_active else BG_SIDEBAR,
            cursor="hand2",
            padx=4,
            pady=2,
        )
        btn_frame.pack(fill=tk.X, pady=2)

        # Indicator bar on the left for active state
        indicator = tk.Frame(
            btn_frame,
            bg=ACCENT_PRIMARY if is_active else BG_SIDEBAR,
            width=4,
            height=28,
        )
        indicator.pack(side=tk.LEFT, padx=(0, 8))

        # Icon Label
        icon_lbl = tk.Label(
            btn_frame,
            text=icon,
            font=FONT_BODY,
            bg=btn_frame["bg"],
            fg=ACCENT_SECONDARY if is_active else TEXT_MUTED,
        )
        icon_lbl.pack(side=tk.LEFT, padx=(0, 8))

        # Text Label
        text_lbl = tk.Label(
            btn_frame,
            text=label,
            font=FONT_BODY_BOLD if is_active else FONT_BODY,
            bg=btn_frame["bg"],
            fg=TEXT_PRIMARY if is_active else TEXT_MUTED,
        )
        text_lbl.pack(side=tk.LEFT, fill=tk.X)

        # Bind clicks to all child widgets
        for widget in (btn_frame, indicator, icon_lbl, text_lbl):
            widget.bind("<Button-1>", lambda e, target=item_id: self.select(target))

        self._buttons[item_id] = btn_frame

    def select(self, item_id: str) -> None:
        """Set active navigation item and notify callback."""
        if item_id == self.active_id:
            return

        old_id = self.active_id
        self.active_id = item_id

        # Refresh styling on old and new buttons
        self._refresh_button_state(old_id, False)
        self._refresh_button_state(item_id, True)

        if self.on_navigate:
            self.on_navigate(item_id)

    def _refresh_button_state(self, item_id: str, is_active: bool) -> None:
        if item_id not in self._buttons:
            return

        frame = self._buttons[item_id]
        bg = BG_SIDEBAR_ACTIVE if is_active else BG_SIDEBAR
        frame.configure(bg=bg)

        children = frame.winfo_children()
        if len(children) >= 3:
            # Indicator bar
            children[0].configure(bg=ACCENT_PRIMARY if is_active else BG_SIDEBAR)
            # Icon
            children[1].configure(
                bg=bg,
                fg=ACCENT_SECONDARY if is_active else TEXT_MUTED,
            )
            # Text
            children[2].configure(
                bg=bg,
                fg=TEXT_PRIMARY if is_active else TEXT_MUTED,
                font=FONT_BODY_BOLD if is_active else FONT_BODY,
            )

    def set_role(self, role: str) -> None:
        """Update visible sidebar items based on user role."""
        self.current_role = role
        if "user_management" in self._buttons:
            frame = self._buttons["user_management"]
            if role.lower() == "administrator":
                frame.pack(fill=tk.X, pady=2)
            else:
                frame.pack_forget()

