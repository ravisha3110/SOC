"""Top Navigation Bar Component.

Contains dynamic page title, search input, threat engine indicator,
notification alerts counter, and user profile badge.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable

from frontend.theme import (
    ACCENT_MUTED,
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_CARD,
    BG_INPUT,
    BG_TOPBAR,
    BORDER_SUBTLE,
    COLOR_DANGER,
    COLOR_WARNING,
    FONT_BADGE,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CAPTION,
    FONT_CAPTION_BOLD,
    FONT_TITLE,
    TEXT_DIMMED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)


class TopBar(tk.Frame):
    """Top navigation bar adhering to Reference 3 layout specifications."""

    def __init__(
        self,
        master: tk.Misc,
        initial_title: str = "Threat Analytics Dashboard",
        on_notification_click: Callable[[], None] | None = None,
        on_search: Callable[[str], None] | None = None,
        on_logout: Callable[[], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=BG_TOPBAR,
            highlightbackground=BORDER_SUBTLE,
            highlightthickness=1,
            padx=22,
            pady=14,
            **kwargs,
        )
        self.on_notification_click = on_notification_click
        self.on_search = on_search
        self.on_logout = on_logout
        self._build_ui(initial_title)

    def _build_ui(self, initial_title: str) -> None:
        # Left Section: Current Page Title & Context
        left_box = tk.Frame(self, bg=BG_TOPBAR)
        left_box.pack(side=tk.LEFT, fill=tk.Y)

        self.title_lbl = tk.Label(
            left_box,
            text=initial_title,
            font=FONT_TITLE,
            bg=BG_TOPBAR,
            fg=TEXT_PRIMARY,
        )
        self.title_lbl.pack(anchor=tk.W)

        self.subtitle_lbl = tk.Label(
            left_box,
            text="SOC Threat Telemetry & Monitoring Console",
            font=FONT_CAPTION,
            bg=BG_TOPBAR,
            fg=TEXT_MUTED,
        )
        self.subtitle_lbl.pack(anchor=tk.W)

        # Right Section: Actions & Profile Placeholder
        right_box = tk.Frame(self, bg=BG_TOPBAR)
        right_box.pack(side=tk.RIGHT, fill=tk.Y)

        # User Profile Badge
        user_badge = tk.Frame(
            right_box,
            bg=BG_CARD,
            highlightbackground=BORDER_SUBTLE,
            highlightthickness=1,
            padx=10,
            pady=4,
        )
        user_badge.pack(side=tk.RIGHT, padx=(8, 0))

        user_icon = tk.Label(
            user_badge,
            text="👤",
            font=FONT_BODY,
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
        )
        user_icon.pack(side=tk.LEFT, padx=(0, 6))

        self.user_name_lbl = tk.Label(
            user_badge,
            text="Analyst (Demo Mode)",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        self.user_name_lbl.pack(side=tk.LEFT)

        # Logout Button
        self.btn_logout = tk.Button(
            right_box,
            text="🚪 Logout",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=COLOR_DANGER,
            activebackground=BG_INPUT,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=8,
            pady=4,
            cursor="hand2",
            command=self._handle_logout,
        )
        self.btn_logout.pack(side=tk.RIGHT, padx=(8, 0))

        # Notification Indicator Button
        self.notif_btn = tk.Button(
            right_box,
            text="🔔 3 Alerts",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
            activebackground=BG_INPUT,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=10,
            pady=5,
            cursor="hand2",
            command=self._handle_notification,
        )
        self.notif_btn.pack(side=tk.RIGHT, padx=(8, 0))

        # Status Pill: Cloud/Engine Status
        self.status_pill = tk.Label(
            right_box,
            text="● ENGINE OFFLINE",
            font=FONT_BADGE,
            bg="#2E1B0F",
            fg=COLOR_WARNING,
            padx=8,
            pady=5,
        )
        self.status_pill.pack(side=tk.RIGHT, padx=(8, 0))

        # Search Box
        search_frame = tk.Frame(
            right_box,
            bg=BG_INPUT,
            highlightbackground=BORDER_SUBTLE,
            highlightthickness=1,
            padx=8,
            pady=2,
        )
        search_frame.pack(side=tk.RIGHT, padx=(8, 0))

        search_icon = tk.Label(
            search_frame,
            text="🔍",
            font=FONT_CAPTION,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
        )
        search_icon.pack(side=tk.LEFT, padx=(0, 4))

        self.search_entry = tk.Entry(
            search_frame,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            font=FONT_BODY,
            width=22,
        )
        self.search_entry.pack(side=tk.LEFT)
        self.search_entry.insert(0, "Search threats, IPs, hashes...")
        self.search_entry.bind("<FocusIn>", self._on_search_focus_in)
        self.search_entry.bind("<FocusOut>", self._on_search_focus_out)
        self.search_entry.bind("<Return>", self._handle_search)

    def _on_search_focus_in(self, event: tk.Event) -> None:
        if self.search_entry.get() == "Search threats, IPs, hashes...":
            self.search_entry.delete(0, tk.END)
            self.search_entry.configure(fg=TEXT_PRIMARY)

    def _on_search_focus_out(self, event: tk.Event) -> None:
        if not self.search_entry.get().strip():
            self.search_entry.insert(0, "Search threats, IPs, hashes...")
            self.search_entry.configure(fg=TEXT_DIMMED)

    def _handle_search(self, event: tk.Event | None = None) -> None:
        query = self.search_entry.get().strip()
        if self.on_search and query != "Search threats, IPs, hashes...":
            self.on_search(query)

    def _handle_notification(self) -> None:
        if self.on_notification_click:
            self.on_notification_click()

    def _handle_logout(self) -> None:
        if self.on_logout:
            self.on_logout()

    def update_user_info(self, username: str, role: str) -> None:
        """Update topbar user profile badge with active session details."""
        self.user_name_lbl.configure(text=f"{username} ({role.upper()})")

    def update_cloud_status(self, is_online: bool) -> None:
        """Update cloud telemetry status pill in topbar."""
        if is_online:
            self.status_pill.configure(text="● CLOUD: ONLINE", bg="#064E3B", fg="#22C55E")
        else:
            self.status_pill.configure(text="● CLOUD: OFFLINE", bg="#2E1B0F", fg=COLOR_WARNING)

    def set_title(self, title: str, subtitle: str | None = None) -> None:
        """Dynamically update top navigation title and subtitle."""
        self.title_lbl.configure(text=title)
        if subtitle:
            self.subtitle_lbl.configure(text=subtitle)
        else:
            self.subtitle_lbl.configure(text="SOC Threat Telemetry & Monitoring Console")

