"""CyberShield UI Components.

Reusable widgets styled for the dark SOC Threat Analytics interface:
- CardFrame: Container card with subtle borders
- StatCard: Overview metric card with DEMO DATA tag
- ThreatChartWidget: Canvas-based severity distribution chart
- RecentActivityTable: Styled Treeview for activity events
- SystemStatusPanel: Operational status indicator (modules disconnected)
- QuickActionsPanel: Interactive quick-action command buttons
- PlaceholderView: View for modules planned for later phases
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from frontend.dashboard_data import (
    ActivityRecord,
    StatItem,
    SystemSecurityStatus,
    ThreatSeverityDistribution,
)
from frontend.theme import (
    ACCENT_HOVER,
    ACCENT_MUTED,
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_CARD,
    BG_CARD_HOVER,
    BG_DARK,
    BG_INPUT,
    BORDER_GLASS,
    COLOR_DANGER,
    COLOR_INFO,
    COLOR_SUCCESS,
    COLOR_WARNING,
    FONT_BADGE,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CAPTION,
    FONT_CAPTION_BOLD,
    FONT_METRIC,
    FONT_MONO_SMALL,
    FONT_SECTION_HEADER,
    FONT_SUBTITLE,
    FONT_TITLE,
    TEXT_DIMMED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)


class CardFrame(tk.Frame):
    """Reusable opaque dark-glass inspired surface with a quiet violet edge."""

    def __init__(
        self,
        master: tk.Misc,
        bg: str = BG_CARD,
        highlightbackground: str = BORDER_GLASS,
        highlightthickness: int = 1,
        padx: int = 18,
        pady: int = 18,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            bg=bg,
            highlightbackground=highlightbackground,
            highlightthickness=highlightthickness,
            padx=padx,
            pady=pady,
            **kwargs,
        )


class StatCard(CardFrame):
    """Statistic card showing metric value, trend, and explicit DEMO DATA badge."""

    def __init__(self, master: tk.Misc, item: StatItem, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.item = item
        self._build_ui()

    def _build_ui(self) -> None:
        # Header Row: Icon + Title + Demo Badge
        header_frame = tk.Frame(self, bg=self["bg"])
        header_frame.pack(fill=tk.X, anchor=tk.W)

        icon_lbl = tk.Label(
            header_frame,
            text=self.item.icon,
            font=FONT_SUBTITLE,
            bg=self["bg"],
            fg=ACCENT_SECONDARY,
        )
        icon_lbl.pack(side=tk.LEFT, padx=(0, 6))

        title_lbl = tk.Label(
            header_frame,
            text=self.item.title,
            font=FONT_CAPTION_BOLD,
            bg=self["bg"],
            fg=TEXT_MUTED,
        )
        title_lbl.pack(side=tk.LEFT)

        if self.item.is_demo:
            demo_badge = tk.Label(
                header_frame,
                text="DEMO",
                font=FONT_BADGE,
                bg=ACCENT_MUTED,
                fg=ACCENT_SECONDARY,
                padx=5,
                pady=1,
            )
            demo_badge.pack(side=tk.RIGHT)

        # Metric Value
        val_lbl = tk.Label(
            self,
            text=self.item.value,
            font=FONT_METRIC,
            bg=self["bg"],
            fg=TEXT_PRIMARY,
            anchor=tk.W,
        )
        val_lbl.pack(fill=tk.X, pady=(10, 4))

        # Footer Row: Trend percentage + contextual label
        footer_frame = tk.Frame(self, bg=self["bg"])
        footer_frame.pack(fill=tk.X)

        trend_color = COLOR_SUCCESS if self.item.is_increase else COLOR_WARNING
        trend_arrow = "▲" if self.item.is_increase else "▼"

        trend_lbl = tk.Label(
            footer_frame,
            text=f"{trend_arrow} {self.item.change}",
            font=FONT_CAPTION_BOLD,
            bg=self["bg"],
            fg=trend_color,
        )
        trend_lbl.pack(side=tk.LEFT, padx=(0, 6))

        sub_lbl = tk.Label(
            footer_frame,
            text="vs previous period",
            font=FONT_CAPTION,
            bg=self["bg"],
            fg=TEXT_DIMMED,
        )
        sub_lbl.pack(side=tk.LEFT)


class ThreatChartWidget(CardFrame):
    """Canvas-based visual breakdown of threat severity tiers with DEMO DATA tag."""

    def __init__(
        self,
        master: tk.Misc,
        distribution: ThreatSeverityDistribution,
        **kwargs,
    ) -> None:
        super().__init__(master, **kwargs)
        self.distribution = distribution
        self._build_ui()

    def _build_ui(self) -> None:
        # Header
        hdr = tk.Frame(self, bg=self["bg"])
        hdr.pack(fill=tk.X, pady=(0, 12))

        title = tk.Label(
            hdr,
            text="Threat Severity Distribution",
            font=FONT_SECTION_HEADER,
            bg=self["bg"],
            fg=TEXT_PRIMARY,
        )
        title.pack(side=tk.LEFT)

        if self.distribution.is_demo:
            demo_lbl = tk.Label(
                hdr,
                text="DEMO DATA",
                font=FONT_BADGE,
                bg=ACCENT_MUTED,
                fg=ACCENT_SECONDARY,
                padx=6,
                pady=1,
            )
            demo_lbl.pack(side=tk.RIGHT)

        # Distribution Canvas Bar
        self.canvas = tk.Canvas(
            self,
            bg=BG_INPUT,
            height=20,
            highlightthickness=0,
            relief="flat",
        )
        self.canvas.pack(fill=tk.X, pady=(0, 12))
        self.canvas.bind("<Configure>", self._draw_bar)

        # Breakdown Legend Grid
        legend_frame = tk.Frame(self, bg=self["bg"])
        legend_frame.pack(fill=tk.X)
        legend_frame.grid_columnconfigure((0, 1), weight=1)

        breakdown = self.distribution.get_breakdown()
        for idx, item in enumerate(breakdown):
            row = idx // 2
            col = idx % 2

            item_box = tk.Frame(legend_frame, bg=BG_INPUT, padx=8, pady=6)
            item_box.grid(row=row, column=col, sticky="ew", padx=3, pady=3)

            # Color dot
            dot = tk.Label(
                item_box,
                text="●",
                font=FONT_BODY_BOLD,
                bg=BG_INPUT,
                fg=item.color,
            )
            dot.pack(side=tk.LEFT, padx=(0, 6))

            name_lbl = tk.Label(
                item_box,
                text=item.severity,
                font=FONT_CAPTION_BOLD,
                bg=BG_INPUT,
                fg=TEXT_SECONDARY,
            )
            name_lbl.pack(side=tk.LEFT)

            count_lbl = tk.Label(
                item_box,
                text=f"{item.count} ({item.percentage}%)",
                font=FONT_CAPTION,
                bg=BG_INPUT,
                fg=TEXT_MUTED,
            )
            count_lbl.pack(side=tk.RIGHT)

    def _draw_bar(self, event: tk.Event | None = None) -> None:
        self.canvas.delete("all")
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        if width <= 1:
            return

        total = self.distribution.total or 1
        current_x = 0

        segments = [
            (self.distribution.critical, COLOR_DANGER),
            (self.distribution.high, COLOR_WARNING),
            (self.distribution.medium, ACCENT_SECONDARY),
            (self.distribution.low, COLOR_INFO),
        ]

        for count, color in segments:
            seg_width = int((count / total) * width)
            if seg_width > 0:
                self.canvas.create_rectangle(
                    current_x,
                    0,
                    current_x + seg_width,
                    height,
                    fill=color,
                    outline="",
                )
                current_x += seg_width


class RecentActivityTable(CardFrame):
    """Recent security activity log table rendered with dark ttk.Treeview."""

    def __init__(
        self,
        master: tk.Misc,
        records: list[ActivityRecord],
        **kwargs,
    ) -> None:
        super().__init__(master, **kwargs)
        self.records = records
        self._build_ui()

    def _build_ui(self) -> None:
        # Table Header
        hdr = tk.Frame(self, bg=self["bg"])
        hdr.pack(fill=tk.X, pady=(0, 10))

        title = tk.Label(
            hdr,
            text="Recent Security Activity",
            font=FONT_SECTION_HEADER,
            bg=self["bg"],
            fg=TEXT_PRIMARY,
        )
        title.pack(side=tk.LEFT)

        demo_badge = tk.Label(
            hdr,
            text="DEMO DATA",
            font=FONT_BADGE,
            bg=ACCENT_MUTED,
            fg=ACCENT_SECONDARY,
            padx=6,
            pady=1,
        )
        demo_badge.pack(side=tk.RIGHT)

        # Treeview Container
        tree_container = tk.Frame(self, bg=self["bg"])
        tree_container.pack(fill=tk.BOTH, expand=True)

        columns = ("id", "time", "event", "target", "severity", "status")
        self.tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            height=6,
            selectmode="browse",
        )

        self.tree.heading("id", text="LOG ID")
        self.tree.heading("time", text="TIMESTAMP")
        self.tree.heading("event", text="SECURITY EVENT")
        self.tree.heading("target", text="TARGET")
        self.tree.heading("severity", text="SEVERITY")
        self.tree.heading("status", text="STATUS")

        self.tree.column("id", width=70, anchor=tk.W)
        self.tree.column("time", width=80, anchor=tk.W)
        self.tree.column("event", width=190, anchor=tk.W)
        self.tree.column("target", width=160, anchor=tk.W)
        self.tree.column("severity", width=85, anchor=tk.CENTER)
        self.tree.column("status", width=85, anchor=tk.CENTER)

        # Populate rows
        for record in self.records:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    record.record_id,
                    record.timestamp,
                    record.event_type,
                    record.target,
                    record.severity,
                    record.status,
                ),
            )

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)


class SystemStatusPanel(CardFrame):
    """System status indicator explicitly reporting scanning modules are disconnected."""

    def __init__(
        self,
        master: tk.Misc,
        status: SystemSecurityStatus,
        on_details_click: Callable[[], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            highlightbackground="#452718",  # Amber/warning subtle border
            **kwargs,
        )
        self.status = status
        self.on_details_click = on_details_click
        self._build_ui()

    def _build_ui(self) -> None:
        # Status Alert Header
        top_row = tk.Frame(self, bg=self["bg"])
        top_row.pack(fill=tk.X)

        icon_lbl = tk.Label(
            top_row,
            text="⚡",
            font=FONT_SUBTITLE,
            bg=self["bg"],
            fg=COLOR_WARNING,
        )
        icon_lbl.pack(side=tk.LEFT, padx=(0, 6))

        title_lbl = tk.Label(
            top_row,
            text=f"SYSTEM STATUS: {self.status.headline}",
            font=FONT_SECTION_HEADER,
            bg=self["bg"],
            fg=COLOR_WARNING,
        )
        title_lbl.pack(side=tk.LEFT)

        state_badge = tk.Label(
            top_row,
            text="PHASE 1 PREVIEW",
            font=FONT_BADGE,
            bg="#382108",
            fg=COLOR_WARNING,
            padx=6,
            pady=2,
        )
        state_badge.pack(side=tk.RIGHT)

        # Operational details text
        desc_lbl = tk.Label(
            self,
            text=self.status.notice,
            font=FONT_CAPTION,
            bg=self["bg"],
            fg=TEXT_SECONDARY,
            wraplength=760,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(6, 8))


class QuickActionsPanel(CardFrame):
    """Interactive quick action command buttons with non-blocking feedback."""

    def __init__(
        self,
        master: tk.Misc,
        on_action: Callable[[str], None],
        **kwargs,
    ) -> None:
        super().__init__(master, **kwargs)
        self.on_action = on_action
        self._build_ui()

    def _build_ui(self) -> None:
        title = tk.Label(
            self,
            text="Quick SOC Operations",
            font=FONT_SECTION_HEADER,
            bg=self["bg"],
            fg=TEXT_PRIMARY,
        )
        title.pack(anchor=tk.W, pady=(0, 10))

        btn_grid = tk.Frame(self, bg=self["bg"])
        btn_grid.pack(fill=tk.X)
        btn_grid.grid_columnconfigure((0, 1), weight=1)

        actions = [
            ("Run Quick Scan", "🔍", "scan"),
            ("Export Activity Log", "📊", "export"),
            ("Verify File Integrity", "🛡️", "integrity"),
            ("System Diagnostics", "⚙️", "diag"),
        ]

        for idx, (label, icon, action_key) in enumerate(actions):
            row = idx // 2
            col = idx % 2

            btn = tk.Button(
                btn_grid,
                text=f"{icon} {label}",
                font=FONT_CAPTION_BOLD,
                bg=BG_INPUT,
                fg=TEXT_SECONDARY,
                activebackground=BG_CARD_HOVER,
                activeforeground=TEXT_PRIMARY,
                relief="flat",
                bd=0,
                padx=10,
                pady=8,
                cursor="hand2",
                command=lambda k=action_key: self.on_action(k),
            )
            btn.grid(row=row, column=col, sticky="ew", padx=3, pady=3)


class PlaceholderView(tk.Frame):
    """View shown for modules scheduled for later phases."""

    def __init__(
        self,
        master: tk.Misc,
        module_name: str,
        planned_phase: str,
        description: str,
        on_return_home: Callable[[], None],
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, padx=30, pady=40, **kwargs)
        self.module_name = module_name
        self.planned_phase = planned_phase
        self.description = description
        self.on_return_home = on_return_home
        self._build_ui()

    def _build_ui(self) -> None:
        center_card = CardFrame(self, bg=BG_CARD, padx=32, pady=32)
        center_card.pack(fill=tk.BOTH, expand=True)

        icon_lbl = tk.Label(
            center_card,
            text="🔒",
            font=("Segoe UI", 42),
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
        )
        icon_lbl.pack(pady=(10, 12))

        title_lbl = tk.Label(
            center_card,
            text=f"{self.module_name}",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(pady=(0, 6))

        phase_badge = tk.Label(
            center_card,
            text=f"PLANNED FOR {self.planned_phase.upper()}",
            font=FONT_BADGE,
            bg=ACCENT_MUTED,
            fg=ACCENT_SECONDARY,
            padx=10,
            pady=4,
        )
        phase_badge.pack(pady=(0, 16))

        desc_lbl = tk.Label(
            center_card,
            text=self.description,
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=600,
            justify=tk.CENTER,
        )
        desc_lbl.pack(pady=(0, 24))

        notice_box = tk.Frame(center_card, bg=BG_INPUT, padx=16, pady=12)
        notice_box.pack(fill=tk.X, padx=20, pady=(0, 24))

        notice_lbl = tk.Label(
            notice_box,
            text=(
                "Academic Integrity Policy: CyberShield strictly prohibits placeholder "
                "or fake mock scanners. This module will be implemented with genuine syllabus-oriented "
                f"algorithms during {self.planned_phase}."
            ),
            font=FONT_CAPTION,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            wraplength=540,
            justify=tk.CENTER,
        )
        notice_lbl.pack()

        btn_return = tk.Button(
            center_card,
            text="← Return to Dashboard",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=20,
            pady=10,
            cursor="hand2",
            command=self.on_return_home,
        )
        btn_return.pack()

