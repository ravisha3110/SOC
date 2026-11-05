"""Threat Analytics Desktop View.

Unified SOC threat analytics console correlating events, severities, and scan findings
across File Integrity, URL Security, Network Monitoring, and Cryptographic audits.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from frontend.components import CardFrame
from frontend.theme import (
    ACCENT_HOVER,
    ACCENT_MUTED,
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_CARD,
    BG_CARD_HOVER,
    BG_DARK,
    BG_INPUT,
    BORDER_SUBTLE,
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
from security.threat_analytics import (
    ThreatAnalyticsEngine,
    ThreatAnalyticsSummary,
)


class ThreatAnalyticsView(tk.Frame):
    """Unified threat correlation and analytics console."""

    def __init__(
        self,
        master: tk.Misc,
        engine: ThreatAnalyticsEngine | None = None,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.engine = engine or ThreatAnalyticsEngine()
        self.on_feedback = on_feedback

        self.last_summary: ThreatAnalyticsSummary | None = None

        self._build_layout()
        self.refresh_analytics()

    def _build_layout(self) -> None:
        """Construct the scrollable canvas container."""
        self.canvas = tk.Canvas(
            self,
            bg=BG_DARK,
            highlightthickness=0,
            relief="flat",
        )
        self.v_scrollbar = ttk.Scrollbar(
            self,
            orient=tk.VERTICAL,
            command=self.canvas.yview,
            style="Vertical.TScrollbar",
        )
        self.scroll_content = tk.Frame(self.canvas, bg=BG_DARK, padx=24, pady=20)
        self.scroll_content_id = self.canvas.create_window((0, 0), window=self.scroll_content, anchor=tk.NW)

        self.canvas.configure(xscrollcommand=None, yscrollcommand=self.v_scrollbar.set)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.scroll_content.bind("<Configure>", self._on_frame_configure)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 1. Header Card
        self._build_header(self.scroll_content)

        # 2. Dynamic Content Container
        self.content_container = tk.Frame(self.scroll_content, bg=BG_DARK)
        self.content_container.pack(fill=tk.BOTH, expand=True)

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfig(self.scroll_content_id, width=event.width)

    def _on_frame_configure(self, event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _build_header(self, parent: tk.Widget) -> None:
        """Header card with briefing and refresh action."""
        hdr = CardFrame(parent, padx=20, pady=16)
        hdr.pack(fill=tk.X, pady=(0, 16))

        top_row = tk.Frame(hdr, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        title_lbl = tk.Label(
            top_row,
            text="THREAT ANALYTICS & CORRELATION",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(side=tk.LEFT)

        btn_row = tk.Frame(top_row, bg=BG_CARD)
        btn_row.pack(side=tk.RIGHT)

        self.btn_refresh = tk.Button(
            btn_row,
            text="⚡ Recalculate Metrics",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.refresh_analytics,
        )
        self.btn_refresh.pack(side=tk.LEFT)

        desc_lbl = tk.Label(
            hdr,
            text=(
                "Unified threat analytics aggregating real forensic telemetry from File Integrity, "
                "URL Heuristics, Network Telemetry, and Security Scans. Categorizes incidents by CVSS "
                "severity and provides multi-factor threat correlation without invented data."
            ),
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=980,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(8, 0))

    def refresh_analytics(self) -> None:
        """Fetch consolidated metrics from the threat analytics engine."""
        summary = self.engine.compile_summary()
        self.last_summary = summary
        self._render_dashboard(summary)

        if self.on_feedback:
            self.on_feedback(f"Threat analytics updated: {summary.total_threats} threats, {summary.total_scans} scans compiled.")

    def _render_dashboard(self, summary: ThreatAnalyticsSummary) -> None:
        """Render metrics cards, severity breakdown, and findings table."""
        for child in self.content_container.winfo_children():
            child.destroy()

        # 1. 4-Grid Overview Cards
        grid_row = tk.Frame(self.content_container, bg=BG_DARK)
        grid_row.pack(fill=tk.X, pady=(0, 14))

        for col_idx in range(4):
            grid_row.columnconfigure(col_idx, weight=1, uniform="stat_cards")

        self._render_stat_card(grid_row, 0, "TOTAL SCANS", str(summary.total_scans), "Security Audits", ACCENT_SECONDARY)
        crit_high = summary.threats_by_severity.get("CRITICAL", 0) + summary.threats_by_severity.get("HIGH", 0)
        self._render_stat_card(grid_row, 1, "ACTIVE THREATS", str(crit_high), "Critical / High", COLOR_DANGER)
        self._render_stat_card(grid_row, 2, "FILE BASELINES", str(summary.file_integrity_stats.get("total_baselines", 0)), "SHA-256 Hashes", COLOR_SUCCESS)
        self._render_stat_card(grid_row, 3, "EVALUATED URLS", str(summary.url_risk_stats.get("total_analyzed", 0)), "Heuristic Checks", "#38bdf8")

        # 2. Severity Distribution Bar Card
        bar_card = CardFrame(self.content_container, padx=20, pady=16)
        bar_card.pack(fill=tk.X, pady=(0, 14))

        b_title = tk.Label(
            bar_card,
            text="THREAT SEVERITY DISTRIBUTION (CVSS)",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        b_title.pack(anchor=tk.W, pady=(0, 10))

        crit = summary.threats_by_severity.get("CRITICAL", 0)
        high = summary.threats_by_severity.get("HIGH", 0)
        med = summary.threats_by_severity.get("MEDIUM", 0)
        low = summary.threats_by_severity.get("LOW", 0)

        chips_row = tk.Frame(bar_card, bg=BG_CARD)
        chips_row.pack(fill=tk.X, pady=(0, 10))

        self._add_badge_chip(chips_row, f"Critical: {crit}", "#7f1d1d", COLOR_DANGER)
        self._add_badge_chip(chips_row, f"High: {high}", "#7c2d12", "#ea580c")
        self._add_badge_chip(chips_row, f"Medium: {med}", "#78350f", COLOR_WARNING)
        self._add_badge_chip(chips_row, f"Low: {low}", "#064e3b", COLOR_SUCCESS)

        # Progress bar
        total_sev = max(1, crit + high + med + low)
        canvas_bar = tk.Canvas(bar_card, height=12, bg=BG_INPUT, highlightthickness=0, relief="flat")
        canvas_bar.pack(fill=tk.X)
        self.canvas_bar = canvas_bar

        def _draw_sev(event: tk.Event) -> None:
            canvas_bar.delete("all")
            w = event.width if hasattr(event, "width") and event.width is not None else canvas_bar.winfo_width()
            h = event.height if hasattr(event, "height") and event.height is not None else canvas_bar.winfo_height()
            if w <= 1:
                return
            x = 0
            for count, col in [(crit, COLOR_DANGER), (high, "#ea580c"), (med, COLOR_WARNING), (low, COLOR_SUCCESS)]:
                seg_w = int((count / total_sev) * w)
                if seg_w > 0:
                    canvas_bar.create_rectangle(x, 0, x + seg_w, h, fill=col, outline="")
                    x += seg_w

        canvas_bar.draw_sev = _draw_sev  # type: ignore[attr-defined]
        canvas_bar.bind("<Configure>", _draw_sev)

        # 3. Recent Security Findings Table Card
        table_card = CardFrame(self.content_container, padx=16, pady=16)
        table_card.pack(fill=tk.BOTH, expand=True)

        t_title = tk.Label(
            table_card,
            text="RECENT THREAT FINDINGS & INCIDENTS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        t_title.pack(anchor=tk.W, pady=(0, 10))

        tree_frame = tk.Frame(table_card, bg=BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("id", "type", "severity", "desc", "time")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=min(10, max(5, len(summary.recent_findings))),
            selectmode="browse",
        )

        self.tree.heading("id", text="LOG ID")
        self.tree.heading("type", text="THREAT TYPE")
        self.tree.heading("severity", text="SEVERITY")
        self.tree.heading("desc", text="DESCRIPTION / TARGET")
        self.tree.heading("time", text="TIMESTAMP")

        self.tree.column("id", width=80, anchor=tk.W)
        self.tree.column("type", width=160, anchor=tk.W)
        self.tree.column("severity", width=90, anchor=tk.CENTER)
        self.tree.column("desc", width=380, anchor=tk.W)
        self.tree.column("time", width=150, anchor=tk.W)

        self.tree.tag_configure("CRITICAL", foreground=COLOR_DANGER)
        self.tree.tag_configure("HIGH", foreground="#ea580c")
        self.tree.tag_configure("MEDIUM", foreground=COLOR_WARNING)
        self.tree.tag_configure("LOW", foreground=COLOR_SUCCESS)
        self.tree.tag_configure("INFO", foreground=TEXT_MUTED)

        for item in summary.recent_findings:
            sev = item.get("severity") or item.get("risk_level") or "INFO"
            tag = sev.upper() if sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "INFO"
            self.tree.insert(
                "",
                tk.END,
                values=(
                    str(item.get("id", "N/A"))[:12],
                    item.get("threat_type") or item.get("scan_type") or "EVENT",
                    sev,
                    item.get("description") or item.get("target") or item.get("result") or "N/A",
                    item.get("created_at", "N/A"),
                ),
                tags=(tag,),
            )

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

    def _render_stat_card(
        self,
        parent: tk.Widget,
        column: int,
        title: str,
        value: str,
        subtitle: str,
        val_color: str,
    ) -> None:
        """Render a single modular metric card in grid."""
        card = CardFrame(parent, padx=14, pady=12)
        card.grid(row=0, column=column, sticky="nsew", padx=4)

        t_lbl = tk.Label(card, text=title, font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED)
        t_lbl.pack(anchor=tk.W)

        v_lbl = tk.Label(card, text=value, font=FONT_METRIC, bg=BG_CARD, fg=val_color)
        v_lbl.pack(anchor=tk.W, pady=(2, 0))

        sub_lbl = tk.Label(card, text=subtitle, font=FONT_CAPTION, bg=BG_CARD, fg=TEXT_DIMMED)
        sub_lbl.pack(anchor=tk.W)

    def _add_badge_chip(self, parent: tk.Widget, text: str, bg: str, fg: str) -> None:
        """Add status chip."""
        lbl = tk.Label(
            parent,
            text=text,
            font=FONT_CAPTION_BOLD,
            bg=bg,
            fg=fg,
            padx=10,
            pady=4,
        )
        lbl.pack(side=tk.LEFT, padx=(0, 8))

