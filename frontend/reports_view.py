"""Security Incident & Executive Reports Desktop View.

Enables SOC analysts to configure, preview, and export comprehensive CSV and
HTML incident reports from real database telemetry.
"""

from __future__ import annotations

import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk
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
    SecurityReport,
    ThreatAnalyticsEngine,
)


class ReportsView(tk.Frame):
    """Executive security reporting interface with CSV and HTML exports."""

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

        self.title_var = tk.StringVar(value="CyberShield SOC Executive Threat Assessment")
        self.analyst_var = tk.StringVar(value="Security Analyst (CyberShield Station)")
        self.current_report: SecurityReport | None = None

        self._build_layout()
        self.generate_and_preview()

    def _build_layout(self) -> None:
        """Construct scrollable container."""
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

        # 2. Config & Export Panel
        self._build_config_panel(self.scroll_content)

        # 3. Dynamic Preview Container
        self.preview_container = tk.Frame(self.scroll_content, bg=BG_DARK)
        self.preview_container.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfig(self.scroll_content_id, width=event.width)

    def _on_frame_configure(self, event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _build_header(self, parent: tk.Widget) -> None:
        """Header card with briefing and notices."""
        hdr = CardFrame(parent, padx=20, pady=16)
        hdr.pack(fill=tk.X, pady=(0, 16))

        top_row = tk.Frame(hdr, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        title_lbl = tk.Label(
            top_row,
            text="SECURITY AUDIT & EXECUTIVE REPORTS",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(side=tk.LEFT)

        badge_lbl = tk.Label(
            top_row,
            text="RFC 4180 CSV & RESPONSIVE HTML",
            font=FONT_BADGE,
            bg=ACCENT_MUTED,
            fg=ACCENT_SECONDARY,
            padx=8,
            pady=3,
        )
        badge_lbl.pack(side=tk.RIGHT)

        desc_lbl = tk.Label(
            hdr,
            text=(
                "Compile executive briefings and forensic finding tables directly from local database telemetry. "
                "Exports standalone HTML audit reports and structured CSV logs for regulatory documentation, "
                "academic viva presentations, and incident remediation."
            ),
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=980,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(8, 0))

    def _build_config_panel(self, parent: tk.Widget) -> None:
        """Render report title, analyst identity, and export actions."""
        panel = CardFrame(parent, padx=20, pady=16)
        panel.pack(fill=tk.X)

        sec_title = tk.Label(
            panel,
            text="REPORT CONFIGURATION & EXPORT CONTROLS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        sec_title.pack(anchor=tk.W, pady=(0, 10))

        # Inputs row
        inputs_row = tk.Frame(panel, bg=BG_CARD)
        inputs_row.pack(fill=tk.X, pady=(0, 12))

        # Title
        t_box = tk.Frame(inputs_row, bg=BG_CARD)
        t_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))
        tk.Label(t_box, text="Report Title:", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_SECONDARY).pack(anchor=tk.W, pady=(0, 4))
        t_border = tk.Frame(t_box, bg=BORDER_SUBTLE, padx=1, pady=1)
        t_border.pack(fill=tk.X)
        self.entry_title = tk.Entry(t_border, textvariable=self.title_var, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", bd=6)
        self.entry_title.pack(fill=tk.X)

        # Analyst
        a_box = tk.Frame(inputs_row, bg=BG_CARD)
        a_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(a_box, text="Lead Security Analyst:", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_SECONDARY).pack(anchor=tk.W, pady=(0, 4))
        a_border = tk.Frame(a_box, bg=BORDER_SUBTLE, padx=1, pady=1)
        a_border.pack(fill=tk.X)
        self.entry_analyst = tk.Entry(a_border, textvariable=self.analyst_var, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", bd=6)
        self.entry_analyst.pack(fill=tk.X)

        # Buttons row
        btn_row = tk.Frame(panel, bg=BG_CARD)
        btn_row.pack(fill=tk.X)

        self.btn_preview = tk.Button(
            btn_row,
            text="⚡ Refresh Preview",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.generate_and_preview,
        )
        self.btn_preview.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_export_html = tk.Button(
            btn_row,
            text="📄 Export HTML Report",
            font=FONT_BODY_BOLD,
            bg=COLOR_SUCCESS,
            fg=TEXT_PRIMARY,
            activebackground="#16a34a",
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.export_html_dialog,
        )
        self.btn_export_html.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_export_csv = tk.Button(
            btn_row,
            text="📊 Export CSV Logs",
            font=FONT_BODY_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_PRIMARY,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.export_csv_dialog,
        )
        self.btn_export_csv.pack(side=tk.LEFT)

    def generate_and_preview(self) -> None:
        """Compile live report and display preview."""
        title = self.title_var.get().strip() or "CyberShield SOC Executive Report"
        analyst = self.analyst_var.get().strip() or "Security Analyst"

        report = self.engine.generate_report(title=title, analyst_name=analyst)
        self.current_report = report
        self._render_preview(report)

        if self.on_feedback:
            self.on_feedback("Security report preview refreshed from current database state.")

    def export_html_dialog(self) -> None:
        """Prompt save dialog and write HTML report."""
        if not self.current_report:
            self.generate_and_preview()

        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Documents", "*.html"), ("All Files", "*.*")],
            initialfile="cybershield_executive_report.html",
            title="Export SOC Executive HTML Report",
        )
        if path:
            assert self.current_report is not None
            out = self.current_report.export_html_to_file(path)
            if self.on_feedback:
                self.on_feedback(f"HTML Report exported successfully to: {os.path.basename(out)}")

    def export_csv_dialog(self) -> None:
        """Prompt save dialog and write CSV findings report."""
        if not self.current_report:
            self.generate_and_preview()

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Tables", "*.csv"), ("All Files", "*.*")],
            initialfile="cybershield_threat_findings.csv",
            title="Export SOC Threat Findings CSV",
        )
        if path:
            assert self.current_report is not None
            out = self.current_report.export_csv_to_file(path)
            if self.on_feedback:
                self.on_feedback(f"CSV Report exported successfully to: {os.path.basename(out)}")

    def _render_preview(self, report: SecurityReport) -> None:
        """Render live report preview card."""
        for child in self.preview_container.winfo_children():
            child.destroy()

        card = CardFrame(self.preview_container, padx=20, pady=18)
        card.pack(fill=tk.BOTH, expand=True)

        # Header preview
        p_hdr = tk.Frame(card, bg=BG_CARD)
        p_hdr.pack(fill=tk.X, pady=(0, 10))

        tk.Label(p_hdr, text=report.title, font=FONT_SUBTITLE, bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor=tk.W)
        tk.Label(p_hdr, text=f"Analyst: {report.analyst_name}  •  Compiled: {report.generated_at}", font=FONT_CAPTION, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W, pady=(2, 0))

        # Metrics chips
        m_row = tk.Frame(card, bg=BG_CARD)
        m_row.pack(fill=tk.X, pady=(8, 12))

        crit_count = report.summary.threats_by_severity.get("CRITICAL", 0)
        high_count = report.summary.threats_by_severity.get("HIGH", 0)

        self._add_preview_chip(m_row, f"Scans: {report.summary.total_scans}", BG_INPUT, TEXT_PRIMARY)
        self._add_preview_chip(m_row, f"Threats: {report.summary.total_threats}", "#7f1d1d" if crit_count > 0 else BG_INPUT, COLOR_DANGER if crit_count > 0 else TEXT_PRIMARY)
        self._add_preview_chip(m_row, f"Critical/High: {crit_count + high_count}", "#7c2d12" if (crit_count + high_count) > 0 else BG_INPUT, "#ea580c" if (crit_count + high_count) > 0 else TEXT_MUTED)
        self._add_preview_chip(m_row, f"File Baselines: {report.summary.file_integrity_stats.get('total_baselines', 0)}", BG_INPUT, COLOR_SUCCESS)
        self._add_preview_chip(m_row, f"URLs Evaluated: {report.summary.url_risk_stats.get('total_analyzed', 0)}", BG_INPUT, "#38bdf8")

        # Recommendations preview
        rec_box = tk.Frame(card, bg=BG_INPUT, padx=14, pady=10)
        rec_box.pack(fill=tk.X, pady=(0, 12))

        tk.Label(rec_box, text="KEY REMEDIATION ACTIONS & PRECAUTIONS", font=FONT_CAPTION_BOLD, bg=BG_INPUT, fg=ACCENT_SECONDARY).pack(anchor=tk.W, pady=(0, 6))
        for r in report.recommendations:
            tk.Label(rec_box, text=f"•  {r}", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, wraplength=900, justify=tk.LEFT).pack(anchor=tk.W, pady=2)

        # Limitations footnote
        tk.Label(card, text=f"Notice: {report.limitations}", font=FONT_CAPTION, bg=BG_CARD, fg=TEXT_DIMMED, wraplength=920, justify=tk.LEFT).pack(anchor=tk.W)

    def _add_preview_chip(self, parent: tk.Widget, text: str, bg: str, fg: str) -> None:
        """Add chip badge to preview."""
        lbl = tk.Label(parent, text=text, font=FONT_CAPTION_BOLD, bg=bg, fg=fg, padx=10, pady=5)
        lbl.pack(side=tk.LEFT, padx=(0, 8))

