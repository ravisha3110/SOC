"""URL Security Analyzer Desktop View.

Integrates heuristic risk scoring, phishing pattern detection, and formal
Deterministic Finite Automaton (DFA) syntactic grammar validation into the SOC interface.
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
from security.url_analyzer import (
    URLAnalysisResult,
    URLRiskLevel,
    URLSecurityAnalyzer,
)


class URLSecurityView(tk.Frame):
    """Interactive desktop screen for analyzing URLs with heuristics and DFA grammar."""

    def __init__(
        self,
        master: tk.Misc,
        analyzer: URLSecurityAnalyzer | None = None,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.analyzer = analyzer or URLSecurityAnalyzer()
        self.on_feedback = on_feedback

        self.url_var = tk.StringVar(value="")
        self.last_result: URLAnalysisResult | None = None

        self._build_layout()

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

        # 2. Input Panel Card
        self._build_input_panel(self.scroll_content)

        # 3. Dynamic Results Container
        self.results_container = tk.Frame(self.scroll_content, bg=BG_DARK)
        self.results_container.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

        # Initial Empty State
        self._render_empty_state()

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfig(self.scroll_content_id, width=event.width)

    def _on_frame_configure(self, event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _build_header(self, parent: tk.Widget) -> None:
        """Render introductory header card with security notices."""
        hdr = CardFrame(parent, padx=20, pady=16)
        hdr.pack(fill=tk.X, pady=(0, 16))

        top_row = tk.Frame(hdr, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        title_lbl = tk.Label(
            top_row,
            text="URL SECURITY ANALYZER",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(side=tk.LEFT)

        badge_lbl = tk.Label(
            top_row,
            text="DFA AUTOMATON & HEURISTIC ENGINE",
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
                "Inspect suspect web URLs for phishing techniques, credential harvesting patterns, "
                "and syntactic grammar anomalies. Implements a Deterministic Finite Automaton (DFA) "
                "for RFC 3986 formal language validation alongside multi-point heuristic risk scoring."
            ),
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=980,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(8, 0))

    def _build_input_panel(self, parent: tk.Widget) -> None:
        """Render URL input field and action buttons."""
        panel = CardFrame(parent, padx=20, pady=18)
        panel.pack(fill=tk.X)

        lbl = tk.Label(
            panel,
            text="URL INSPECTION TARGET",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        lbl.pack(anchor=tk.W, pady=(0, 8))

        row = tk.Frame(panel, bg=BG_CARD)
        row.pack(fill=tk.X, pady=(0, 4))

        # Input Entry Border
        border = tk.Frame(row, bg=BORDER_SUBTLE, padx=1, pady=1)
        border.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.entry_url = tk.Entry(
            border,
            textvariable=self.url_var,
            font=("Segoe UI", 12),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            bd=8,
        )
        self.entry_url.pack(fill=tk.X)
        self.entry_url.bind("<Return>", lambda event: self.run_analysis())

        # Analyze Button
        self.btn_analyze = tk.Button(
            row,
            text="⚡ Analyze URL",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=18,
            pady=7,
            cursor="hand2",
            command=self.run_analysis,
        )
        self.btn_analyze.pack(side=tk.LEFT, padx=(0, 8))

        # Clear Button
        self.btn_clear = tk.Button(
            row,
            text="🗑 Clear",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_MUTED,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
            command=self.clear_all,
        )
        self.btn_clear.pack(side=tk.LEFT)

    def run_analysis(self) -> None:
        """Execute heuristic assessment and DFA validation on entered URL."""
        raw_url = self.url_var.get().strip()
        if not raw_url:
            if self.on_feedback:
                self.on_feedback("Please enter a URL to analyze.")
            return

        result = self.analyzer.analyze(raw_url)
        self.last_result = result
        self._render_results(result)

        if self.on_feedback:
            self.on_feedback(f"URL analysis complete: Risk Level {result.risk_level.value} ({result.risk_score:.0f}/100)")

    def clear_all(self) -> None:
        """Reset input field and return to initial empty state."""
        self.url_var.set("")
        self.last_result = None
        self._render_empty_state()
        if self.on_feedback:
            self.on_feedback("URL analyzer reset.")

    def _render_empty_state(self) -> None:
        """Render instructional card when no URL has been entered."""
        for child in self.results_container.winfo_children():
            child.destroy()

        card = CardFrame(self.results_container, padx=24, pady=32)
        card.pack(fill=tk.BOTH, expand=True)

        icon_lbl = tk.Label(
            card,
            text="🌐",
            font=("Segoe UI", 32),
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
        )
        icon_lbl.pack(pady=(0, 10))

        title_lbl = tk.Label(
            card,
            text="Ready for URL Inspection",
            font=FONT_SUBTITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(pady=(0, 6))

        instructions = (
            "Enter any web link (e.g., https://example.com or a suspected phishing link) and click '⚡ Analyze URL'.\n"
            "The system evaluates the URL locally against RFC 3986 DFA grammar and flags suspicious heuristic markers."
        )
        inst_lbl = tk.Label(
            card,
            text=instructions,
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify=tk.CENTER,
            pady=8,
        )
        inst_lbl.pack()

    def _render_results(self, result: URLAnalysisResult) -> None:
        """Render score meter, DFA automaton state, indicators, and recommendations."""
        for child in self.results_container.winfo_children():
            child.destroy()

        # Color and label mappings for Risk Level
        level_styles = {
            URLRiskLevel.LOW: {"color": COLOR_SUCCESS, "bg": "#064e3b", "label": "LOW RISK"},
            URLRiskLevel.MODERATE: {"color": COLOR_WARNING, "bg": "#78350f", "label": "MODERATE RISK"},
            URLRiskLevel.HIGH: {"color": "#ea580c", "bg": "#7c2d12", "label": "HIGH RISK"},
            URLRiskLevel.CRITICAL: {"color": COLOR_DANGER, "bg": "#7f1d1d", "label": "CRITICAL RISK"},
        }
        style = level_styles.get(result.risk_level, level_styles[URLRiskLevel.LOW])

        # 1. Risk Score Overview Card
        score_card = CardFrame(self.results_container, padx=20, pady=16)
        score_card.pack(fill=tk.X, pady=(0, 14))

        sc_top = tk.Frame(score_card, bg=BG_CARD)
        sc_top.pack(fill=tk.X)

        score_lbl = tk.Label(
            sc_top,
            text=f"RISK SCORE: {result.risk_score:.0f} / 100",
            font=FONT_METRIC,
            bg=BG_CARD,
            fg=style["color"],
        )
        score_lbl.pack(side=tk.LEFT)

        level_badge = tk.Label(
            sc_top,
            text=style["label"],
            font=FONT_BODY_BOLD,
            bg=style["bg"],
            fg=style["color"],
            padx=12,
            pady=4,
        )
        level_badge.pack(side=tk.RIGHT)

        # Progress Meter Canvas
        self.meter_canvas = tk.Canvas(
            score_card,
            height=12,
            bg=BG_INPUT,
            highlightthickness=0,
            relief="flat",
        )
        self.meter_canvas.pack(fill=tk.X, pady=(12, 4))
        self.meter_canvas.bind("<Configure>", lambda e: self._draw_meter(result.risk_score, style["color"]))

        # 2. DFA Automaton Structural Validation Panel
        dfa_card = CardFrame(self.results_container, padx=20, pady=16)
        dfa_card.pack(fill=tk.X, pady=(0, 14))

        dfa_top = tk.Frame(dfa_card, bg=BG_CARD)
        dfa_top.pack(fill=tk.X, pady=(0, 8))

        dfa_title = tk.Label(
            dfa_top,
            text="DETERMINISTIC FINITE AUTOMATON (DFA) VALIDATION",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        dfa_title.pack(side=tk.LEFT)

        status_text = "ACCEPTED (RFC 3986 COMPLIANT)" if result.dfa_result.is_accepted else "REJECTED (SYNTAX ANOMALY)"
        status_fg = COLOR_SUCCESS if result.dfa_result.is_accepted else COLOR_DANGER
        status_bg = "#064e3b" if result.dfa_result.is_accepted else "#7f1d1d"

        dfa_badge = tk.Label(
            dfa_top,
            text=status_text,
            font=FONT_BADGE,
            bg=status_bg,
            fg=status_fg,
            padx=8,
            pady=2,
        )
        dfa_badge.pack(side=tk.RIGHT)

        # Traced state sequence
        seq_text = " → ".join(result.dfa_result.state_sequence[:8])
        if len(result.dfa_result.state_sequence) > 8:
            seq_text += f" ... → {result.dfa_result.final_state}"

        seq_box = tk.Frame(dfa_card, bg=BG_INPUT, padx=10, pady=8)
        seq_box.pack(fill=tk.X, pady=(0, 8))

        seq_lbl = tk.Label(
            seq_box,
            text=f"Automaton State Sequence:  {seq_text}",
            font=FONT_MONO_SMALL,
            bg=BG_INPUT,
            fg=ACCENT_SECONDARY,
            anchor=tk.W,
        )
        seq_lbl.pack(fill=tk.X)

        exp_lbl = tk.Label(
            dfa_card,
            text=result.dfa_result.explanation,
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=960,
            justify=tk.LEFT,
        )
        exp_lbl.pack(anchor=tk.W)

        # 3. Detected Risk Indicators Card
        ind_card = CardFrame(self.results_container, padx=20, pady=16)
        ind_card.pack(fill=tk.X, pady=(0, 14))

        ind_title = tk.Label(
            ind_card,
            text=f"DETECTED SECURITY INDICATORS ({len(result.indicators)})",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        ind_title.pack(anchor=tk.W, pady=(0, 10))

        for ind in result.indicators:
            item_row = tk.Frame(ind_card, bg=BG_CARD, pady=4)
            item_row.pack(fill=tk.X)

            sev_color = {
                "CRITICAL": COLOR_DANGER,
                "HIGH": "#ea580c",
                "MEDIUM": COLOR_WARNING,
                "LOW": COLOR_INFO,
                "INFO": TEXT_MUTED,
            }.get(ind.severity, TEXT_MUTED)

            chip = tk.Label(
                item_row,
                text=f"[{ind.severity}] +{ind.points}",
                font=FONT_BADGE,
                bg=BG_INPUT,
                fg=sev_color,
                padx=6,
                pady=2,
            )
            chip.pack(side=tk.LEFT, padx=(0, 10))

            detail_lbl = tk.Label(
                item_row,
                text=f"{ind.name}: {ind.description}",
                font=FONT_BODY,
                bg=BG_CARD,
                fg=TEXT_PRIMARY,
                wraplength=820,
                justify=tk.LEFT,
            )
            detail_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 4. Recommendations Card
        rec_card = CardFrame(self.results_container, padx=20, pady=16)
        rec_card.pack(fill=tk.X, pady=(0, 14))

        rec_title = tk.Label(
            rec_card,
            text="ACTIONABLE PRECAUTIONS & RECOMMENDATIONS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        rec_title.pack(anchor=tk.W, pady=(0, 8))

        for rec in result.recommendations:
            bullet_lbl = tk.Label(
                rec_card,
                text=f"•  {rec}",
                font=FONT_BODY,
                bg=BG_CARD,
                fg=TEXT_SECONDARY,
                wraplength=940,
                justify=tk.LEFT,
                pady=2,
            )
            bullet_lbl.pack(anchor=tk.W)

        # 5. Academic Disclaimer Card
        disc_card = CardFrame(self.results_container, padx=16, pady=12)
        disc_card.pack(fill=tk.X)

        disc_lbl = tk.Label(
            disc_card,
            text=f"Notice: {result.disclaimer}",
            font=FONT_CAPTION,
            bg=BG_CARD,
            fg=TEXT_DIMMED,
            wraplength=960,
            justify=tk.LEFT,
        )
        disc_lbl.pack(anchor=tk.W)

    def _draw_meter(self, score: float, fill_color: str) -> None:
        """Render color-coded bar in meter canvas."""
        self.meter_canvas.delete("all")
        width = self.meter_canvas.winfo_width()
        height = self.meter_canvas.winfo_height()
        if width <= 1:
            return

        fill_width = int((score / 100.0) * width)
        if fill_width > 0:
            self.meter_canvas.create_rectangle(
                0,
                0,
                fill_width,
                height,
                fill=fill_color,
                outline="",
            )

