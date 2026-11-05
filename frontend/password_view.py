"""CyberShield Password Security Analyzer GUI View.

Provides an interactive Tkinter/ttk desktop interface for credential resilience evaluation:
- Masked password input with interactive Show/Hide toggle
- Direct in-memory invocation of Phase 4A PasswordAnalyzer
- Real-time visual strength tier indicator (VERY_WEAK to VERY_STRONG)
- Numerical score meter (0–100) with color-coded visual progress
- Character diversity indicators (Lowercase, Uppercase, Digits, Symbols)
- Empirical Shannon entropy and theoretical character-pool entropy diagnostics
- Detected structural patterns and dictionary matching indicators
- Actionable recommendations for password strengthening

Zero Credential Retention:
- Passwords are never saved, logged, or sent over network/database layers.
- Clear action wipes input and resets state immediately.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

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
    COLOR_OFFLINE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    FONT_BADGE,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_CAPTION,
    FONT_CAPTION_BOLD,
    FONT_FAMILY,
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
from security.password_analyzer import (
    PasswordAnalysisResult,
    PasswordAnalyzer,
    PasswordStrength,
)


STRENGTH_COLORS: dict[str, str] = {
    PasswordStrength.VERY_WEAK.value: COLOR_DANGER,
    PasswordStrength.WEAK.value: COLOR_WARNING,
    PasswordStrength.MODERATE: COLOR_INFO,
    PasswordStrength.STRONG.value: ACCENT_SECONDARY,
    PasswordStrength.VERY_STRONG.value: COLOR_SUCCESS,
}


class PasswordSecurityView(tk.Frame):
    """Interactive Password Security Analyzer View."""

    def __init__(
        self,
        master: tk.Misc,
        analyzer: PasswordAnalyzer | None = None,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.analyzer = analyzer or PasswordAnalyzer()
        self.on_feedback = on_feedback

        self.password_var = tk.StringVar(value="")
        self.is_password_visible = False
        self.last_result: PasswordAnalysisResult | None = None

        self._build_layout()

    def _build_layout(self) -> None:
        """Construct the scrollable desktop interface."""
        # Scrollable canvas setup matching Dashboard view
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

        # 2. Input & Controls Card
        self._build_input_panel(self.scroll_content)

        # 3. Dynamic Results Container (toggled on analyze)
        self.results_container = tk.Frame(self.scroll_content, bg=BG_DARK)
        self.results_container.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

        # Show clean initial placeholder
        self._render_empty_results_state()

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfig(self.scroll_content_id, width=event.width)

    def _on_frame_configure(self, event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _build_header(self, parent: tk.Widget) -> None:
        """Render page title and introductory briefing card."""
        header_card = CardFrame(parent, padx=20, pady=16)
        header_card.pack(fill=tk.X, pady=(0, 16))

        title_row = tk.Frame(header_card, bg=BG_CARD)
        title_row.pack(fill=tk.X)

        title_lbl = tk.Label(
            title_row,
            text="🔑 Password Security Analyzer",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(side=tk.LEFT)

        status_badge = tk.Label(
            title_row,
            text="PHASE 4 // LOCAL ANALYSIS ENGINE",
            font=FONT_BADGE,
            bg=ACCENT_MUTED,
            fg=ACCENT_SECONDARY,
            padx=8,
            pady=3,
        )
        status_badge.pack(side=tk.RIGHT)

        desc_lbl = tk.Label(
            header_card,
            text=(
                "Evaluate credential resilience through multi-signal entropy calculation, "
                "local dictionary matching, keyboard-walk detection, and structural pattern recognition. "
                "Passwords are analyzed strictly in-memory and are never stored or transmitted."
            ),
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=960,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(8, 0))

    def _build_input_panel(self, parent: tk.Widget) -> None:
        """Render password input field, show/hide toggle, and action buttons."""
        self.input_card = CardFrame(parent, padx=20, pady=18)
        self.input_card.pack(fill=tk.X)

        input_title = tk.Label(
            self.input_card,
            text="CREDENTIAL INSPECTION INPUT",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        input_title.pack(anchor=tk.W, pady=(0, 8))

        # Input Row
        input_row = tk.Frame(self.input_card, bg=BG_CARD)
        input_row.pack(fill=tk.X, pady=(0, 8))

        entry_border = tk.Frame(input_row, bg=BORDER_SUBTLE, padx=1, pady=1)
        entry_border.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.password_entry = tk.Entry(
            entry_border,
            textvariable=self.password_var,
            show="•",
            font=(FONT_FAMILY, 12),
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            bd=8,
        )
        self.password_entry.pack(fill=tk.X)
        self.password_entry.bind("<Return>", self._on_entry_return)

        # Toggle Button
        self.toggle_btn = tk.Button(
            input_row,
            text="👁 Show",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_SECONDARY,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
            command=self.toggle_password_visibility,
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Analyze Button
        self.analyze_btn = tk.Button(
            input_row,
            text="⚡ Analyze Password",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=16,
            pady=7,
            cursor="hand2",
            command=self.run_analysis,
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Clear Button
        self.clear_btn = tk.Button(
            input_row,
            text="✕ Clear",
            font=FONT_BODY,
            bg=BG_CARD_HOVER,
            fg=TEXT_MUTED,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
            command=self.clear_input,
        )
        self.clear_btn.pack(side=tk.LEFT)

        # Validation message row
        self.validation_lbl = tk.Label(
            self.input_card,
            text="",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=COLOR_WARNING,
        )
        self.validation_lbl.pack(anchor=tk.W)

    def _render_empty_results_state(self) -> None:
        """Display helpful placeholder instructions when no analysis has run."""
        for child in self.results_container.winfo_children():
            child.destroy()

        empty_card = CardFrame(self.results_container, padx=24, pady=32)
        empty_card.pack(fill=tk.X)

        icon_lbl = tk.Label(
            empty_card,
            text="🛡️",
            font=(FONT_FAMILY, 32),
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        icon_lbl.pack(pady=(0, 8))

        title_lbl = tk.Label(
            empty_card,
            text="No Password Analyzed Yet",
            font=FONT_SUBTITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack()

        subtitle_lbl = tk.Label(
            empty_card,
            text="Enter a credential above and click 'Analyze Password' to calculate entropy and detect weaknesses.",
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        subtitle_lbl.pack(pady=(4, 0))

    def _on_entry_return(self, event: tk.Event | None = None) -> None:
        """Handle Return/Enter keypress in the password entry field."""
        self.run_analysis()

    def run_analysis(self) -> None:
        """Execute password analysis safely using local PasswordAnalyzer."""
        raw_input = self.password_var.get()

        if not raw_input:
            self.validation_lbl.configure(
                text="⚠️ Please enter a password before analyzing.",
                fg=COLOR_WARNING,
            )
            self._render_empty_results_state()
            if self.on_feedback:
                self.on_feedback("Password analysis halted: Input field is empty.")
            return

        self.validation_lbl.configure(text="")

        try:
            self.last_result = self.analyzer.analyze(raw_input)
            self._render_analysis_results(self.last_result)
            if self.on_feedback:
                self.on_feedback(
                    f"Analyzed password: {self.last_result.strength} (Score: {self.last_result.score}/100)"
                )
        except Exception as exc:
            self.validation_lbl.configure(
                text=f"Analysis error encountered: {type(exc).__name__}",
                fg=COLOR_DANGER,
            )
        finally:
            del raw_input

    def toggle_password_visibility(self) -> None:
        """Toggle entry show character between hidden bullet and plaintext."""
        self.is_password_visible = not self.is_password_visible
        if self.is_password_visible:
            self.password_entry.configure(show="")
            self.toggle_btn.configure(text="🙈 Hide")
        else:
            self.password_entry.configure(show="•")
            self.toggle_btn.configure(text="👁 Show")

    def clear_input(self) -> None:
        """Clear password input and reset the results container cleanly."""
        self.password_var.set("")
        self.validation_lbl.configure(text="")
        self.last_result = None
        self._render_empty_results_state()
        if self.on_feedback:
            self.on_feedback("Password input and analysis metrics cleared.")

    def _render_analysis_results(self, result: PasswordAnalysisResult) -> None:
        """Render all analytical metrics and diagnostic panels."""
        for child in self.results_container.winfo_children():
            child.destroy()

        # -------------------------------------------------------------
        # Section A: Primary Strength Banner & Score Bar Card
        # -------------------------------------------------------------
        banner_card = CardFrame(self.results_container, padx=20, pady=16)
        banner_card.pack(fill=tk.X, pady=(0, 16))

        top_row = tk.Frame(banner_card, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        # Left: Strength label and badge
        badge_color = STRENGTH_COLORS.get(result.strength, TEXT_MUTED)
        badge_frame = tk.Frame(top_row, bg=BG_CARD)
        badge_frame.pack(side=tk.LEFT)

        strength_title = tk.Label(
            badge_frame,
            text="STRENGTH CLASSIFICATION",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        strength_title.pack(anchor=tk.W)

        self.strength_badge = tk.Label(
            badge_frame,
            text=f"  {result.strength.replace('_', ' ')}  ",
            font=FONT_TITLE,
            bg=badge_color,
            fg="#000000" if result.strength in (PasswordStrength.VERY_STRONG.value, PasswordStrength.MODERATE) else TEXT_PRIMARY,
            padx=10,
            pady=4,
        )
        self.strength_badge.pack(anchor=tk.W, pady=(4, 0))

        # Right: Numerical Score
        score_frame = tk.Frame(top_row, bg=BG_CARD)
        score_frame.pack(side=tk.RIGHT)

        score_title = tk.Label(
            score_frame,
            text="SECURITY SCORE",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        score_title.pack(anchor=tk.E)

        self.score_lbl = tk.Label(
            score_frame,
            text=f"{result.score} / 100",
            font=FONT_METRIC,
            bg=BG_CARD,
            fg=badge_color,
        )
        self.score_lbl.pack(anchor=tk.E)

        # Score Visual Progress Meter
        progress_bg = tk.Frame(banner_card, bg=BORDER_SUBTLE, height=10)
        progress_bg.pack(fill=tk.X, pady=(14, 4))
        progress_bg.pack_propagate(False)

        fill_width_factor = max(0.01, min(1.0, result.score / 100.0))
        progress_fill = tk.Frame(progress_bg, bg=badge_color)
        progress_fill.place(relx=0, rely=0, relwidth=fill_width_factor, relheight=1.0)

        # -------------------------------------------------------------
        # Section B: 3 Diagnostic Cards (Length, Diversity, Entropy)
        # -------------------------------------------------------------
        metrics_row = tk.Frame(self.results_container, bg=BG_DARK)
        metrics_row.pack(fill=tk.X, pady=(0, 16))
        metrics_row.grid_columnconfigure((0, 1, 2), weight=1, uniform="diag_cards")

        # Card 1: Length Evaluation
        c1 = CardFrame(metrics_row, padx=16, pady=14)
        c1.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        tk.Label(c1, text="PASSWORD LENGTH", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)
        self.length_lbl = tk.Label(c1, text=f"{result.length} characters", font=FONT_SUBTITLE, bg=BG_CARD, fg=TEXT_PRIMARY)
        self.length_lbl.pack(anchor=tk.W, pady=(4, 4))

        if result.length >= 12:
            len_status = "✓ Meets Recommended (≥12)"
            len_fg = COLOR_SUCCESS
        elif result.length >= 8:
            len_status = "⚠️ Acceptable Minimum (8–11)"
            len_fg = COLOR_WARNING
        else:
            len_status = "✕ Excessively Short (<8)"
            len_fg = COLOR_DANGER

        tk.Label(c1, text=len_status, font=FONT_CAPTION, bg=BG_CARD, fg=len_fg).pack(anchor=tk.W)

        # Card 2: Diversity Breakdown
        c2 = CardFrame(metrics_row, padx=16, pady=14)
        c2.grid(row=0, column=1, sticky="nsew", padx=4)

        tk.Label(c2, text="CHARACTER DIVERSITY", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)
        self.diversity_lbl = tk.Label(c2, text=f"{result.character_diversity} of 4 classes", font=FONT_SUBTITLE, bg=BG_CARD, fg=TEXT_PRIMARY)
        self.diversity_lbl.pack(anchor=tk.W, pady=(4, 6))

        cats_row = tk.Frame(c2, bg=BG_CARD)
        cats_row.pack(fill=tk.X)

        cat_names = [
            ("lowercase", "a-z"),
            ("uppercase", "A-Z"),
            ("digits", "0-9"),
            ("symbols", "!@#$"),
        ]
        for key, label in cat_names:
            is_present = result.character_categories.get(key, False)
            cat_tag = tk.Label(
                cats_row,
                text=f"{'✓' if is_present else '✕'} {label}",
                font=FONT_BADGE,
                bg=BG_CARD_HOVER if is_present else BG_INPUT,
                fg=COLOR_SUCCESS if is_present else TEXT_DIMMED,
                padx=6,
                pady=2,
            )
            cat_tag.pack(side=tk.LEFT, padx=(0, 4))

        # Card 3: Entropy Metrics
        c3 = CardFrame(metrics_row, padx=16, pady=14)
        c3.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

        tk.Label(c3, text="ENTROPY ESTIMATES", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)

        ent_grid = tk.Frame(c3, bg=BG_CARD)
        ent_grid.pack(fill=tk.X, pady=(4, 4))

        tk.Label(ent_grid, text="Shannon Entropy:", font=FONT_CAPTION, bg=BG_CARD, fg=TEXT_SECONDARY).grid(row=0, column=0, sticky=tk.W)
        self.shannon_lbl = tk.Label(ent_grid, text=f"{result.shannon_entropy_bits:.2f} bits", font=FONT_MONO_SMALL, bg=BG_CARD, fg=ACCENT_SECONDARY)
        self.shannon_lbl.grid(row=0, column=1, sticky=tk.E, padx=(6, 0))

        tk.Label(ent_grid, text="Pool Search Space:", font=FONT_CAPTION, bg=BG_CARD, fg=TEXT_SECONDARY).grid(row=1, column=0, sticky=tk.W)
        self.pool_lbl = tk.Label(ent_grid, text=f"{result.estimated_pool_entropy_bits:.2f} bits", font=FONT_MONO_SMALL, bg=BG_CARD, fg=TEXT_PRIMARY)
        self.pool_lbl.grid(row=1, column=1, sticky=tk.E, padx=(6, 0))

        tk.Label(
            c3,
            text="*Heuristic estimates; not cracking guarantees.",
            font=(FONT_FAMILY, 8),
            bg=BG_CARD,
            fg=TEXT_MUTED,
        ).pack(anchor=tk.W)

        # -------------------------------------------------------------
        # Section C: Detected Vulnerability Patterns & Dictionary Status
        # -------------------------------------------------------------
        patterns_card = CardFrame(self.results_container, padx=20, pady=16)
        patterns_card.pack(fill=tk.X, pady=(0, 16))

        tk.Label(
            patterns_card,
            text="DETECTED STRUCTURAL PATTERNS & DICTIONARY STATUS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(0, 8))

        dict_row = tk.Frame(patterns_card, bg=BG_CARD)
        dict_row.pack(fill=tk.X, pady=(0, 8))

        if result.dictionary_match:
            dict_badge_bg = COLOR_DANGER
            dict_badge_fg = TEXT_PRIMARY
            dict_text = "MATCH FOUND IN COMMON PASSWORD DICTIONARY"
        else:
            dict_badge_bg = BG_CARD_HOVER
            dict_badge_fg = COLOR_SUCCESS
            dict_text = "✓ No exact common dictionary match"

        self.dict_badge = tk.Label(
            dict_row,
            text=f"  {dict_text}  ",
            font=FONT_CAPTION_BOLD,
            bg=dict_badge_bg,
            fg=dict_badge_fg,
            pady=3,
        )
        self.dict_badge.pack(side=tk.LEFT)

        # Pattern list tags
        tags_frame = tk.Frame(patterns_card, bg=BG_CARD)
        tags_frame.pack(fill=tk.X)

        if not result.detected_patterns or (result.detected_patterns == ["empty_input"]):
            tk.Label(
                tags_frame,
                text="✓ No predictable structural patterns detected.",
                font=FONT_BODY,
                bg=BG_CARD,
                fg=COLOR_SUCCESS,
            ).pack(anchor=tk.W)
        else:
            tk.Label(
                tags_frame,
                text="Weakness Indicators:",
                font=FONT_CAPTION,
                bg=BG_CARD,
                fg=TEXT_SECONDARY,
            ).pack(anchor=tk.W, pady=(0, 4))

            tag_chips_frame = tk.Frame(tags_frame, bg=BG_CARD)
            tag_chips_frame.pack(fill=tk.X)

            for pattern in result.detected_patterns:
                chip = tk.Label(
                    tag_chips_frame,
                    text=f"⚠️ {pattern.replace('_', ' ').title()}",
                    font=FONT_BADGE,
                    bg=BG_CARD_HOVER,
                    fg=COLOR_WARNING,
                    padx=8,
                    pady=3,
                )
                chip.pack(side=tk.LEFT, padx=(0, 6), pady=2)

        # -------------------------------------------------------------
        # Section D: Actionable Recommendations
        # -------------------------------------------------------------
        recs_card = CardFrame(self.results_container, padx=20, pady=16)
        recs_card.pack(fill=tk.X)

        tk.Label(
            recs_card,
            text="RECOMMENDED SECURITY REMEDIATIONS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(0, 8))

        if not result.recommendations:
            tk.Label(
                recs_card,
                text="✓ Password meets current robust security standards.",
                font=FONT_BODY,
                bg=BG_CARD,
                fg=COLOR_SUCCESS,
            ).pack(anchor=tk.W)
        else:
            for rec in result.recommendations:
                rec_row = tk.Frame(recs_card, bg=BG_CARD)
                rec_row.pack(fill=tk.X, pady=2)
                bullet = tk.Label(rec_row, text="•", font=FONT_BODY_BOLD, bg=BG_CARD, fg=ACCENT_SECONDARY)
                bullet.pack(side=tk.LEFT, anchor=tk.N, padx=(0, 6))
                rec_text = tk.Label(
                    rec_row,
                    text=rec,
                    font=FONT_BODY,
                    bg=BG_CARD,
                    fg=TEXT_PRIMARY if result.strength in (PasswordStrength.STRONG.value, PasswordStrength.VERY_STRONG.value) else TEXT_SECONDARY,
                    wraplength=900,
                    justify=tk.LEFT,
                )
                rec_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
