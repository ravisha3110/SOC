"""CyberShield Authentication View.

Provides interactive Login and Registration interfaces adhering to the CyberShield dark SOC theme.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from frontend.components import CardFrame
from frontend.theme import (
    ACCENT_MUTED,
    ACCENT_PRIMARY,
    ACCENT_SECONDARY,
    BG_CARD,
    BG_DARK,
    BG_INPUT,
    BORDER_FOCUS,
    BORDER_SUBTLE,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_WARNING,
    FONT_BADGE,
    FONT_BODY,
    FONT_BODY_BOLD,
    FONT_BUTTON,
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
from security.auth import AuthService, Role, Session


class AuthView(tk.Frame):
    """Modern dark SOC authentication card supporting Login and Registration."""

    def __init__(
        self,
        master: tk.Misc,
        auth_service: AuthService,
        on_login_success: Callable[[Session], None],
        on_feedback: Callable[[str], None] | None = None,
        enable_demo_logins: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.auth_service = auth_service
        self.on_login_success = on_login_success
        self.on_feedback = on_feedback
        self.enable_demo_logins = enable_demo_logins

        self.mode = "login"  # "login" or "register"
        self._password_masked = True

        self._build_ui()

    def _build_ui(self) -> None:
        # Centering outer frame
        center_frame = tk.Frame(self, bg=BG_DARK)
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Main Authentication Card
        self.card = CardFrame(center_frame, padx=32, pady=28, highlightbackground=BORDER_SUBTLE)
        self.card.pack(fill=tk.BOTH, expand=True)

        # Shield Icon & SOC Branding
        logo_label = tk.Label(
            self.card,
            text="🛡️ CYBERSHIELD SOC",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
        )
        logo_label.pack(pady=(0, 4))

        sub_label = tk.Label(
            self.card,
            text="Secure Threat Workstation • Access Control",
            font=FONT_CAPTION,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        sub_label.pack(pady=(0, 20))

        # Mode Selector Buttons (LOGIN / REGISTER Tabs)
        tab_frame = tk.Frame(self.card, bg=BG_CARD)
        tab_frame.pack(fill=tk.X, pady=(0, 16))
        tab_frame.grid_columnconfigure((0, 1), weight=1)

        self.btn_tab_login = tk.Button(
            tab_frame,
            text="LOGIN",
            font=FONT_BUTTON,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            relief="flat",
            bd=0,
            pady=6,
            cursor="hand2",
            command=lambda: self.switch_mode("login"),
        )
        self.btn_tab_login.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.btn_tab_register = tk.Button(
            tab_frame,
            text="REGISTER",
            font=FONT_BUTTON,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            relief="flat",
            bd=0,
            pady=6,
            cursor="hand2",
            command=lambda: self.switch_mode("register"),
        )
        self.btn_tab_register.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # Form Fields Frame
        form_frame = tk.Frame(self.card, bg=BG_CARD)
        form_frame.pack(fill=tk.X)

        # 1. Username
        tk.Label(
            form_frame,
            text="USERNAME",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(anchor=tk.W, pady=(0, 4))

        self.entry_username = tk.Entry(
            form_frame,
            font=FONT_BODY,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_SUBTLE,
            highlightcolor=BORDER_FOCUS,
            width=32,
        )
        self.entry_username.pack(fill=tk.X, ipady=6, pady=(0, 12))

        # 2. Password
        tk.Label(
            form_frame,
            text="PASSWORD",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(anchor=tk.W, pady=(0, 4))

        pw_row = tk.Frame(form_frame, bg=BG_CARD)
        pw_row.pack(fill=tk.X, pady=(0, 12))

        self.entry_password = tk.Entry(
            pw_row,
            font=FONT_BODY,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_SUBTLE,
            highlightcolor=BORDER_FOCUS,
            show="•",
            width=26,
        )
        self.entry_password.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)

        self.btn_toggle_pw = tk.Button(
            pw_row,
            text="👁",
            font=FONT_BODY,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=8,
            cursor="hand2",
            command=self._toggle_password_mask,
        )
        self.btn_toggle_pw.pack(side=tk.LEFT, padx=(4, 0))

        # 3. Role Selector (Visible only in register mode)
        self.role_frame = tk.Frame(form_frame, bg=BG_CARD)
        tk.Label(
            self.role_frame,
            text="ROLE ASSIGNMENT",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(anchor=tk.W, pady=(0, 4))

        self.role_var = tk.StringVar(value="analyst")
        self.combo_role = ttk.Combobox(
            self.role_frame,
            textvariable=self.role_var,
            values=["analyst", "viewer", "administrator"],
            state="readonly",
            font=FONT_BODY,
        )
        self.combo_role.pack(fill=tk.X, ipady=4, pady=(0, 12))

        # Alert Message Banner
        self.lbl_alert = tk.Label(
            self.card,
            text="",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=COLOR_DANGER,
            wraplength=300,
        )
        self.lbl_alert.pack(fill=tk.X, pady=(0, 10))

        # Action Submit Button
        self.btn_submit = tk.Button(
            self.card,
            text="AUTHENTICATE & ENTER SOC",
            font=FONT_BUTTON,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            activebackground=ACCENT_SECONDARY,
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            pady=10,
            cursor="hand2",
            command=self._handle_submit,
        )
        self.btn_submit.pack(fill=tk.X, pady=(0, 16))

        # Quick Demo Login Section for Rapid Academic Viva Evaluation
        if self.enable_demo_logins:
            demo_sep = tk.Label(
                self.card,
                text="── QUICK DEMO ROLES (EVALUATION) ──",
                font=FONT_BADGE,
                bg=BG_CARD,
                fg=TEXT_DIMMED,
            )
            demo_sep.pack(pady=(4, 8))

            demo_btns_row = tk.Frame(self.card, bg=BG_CARD)
            demo_btns_row.pack(fill=tk.X)
            demo_btns_row.grid_columnconfigure((0, 1, 2), weight=1)

            b_admin = tk.Button(
                demo_btns_row,
                text="Admin",
                font=FONT_BADGE,
                bg="#2A1B4E",
                fg=ACCENT_SECONDARY,
                relief="flat",
                bd=0,
                pady=4,
                cursor="hand2",
                command=lambda: self._quick_demo_login("admin_demo", Role.ADMINISTRATOR),
            )
            b_admin.grid(row=0, column=0, sticky="ew", padx=2)

            b_analyst = tk.Button(
                demo_btns_row,
                text="Analyst",
                font=FONT_BADGE,
                bg="#1E2A38",
                fg="#38BDF8",
                relief="flat",
                bd=0,
                pady=4,
                cursor="hand2",
                command=lambda: self._quick_demo_login("analyst_demo", Role.ANALYST),
            )
            b_analyst.grid(row=0, column=1, sticky="ew", padx=2)

            b_viewer = tk.Button(
                demo_btns_row,
                text="Viewer",
                font=FONT_BADGE,
                bg="#1C2D27",
                fg=COLOR_SUCCESS,
                relief="flat",
                bd=0,
                pady=4,
                cursor="hand2",
                command=lambda: self._quick_demo_login("viewer_demo", Role.VIEWER),
            )
            b_viewer.grid(row=0, column=2, sticky="ew", padx=2)

        # Enter key binding
        self.entry_username.bind("<Return>", lambda e: self._handle_submit())
        self.entry_password.bind("<Return>", lambda e: self._handle_submit())

    def switch_mode(self, mode: str) -> None:
        """Switch between Login and Registration forms."""
        self.mode = mode
        self.lbl_alert.configure(text="")

        if mode == "login":
            self.btn_tab_login.configure(bg=ACCENT_PRIMARY, fg="#FFFFFF")
            self.btn_tab_register.configure(bg=BG_INPUT, fg=TEXT_MUTED)
            self.role_frame.pack_forget()
            self.btn_submit.configure(text="AUTHENTICATE & ENTER SOC")
        else:
            self.btn_tab_login.configure(bg=BG_INPUT, fg=TEXT_MUTED)
            self.btn_tab_register.configure(bg=ACCENT_PRIMARY, fg="#FFFFFF")
            self.role_frame.pack(fill=tk.X)
            self.btn_submit.configure(text="CREATE USER ACCOUNT")

    def _toggle_password_mask(self) -> None:
        """Toggle between password masking and plaintext display."""
        self._password_masked = not self._password_masked
        self.entry_password.configure(show="•" if self._password_masked else "")
        self.btn_toggle_pw.configure(text="👁" if self._password_masked else "🙈")

    def _handle_submit(self) -> None:
        """Handle Login or Registration submission."""
        username = self.entry_username.get().strip()
        password = self.entry_password.get()

        if self.mode == "login":
            success, message, session = self.auth_service.authenticate_user(username, password)
            if success and session:
                self.lbl_alert.configure(text="")
                if self.on_feedback:
                    self.on_feedback(f"Welcome {session.username} ({session.role.value.upper()})")
                self.on_login_success(session)
            else:
                self.lbl_alert.configure(text=f"⚠️ {message}", fg=COLOR_DANGER)
        else:
            role_choice = self.role_var.get()
            success, message, created = self.auth_service.register_user(
                username=username,
                password=password,
                role=role_choice,
            )
            if success and created:
                self.lbl_alert.configure(text="Account created! Logging in...", fg=COLOR_SUCCESS)
                # Automatically authenticate new user
                _, _, session = self.auth_service.authenticate_user(username, password)
                if session:
                    self.on_login_success(session)
            else:
                self.lbl_alert.configure(text=f"⚠️ {message}", fg=COLOR_DANGER)

    def _quick_demo_login(self, username: str, role: Role) -> None:
        """Rapid helper for evaluation viva to authenticate as a given role."""
        # Ensure user exists in repository
        pw = "DemoPassword2026!"
        self.auth_service.register_user(username, pw, role=role)
        success, _, session = self.auth_service.authenticate_user(username, pw)
        if success and session:
            if self.on_feedback:
                self.on_feedback(f"Demo login successful as {role.value.upper()}")
            self.on_login_success(session)
