"""CyberShield Administrator User Management and RBAC View."""

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


class UserManagementView(tk.Frame):
    """Administrator console for inspecting and managing users, roles, and status."""

    def __init__(
        self,
        master: tk.Misc,
        auth_service: AuthService,
        current_session: Session,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.auth_service = auth_service
        self.current_session = current_session
        self.on_feedback = on_feedback

        self._build_ui()
        self.refresh_users()

    def _build_ui(self) -> None:
        # Header banner
        header_card = CardFrame(self, padx=20, pady=16)
        header_card.pack(fill=tk.X, padx=20, pady=(16, 12))

        tk.Label(
            header_card,
            text="👥 SOC USER & ACCESS CONTROL MANAGEMENT",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        ).pack(anchor=tk.W)

        tk.Label(
            header_card,
            text="Administer analyst credentials, enforce least-privilege RBAC roles, and control active sessions.",
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(4, 0))

        # Main Workspace Container (2 Columns: Left = User Table, Right = Management Actions)
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 16))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # 1. Left Column: Users Treeview Card
        table_card = CardFrame(body, padx=16, pady=16)
        table_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        tbl_hdr = tk.Frame(table_card, bg=BG_CARD)
        tbl_hdr.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            tbl_hdr,
            text="REGISTERED USERS & ROLES",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(side=tk.LEFT)

        self.btn_refresh = tk.Button(
            tbl_hdr,
            text="🔄 Refresh",
            font=FONT_CAPTION_BOLD,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self.refresh_users,
        )
        self.btn_refresh.pack(side=tk.RIGHT)

        # Treeview
        tree_frame = tk.Frame(table_card, bg=BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("id", "username", "role", "status", "created_at")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            selectmode="browse",
            style="Treeview",
        )
        self.tree.heading("id", text="User ID")
        self.tree.heading("username", text="Username")
        self.tree.heading("role", text="Assigned Role")
        self.tree.heading("status", text="Account Status")
        self.tree.heading("created_at", text="Registered At")

        self.tree.column("id", width=90, minwidth=70)
        self.tree.column("username", width=120, minwidth=100)
        self.tree.column("role", width=110, minwidth=90)
        self.tree.column("status", width=90, minwidth=80)
        self.tree.column("created_at", width=140, minwidth=120)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_user_selected)

        # 2. Right Column: User Management Controls Card
        ctrl_card = CardFrame(body, padx=16, pady=16)
        ctrl_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        tk.Label(
            ctrl_card,
            text="USER ACTION CONTROLS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(anchor=tk.W, pady=(0, 12))

        # Selected User Label
        self.lbl_selected_user = tk.Label(
            ctrl_card,
            text="Selected User: None",
            font=FONT_BODY_BOLD,
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
        )
        self.lbl_selected_user.pack(anchor=tk.W, pady=(0, 12))

        # Change Role Dropdown & Button
        tk.Label(ctrl_card, text="CHANGE ROLE", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W, pady=(0, 4))
        role_row = tk.Frame(ctrl_card, bg=BG_CARD)
        role_row.pack(fill=tk.X, pady=(0, 14))

        self.target_role_var = tk.StringVar(value="analyst")
        self.combo_target_role = ttk.Combobox(
            role_row,
            textvariable=self.target_role_var,
            values=["administrator", "analyst", "viewer"],
            state="readonly",
            font=FONT_BODY,
            width=14,
        )
        self.combo_target_role.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.btn_change_role = tk.Button(
            role_row,
            text="Apply Role",
            font=FONT_CAPTION_BOLD,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            relief="flat",
            bd=0,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._handle_change_role,
        )
        self.btn_change_role.pack(side=tk.LEFT, padx=(8, 0))

        # Toggle Active / Deactivate Button
        self.btn_toggle_status = tk.Button(
            ctrl_card,
            text="Deactivate Account",
            font=FONT_BODY_BOLD,
            bg="#2E1B0F",
            fg=COLOR_WARNING,
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._handle_toggle_status,
        )
        self.btn_toggle_status.pack(fill=tk.X, pady=(0, 10))

        # Delete User Button
        self.btn_delete_user = tk.Button(
            ctrl_card,
            text="Delete Account",
            font=FONT_BODY_BOLD,
            bg="#2E1111",
            fg=COLOR_DANGER,
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._handle_delete_user,
        )
        self.btn_delete_user.pack(fill=tk.X, pady=(0, 20))

        # Add New User Form Section
        tk.Label(ctrl_card, text="CREATE NEW USER", font=FONT_SECTION_HEADER, bg=BG_CARD, fg=TEXT_SECONDARY).pack(anchor=tk.W, pady=(0, 8))

        self.entry_new_user = tk.Entry(ctrl_card, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat")
        self.entry_new_user.pack(fill=tk.X, ipady=4, pady=(0, 6))
        self.entry_new_user.insert(0, "New Username")

        self.entry_new_pass = tk.Entry(ctrl_card, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", show="•")
        self.entry_new_pass.pack(fill=tk.X, ipady=4, pady=(0, 8))
        self.entry_new_pass.insert(0, "TempPass2026!")

        self.new_user_role_var = tk.StringVar(value="analyst")
        self.combo_new_role = ttk.Combobox(ctrl_card, textvariable=self.new_user_role_var, values=["analyst", "viewer", "administrator"], state="readonly")
        self.combo_new_role.pack(fill=tk.X, ipady=4, pady=(0, 10))

        self.btn_create_user = tk.Button(
            ctrl_card,
            text="+ Create User Account",
            font=FONT_BUTTON,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._handle_create_user,
        )
        self.btn_create_user.pack(fill=tk.X)

    def refresh_users(self) -> None:
        """Fetch and populate users list."""
        prev_selected_id = self._get_selected_user_id()
        for row in self.tree.get_children():
            self.tree.delete(row)

        to_select = None
        users = self.auth_service.list_users(self.current_session)
        for u in users:
            status_str = "Active" if u.get("is_active", True) else "Disabled"
            short_id = u["id"][:8] + "..." if len(u["id"]) > 10 else u["id"]
            item_id = self.tree.insert(
                "",
                tk.END,
                values=(short_id, u["username"], u["role"].upper(), status_str, u["created_at"][:19]),
                tags=(u["id"],),
            )
            if prev_selected_id and u["id"] == prev_selected_id:
                to_select = item_id

        if to_select:
            self.tree.selection_set(to_select)

        if self.on_feedback:
            self.on_feedback(f"User management loaded {len(users)} registered accounts.")

    def _on_user_selected(self, event: tk.Event) -> None:
        """Update action buttons when a row is clicked."""
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        vals = item["values"]
        username = vals[1]
        status_str = vals[3]
        self.lbl_selected_user.configure(text=f"Selected User: {username}")
        if status_str == "Active":
            self.btn_toggle_status.configure(text=f"Deactivate '{username}'", fg=COLOR_WARNING, bg="#2E1B0F")
        else:
            self.btn_toggle_status.configure(text=f"Activate '{username}'", fg=COLOR_SUCCESS, bg="#064E3B")

    def _get_selected_user_id(self) -> str | None:
        """Helper to get actual user ID from selection tags."""
        selected = self.tree.selection()
        if not selected:
            return None
        item = self.tree.item(selected[0])
        tags = item.get("tags", ())
        return tags[0] if tags else None

    def _handle_change_role(self) -> None:
        """Change role for selected user."""
        u_id = self._get_selected_user_id()
        if not u_id:
            if self.on_feedback:
                self.on_feedback("Please select a user from the table first.")
            return

        new_role = self.target_role_var.get()
        ok, msg = self.auth_service.update_user_role(u_id, new_role, self.current_session)
        if self.on_feedback:
            self.on_feedback(msg)
        if ok:
            self.refresh_users()

    def _handle_toggle_status(self) -> None:
        """Activate or deactivate selected user."""
        u_id = self._get_selected_user_id()
        if not u_id:
            if self.on_feedback:
                self.on_feedback("Please select a user from the table first.")
            return

        selected = self.tree.selection()[0]
        curr_status = self.tree.item(selected)["values"][3]
        new_active = curr_status != "Active"

        ok, msg = self.auth_service.set_user_active_status(u_id, new_active, self.current_session)
        if self.on_feedback:
            self.on_feedback(msg)
        if ok:
            self.refresh_users()

    def _handle_delete_user(self) -> None:
        """Delete selected user account."""
        u_id = self._get_selected_user_id()
        if not u_id:
            if self.on_feedback:
                self.on_feedback("Please select a user from the table first.")
            return

        ok, msg = self.auth_service.delete_user(u_id, self.current_session)
        if self.on_feedback:
            self.on_feedback(msg)
        if ok:
            self.refresh_users()

    def _handle_create_user(self) -> None:
        """Create a user account from form fields."""
        u_name = self.entry_new_user.get().strip()
        u_pass = self.entry_new_pass.get()
        u_role = self.new_user_role_var.get()

        ok, msg, _ = self.auth_service.register_user(u_name, u_pass, role=u_role)
        if self.on_feedback:
            self.on_feedback(msg)
        if ok:
            self.refresh_users()
            self.entry_new_user.delete(0, tk.END)
            self.entry_new_pass.delete(0, tk.END)
