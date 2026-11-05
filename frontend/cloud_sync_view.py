"""CyberShield Hybrid Cloud Synchronization and Settings View."""

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
from security.auth import Permission, Role, Session
from security.cloud_sync import (
    CloudConnectionStatus,
    CloudSyncEngine,
    SyncDirection,
    SyncSummary,
)


class CloudSyncView(tk.Frame):
    """Hybrid cloud synchronization console with connection status, conflict audit, and manual sync controls."""

    def __init__(
        self,
        master: tk.Misc,
        sync_engine: CloudSyncEngine,
        current_session: Session | None = None,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.sync_engine = sync_engine
        self.current_session = current_session
        self.on_feedback = on_feedback

        self._build_ui()
        self.refresh_status()

    def _build_ui(self) -> None:
        # Header banner card
        header_card = CardFrame(self, padx=20, pady=16)
        header_card.pack(fill=tk.X, padx=20, pady=(16, 12))

        tk.Label(
            header_card,
            text="☁️ HYBRID CLOUD SYNCHRONIZATION (NEON POSTGRESQL)",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        ).pack(anchor=tk.W)

        tk.Label(
            header_card,
            text="Offline-first SQLite edge persistence with idempotent cloud sync to Neon PostgreSQL. Zero credential transmission.",
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(4, 0))

        # 1. Telemetry Status Card (Connection, URL, Pending Records, Last Sync)
        status_card = CardFrame(self, padx=20, pady=16)
        status_card.pack(fill=tk.X, padx=20, pady=(0, 12))

        stat_row = tk.Frame(status_card, bg=BG_CARD)
        stat_row.pack(fill=tk.X)
        stat_row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Cloud Status Pill
        c_box = tk.Frame(stat_row, bg=BG_CARD)
        c_box.grid(row=0, column=0, sticky="w")
        tk.Label(c_box, text="CLOUD STATUS", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)
        self.lbl_cloud_status = tk.Label(
            c_box,
            text="● CHECKING...",
            font=FONT_SUBTITLE,
            bg=BG_CARD,
            fg=COLOR_WARNING,
        )
        self.lbl_cloud_status.pack(anchor=tk.W, pady=(2, 0))

        # Masked Target URL
        url_box = tk.Frame(stat_row, bg=BG_CARD)
        url_box.grid(row=0, column=1, sticky="w", padx=10)
        tk.Label(url_box, text="TARGET DATABASE", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)
        self.lbl_masked_url = tk.Label(
            url_box,
            text="[Masked]",
            font=FONT_CAPTION,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        )
        self.lbl_masked_url.pack(anchor=tk.W, pady=(4, 0))

        # Local Records Count
        rec_box = tk.Frame(stat_row, bg=BG_CARD)
        rec_box.grid(row=0, column=2, sticky="w", padx=10)
        tk.Label(rec_box, text="LOCAL SQLITE RECORDS", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)
        self.lbl_records_count = tk.Label(
            rec_box,
            text="0 Records",
            font=FONT_SUBTITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        self.lbl_records_count.pack(anchor=tk.W, pady=(2, 0))

        # Last Sync Timestamp
        time_box = tk.Frame(stat_row, bg=BG_CARD)
        time_box.grid(row=0, column=3, sticky="w")
        tk.Label(time_box, text="LAST SYNCHRONIZED", font=FONT_CAPTION_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor=tk.W)
        self.lbl_last_sync = tk.Label(
            time_box,
            text="Never",
            font=FONT_CAPTION,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        self.lbl_last_sync.pack(anchor=tk.W, pady=(4, 0))

        # 2. Controls & Actions Row
        actions_card = CardFrame(self, padx=20, pady=16)
        actions_card.pack(fill=tk.X, padx=20, pady=(0, 12))

        btn_row = tk.Frame(actions_card, bg=BG_CARD)
        btn_row.pack(fill=tk.X)

        self.btn_sync_bidirectional = tk.Button(
            btn_row,
            text="⚡ Full Bidirectional Sync",
            font=FONT_BUTTON,
            bg=ACCENT_PRIMARY,
            fg="#FFFFFF",
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            command=lambda: self._handle_sync(SyncDirection.BIDIRECTIONAL),
        )
        self.btn_sync_bidirectional.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_upload = tk.Button(
            btn_row,
            text="⬆️ Upload to Neon",
            font=FONT_BODY_BOLD,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
            command=lambda: self._handle_sync(SyncDirection.UPLOAD_ONLY),
        )
        self.btn_upload.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_download = tk.Button(
            btn_row,
            text="⬇️ Download from Neon",
            font=FONT_BODY_BOLD,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
            command=lambda: self._handle_sync(SyncDirection.DOWNLOAD_ONLY),
        )
        self.btn_download.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_test_conn = tk.Button(
            btn_row,
            text="🔍 Test Connection",
            font=FONT_CAPTION_BOLD,
            bg=BG_INPUT,
            fg=ACCENT_SECONDARY,
            relief="flat",
            bd=0,
            padx=12,
            pady=8,
            cursor="hand2",
            command=self.refresh_status,
        )
        self.btn_test_conn.pack(side=tk.RIGHT)

        # 3. Post-Sync Audit Results and Breakdown Card
        audit_card = CardFrame(self, padx=20, pady=16)
        audit_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 16))

        tk.Label(
            audit_card,
            text="AUDIT LOG & CONFLICT DETECTION",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        ).pack(anchor=tk.W, pady=(0, 8))

        # Treeview for table stats & conflicts
        tree_frame = tk.Frame(audit_card, bg=BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("category", "table", "details", "status")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            style="Treeview",
        )
        self.tree.heading("category", text="Category")
        self.tree.heading("table", text="Table Name")
        self.tree.heading("details", text="Sync Breakdown / Conflict Details")
        self.tree.heading("status", text="Result")

        self.tree.column("category", width=120, minwidth=100)
        self.tree.column("table", width=130, minwidth=110)
        self.tree.column("details", width=420, minwidth=250)
        self.tree.column("status", width=110, minwidth=90)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def refresh_status(self) -> None:
        """Check cloud reachability and refresh telemetry display."""
        overview = self.sync_engine.get_status_overview()
        status_val = overview["cloud_status"]

        if status_val == "ONLINE":
            self.lbl_cloud_status.configure(text="● ONLINE (NEON)", fg=COLOR_SUCCESS)
        elif status_val == "OFFLINE":
            self.lbl_cloud_status.configure(text="● OFFLINE", fg=COLOR_DANGER)
        elif status_val == "NOT_CONFIGURED":
            self.lbl_cloud_status.configure(text="● NOT CONFIGURED", fg=COLOR_WARNING)
        else:
            self.lbl_cloud_status.configure(text="● CONNECTION ERROR", fg=COLOR_DANGER)

        self.lbl_masked_url.configure(text=overview["masked_target_url"])
        self.lbl_records_count.configure(text=f"{overview['total_local_records']} Records")
        self.lbl_last_sync.configure(text=overview["last_synced_at"][:19] if overview["last_synced_at"] else "Never")

        # RBAC Check: Viewers cannot trigger sync
        if self.current_session and self.current_session.role == Role.VIEWER:
            self.btn_sync_bidirectional.configure(state=tk.DISABLED)
            self.btn_upload.configure(state=tk.DISABLED)
            self.btn_download.configure(state=tk.DISABLED)
            if self.on_feedback:
                self.on_feedback("Viewer Role: Read-only access to cloud status. Sync controls disabled.")
        elif self.on_feedback:
            self.on_feedback(f"Cloud status checked: {status_val}")

    def _handle_sync(self, direction: SyncDirection) -> None:
        """Trigger sync in requested direction and display detailed results."""
        if self.current_session and self.current_session.role == Role.VIEWER:
            if self.on_feedback:
                self.on_feedback("Permission denied: Viewer role cannot trigger cloud synchronization.")
            return

        if self.on_feedback:
            self.on_feedback(f"Executing {direction.value} synchronization with Neon PostgreSQL...")

        summary: SyncSummary = self.sync_engine.synchronize(direction=direction)

        # Clear tree
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Populate summary rows
        for t_name, stats in summary.table_stats.items():
            up = stats.get("uploaded", 0)
            down = stats.get("downloaded", 0)
            self.tree.insert(
                "",
                tk.END,
                values=("Table Stats", t_name, f"Uploaded: {up} | Downloaded: {down}", "Synced"),
            )

        # Populate conflicts
        if summary.conflicts:
            for c in summary.conflicts:
                self.tree.insert(
                    "",
                    tk.END,
                    values=("Conflict", c.table_name, f"ID: {c.record_id} — {c.conflict_reason}", "Flagged"),
                )
        else:
            self.tree.insert(
                "",
                tk.END,
                values=("Integrity", "All Tables", "Zero attribute conflicts detected. Idempotent match.", "Verified"),
            )

        # Populate errors if any
        for err in summary.errors:
            self.tree.insert(
                "",
                tk.END,
                values=("Error / Warning", "Engine", err, summary.status),
            )

        # Update telemetry labels
        self.refresh_status()

        if self.on_feedback:
            msg = (
                f"Sync {summary.status}: {summary.records_uploaded} uploaded, "
                f"{summary.records_downloaded} downloaded, {summary.conflicts_detected} conflicts."
            )
            self.on_feedback(msg)

