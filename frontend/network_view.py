"""Network Activity Monitor Desktop View.

Renders active local socket connections, endpoint ports, and socket states
with filtering, search, and database snapshot capabilities.
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
from security.network_monitor import (
    LocalNetworkMonitor,
    NetworkConnectionRecord,
    NetworkSummary,
)


class NetworkActivityView(tk.Frame):
    """Local network socket telemetry interface."""

    def __init__(
        self,
        master: tk.Misc,
        monitor: LocalNetworkMonitor | None = None,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.monitor = monitor or LocalNetworkMonitor()
        self.on_feedback = on_feedback

        self.status_filter_var = tk.StringVar(value="ALL")
        self.search_query_var = tk.StringVar(value="")
        self.last_records: list[NetworkConnectionRecord] = []

        self._build_layout()
        self.refresh_connections()

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

        # 2. Controls & Search Panel
        self._build_controls_panel(self.scroll_content)

        # 3. Dynamic Results Container
        self.results_container = tk.Frame(self.scroll_content, bg=BG_DARK)
        self.results_container.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self.canvas.itemconfig(self.scroll_content_id, width=event.width)

    def _on_frame_configure(self, event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _build_header(self, parent: tk.Widget) -> None:
        """Header card with briefing and defensive boundary notice."""
        hdr = CardFrame(parent, padx=20, pady=16)
        hdr.pack(fill=tk.X, pady=(0, 16))

        top_row = tk.Frame(hdr, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        title_lbl = tk.Label(
            top_row,
            text="NETWORK ACTIVITY MONITOR",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(side=tk.LEFT)

        badge_lbl = tk.Label(
            top_row,
            text="LOCAL SOCKET TELEMETRY",
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
                "Passive defensive visibility into local TCP/UDP socket connections and listening ports. "
                "Monitors strictly local system endpoints without external port scanning, packet interception, "
                "or process modification."
            ),
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=980,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(8, 0))

    def _build_controls_panel(self, parent: tk.Widget) -> None:
        """Render action buttons, status filters, and search bar."""
        panel = CardFrame(parent, padx=20, pady=16)
        panel.pack(fill=tk.X)

        sec_title = tk.Label(
            panel,
            text="CONNECTION FILTERS & ACTIONS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        sec_title.pack(anchor=tk.W, pady=(0, 10))

        row = tk.Frame(panel, bg=BG_CARD)
        row.pack(fill=tk.X)

        # Refresh Button
        self.btn_refresh = tk.Button(
            row,
            text="⚡ Refresh Now",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.refresh_connections,
        )
        self.btn_refresh.pack(side=tk.LEFT, padx=(0, 8))

        # Save Snapshot Button
        self.btn_snapshot = tk.Button(
            row,
            text="💾 Save Snapshot",
            font=FONT_BODY_BOLD,
            bg=COLOR_SUCCESS,
            fg=TEXT_PRIMARY,
            activebackground="#16a34a",
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2",
            command=self.save_snapshot,
        )
        self.btn_snapshot.pack(side=tk.LEFT, padx=(0, 12))

        # Status Filter Label & Combobox
        st_lbl = tk.Label(
            row,
            text="State:",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
        )
        st_lbl.pack(side=tk.LEFT, padx=(0, 6))

        self.cb_status = ttk.Combobox(
            row,
            textvariable=self.status_filter_var,
            values=["ALL", "ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT"],
            state="readonly",
            width=14,
        )
        self.cb_status.pack(side=tk.LEFT, padx=(0, 12))
        self.cb_status.bind("<<ComboboxSelected>>", lambda e: self.refresh_connections())

        # Search Entry
        search_border = tk.Frame(row, bg=BORDER_SUBTLE, padx=1, pady=1)
        search_border.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.entry_search = tk.Entry(
            search_border,
            textvariable=self.search_query_var,
            font=FONT_BODY,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            bd=6,
        )
        self.entry_search.pack(fill=tk.X)
        self.entry_search.bind("<Return>", lambda e: self.refresh_connections())

        # Search Button
        self.btn_search = tk.Button(
            row,
            text="🔍 Filter",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_PRIMARY,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2",
            command=self.refresh_connections,
        )
        self.btn_search.pack(side=tk.LEFT, padx=(0, 6))

        # Clear Filters Button
        self.btn_clear = tk.Button(
            row,
            text="🗑 Reset",
            font=FONT_CAPTION_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_MUTED,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
            command=self.clear_filters,
        )
        self.btn_clear.pack(side=tk.LEFT)

    def refresh_connections(self) -> None:
        """Fetch active network sockets and update table and summary metrics."""
        status_filter = self.status_filter_var.get()
        search_query = self.search_query_var.get()

        records = self.monitor.get_active_connections(
            status_filter=status_filter,
            search_query=search_query,
        )
        self.last_records = records
        summary = self.monitor.get_summary(records)

        self._render_results(records, summary)

        if self.on_feedback:
            self.on_feedback(f"Network monitor updated: {len(records)} active socket(s) displayed.")

    def save_snapshot(self) -> None:
        """Save top active connections to local database repository."""
        if not self.last_records:
            if self.on_feedback:
                self.on_feedback("No active connection records to snapshot.")
            return

        saved = self.monitor.save_snapshot_to_repository(self.last_records, limit=15)
        if saved > 0 and self.on_feedback:
            self.on_feedback(f"Persisted {saved} network connection snapshot records to database.")
        elif self.on_feedback:
            self.on_feedback("Snapshot complete (in-memory).")

    def clear_filters(self) -> None:
        """Reset status dropdown and search entry."""
        self.status_filter_var.set("ALL")
        self.search_query_var.set("")
        self.refresh_connections()
        if self.on_feedback:
            self.on_feedback("Connection filters cleared.")

    def _render_results(self, records: list[NetworkConnectionRecord], summary: NetworkSummary) -> None:
        """Render summary chips and connections Treeview."""
        for child in self.results_container.winfo_children():
            child.destroy()

        # 1. Summary Chips Card
        sum_card = CardFrame(self.results_container, padx=16, pady=12)
        sum_card.pack(fill=tk.X, pady=(0, 14))

        chips_row = tk.Frame(sum_card, bg=BG_CARD)
        chips_row.pack(fill=tk.X)

        self._add_metric_chip(chips_row, f"Total: {summary.total_connections}", BG_CARD_HOVER, TEXT_PRIMARY)
        self._add_metric_chip(chips_row, f"Established: {summary.established_count}", "#064e3b", COLOR_SUCCESS)
        self._add_metric_chip(chips_row, f"Listening: {summary.listen_count}", "#4c1d95", ACCENT_SECONDARY)
        self._add_metric_chip(chips_row, f"Time Wait: {summary.time_wait_count}", "#78350f", COLOR_WARNING)
        self._add_metric_chip(chips_row, f"Active PIDs: {summary.active_pids}", "#0c4a6e", "#38bdf8")

        # 2. Connections Treeview Card
        table_card = CardFrame(self.results_container, padx=16, pady=16)
        table_card.pack(fill=tk.BOTH, expand=True)

        t_title = tk.Label(
            table_card,
            text="ACTIVE SOCKET CONNECTIONS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        t_title.pack(anchor=tk.W, pady=(0, 10))

        tree_frame = tk.Frame(table_card, bg=BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("pid", "process", "proto", "local", "remote", "status")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=min(12, max(5, len(records))),
            selectmode="browse",
        )

        self.tree.heading("pid", text="PID")
        self.tree.heading("process", text="PROCESS NAME")
        self.tree.heading("proto", text="PROTO")
        self.tree.heading("local", text="LOCAL ENDPOINT")
        self.tree.heading("remote", text="REMOTE ENDPOINT")
        self.tree.heading("status", text="STATE")

        self.tree.column("pid", width=70, anchor=tk.CENTER)
        self.tree.column("process", width=190, anchor=tk.W)
        self.tree.column("proto", width=60, anchor=tk.CENTER)
        self.tree.column("local", width=220, anchor=tk.W)
        self.tree.column("remote", width=220, anchor=tk.W)
        self.tree.column("status", width=120, anchor=tk.CENTER)

        self.tree.tag_configure("ESTABLISHED", foreground=COLOR_SUCCESS)
        self.tree.tag_configure("LISTEN", foreground=ACCENT_SECONDARY)
        self.tree.tag_configure("TIME_WAIT", foreground=COLOR_WARNING)
        self.tree.tag_configure("CLOSE_WAIT", foreground="#ea580c")
        self.tree.tag_configure("NONE", foreground=TEXT_MUTED)

        for rec in records:
            tag = rec.status if rec.status in ("ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT") else "NONE"
            self.tree.insert(
                "",
                tk.END,
                values=(
                    str(rec.pid) if rec.pid is not None else "-",
                    rec.process_name or "Restricted / System",
                    rec.protocol,
                    rec.local_address,
                    rec.remote_address,
                    rec.status,
                ),
                tags=(tag,),
            )

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Footnote
        foot_lbl = tk.Label(
            table_card,
            text="Notice: Process details for certain system-level sockets may require administrative permissions.",
            font=FONT_CAPTION,
            bg=BG_CARD,
            fg=TEXT_DIMMED,
            anchor=tk.W,
        )
        foot_lbl.pack(anchor=tk.W, pady=(8, 0))

    def _add_metric_chip(self, parent: tk.Widget, text: str, bg: str, fg: str) -> None:
        """Add status chip badge."""
        lbl = tk.Label(
            parent,
            text=text,
            font=FONT_CAPTION_BOLD,
            bg=bg,
            fg=fg,
            padx=10,
            pady=5,
        )
        lbl.pack(side=tk.LEFT, padx=(0, 8))

