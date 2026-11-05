"""File Integrity Scanner View.

Desktop GUI view for selecting files and directories, generating SHA-256
cryptographic checksums, verifying against baselines, and detecting modifications.
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
from security.file_integrity import (
    FileIntegrityRecord,
    FileIntegrityScanner,
    IntegrityStatus,
)


def _format_size(size_bytes: int) -> str:
    """Format byte count into human-readable unit."""
    if size_bytes <= 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"


class FileIntegrityView(tk.Frame):
    """File Integrity Scanner desktop interface."""

    def __init__(
        self,
        master: tk.Misc,
        scanner: FileIntegrityScanner | None = None,
        on_feedback: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, bg=BG_DARK, **kwargs)
        self.scanner = scanner or FileIntegrityScanner()
        self.on_feedback = on_feedback

        self.selected_paths: list[str] = []
        self.is_folder_mode = False
        self.selected_folder: str | None = None
        self.last_results: list[FileIntegrityRecord] = []

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

        # 2. Controls Panel
        self._build_controls_panel(self.scroll_content)

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
        """Header card with briefing and security notices."""
        hdr = CardFrame(parent, padx=20, pady=16)
        hdr.pack(fill=tk.X, pady=(0, 16))

        top_row = tk.Frame(hdr, bg=BG_CARD)
        top_row.pack(fill=tk.X)

        title_lbl = tk.Label(
            top_row,
            text="FILE INTEGRITY SCANNER (FIM)",
            font=FONT_TITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(side=tk.LEFT)

        badge_lbl = tk.Label(
            top_row,
            text="SHA-256 CRYPTOGRAPHIC ENGINE",
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
                "Monitor and audit critical filesystem artifacts for unauthorized changes. "
                "Calculates deterministic SHA-256 digests in 64 KB memory-safe chunks and flags "
                "modified, added, or deleted files against stored cryptographic baselines."
            ),
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            wraplength=980,
            justify=tk.LEFT,
        )
        desc_lbl.pack(fill=tk.X, pady=(8, 0))

    def _build_controls_panel(self, parent: tk.Widget) -> None:
        """Render target selection and scan action buttons."""
        panel = CardFrame(parent, padx=20, pady=18)
        panel.pack(fill=tk.X)

        sec_title = tk.Label(
            panel,
            text="TARGET SELECTION & SCAN ACTIONS",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        sec_title.pack(anchor=tk.W, pady=(0, 10))

        # Button Row
        btn_row = tk.Frame(panel, bg=BG_CARD)
        btn_row.pack(fill=tk.X, pady=(0, 10))

        # Select Files Button
        self.btn_select_files = tk.Button(
            btn_row,
            text="📄 Select Files",
            font=FONT_BODY_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_PRIMARY,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
            command=self.select_files_dialog,
        )
        self.btn_select_files.pack(side=tk.LEFT, padx=(0, 8))

        # Select Folder Button
        self.btn_select_folder = tk.Button(
            btn_row,
            text="📁 Select Folder",
            font=FONT_BODY_BOLD,
            bg=BG_CARD_HOVER,
            fg=TEXT_PRIMARY,
            activebackground=BORDER_SUBTLE,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
            command=self.select_folder_dialog,
        )
        self.btn_select_folder.pack(side=tk.LEFT, padx=(0, 8))

        # Run Scan Button
        self.btn_run_scan = tk.Button(
            btn_row,
            text="⚡ Run Integrity Scan",
            font=FONT_BODY_BOLD,
            bg=ACCENT_PRIMARY,
            fg=TEXT_PRIMARY,
            activebackground=ACCENT_HOVER,
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=18,
            pady=7,
            cursor="hand2",
            command=self.run_scan,
        )
        self.btn_run_scan.pack(side=tk.LEFT, padx=(0, 8))

        # Establish/Save Baseline Button
        self.btn_save_baseline = tk.Button(
            btn_row,
            text="💾 Save Baseline",
            font=FONT_BODY_BOLD,
            bg=COLOR_SUCCESS,
            fg=TEXT_PRIMARY,
            activebackground="#16a34a",
            activeforeground=TEXT_PRIMARY,
            relief="flat",
            padx=14,
            pady=7,
            cursor="hand2",
            command=self.save_baseline,
        )
        self.btn_save_baseline.pack(side=tk.LEFT, padx=(0, 8))

        # Clear Button
        self.btn_clear = tk.Button(
            btn_row,
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

        # Target Path Display
        path_box = tk.Frame(panel, bg=BG_INPUT, highlightbackground=BORDER_SUBTLE, highlightthickness=1, padx=12, pady=8)
        path_box.pack(fill=tk.X)

        self.lbl_target = tk.Label(
            path_box,
            text="No target files or directories selected. Choose files or a folder above.",
            font=FONT_CAPTION,
            bg=BG_INPUT,
            fg=TEXT_DIMMED,
            anchor=tk.W,
        )
        self.lbl_target.pack(fill=tk.X)

    def select_files_dialog(self) -> None:
        """Prompt user with file picker for one or more files."""
        files = filedialog.askopenfilenames(
            title="Select Files for Cryptographic Integrity Audit",
        )
        if files:
            self.selected_paths = list(files)
            self.is_folder_mode = False
            self.selected_folder = None
            count = len(self.selected_paths)
            self.lbl_target.config(
                text=f"Selected {count} file{'s' if count > 1 else ''}: {', '.join(os.path.basename(p) for p in self.selected_paths[:3])}{'...' if count > 3 else ''}",
                fg=TEXT_PRIMARY,
            )
            if self.on_feedback:
                self.on_feedback(f"Selected {count} file(s) for integrity audit.")

    def select_folder_dialog(self) -> None:
        """Prompt user with directory picker for recursive scanning."""
        folder = filedialog.askdirectory(
            title="Select Directory for File Integrity Audit",
        )
        if folder:
            self.selected_folder = folder
            self.is_folder_mode = True
            self.selected_paths = []
            self.lbl_target.config(
                text=f"Selected Directory: {folder}",
                fg=TEXT_PRIMARY,
            )
            if self.on_feedback:
                self.on_feedback(f"Selected directory: {os.path.basename(folder) or folder}")

    def run_scan(self) -> None:
        """Execute SHA-256 scanning and integrity verification against baseline."""
        if not self.selected_paths and not self.selected_folder:
            if self.on_feedback:
                self.on_feedback("Please select files or a directory to scan.")
            return

        if self.is_folder_mode and self.selected_folder:
            records = self.scanner.scan_directory(self.selected_folder, recursive=True)
        else:
            records = self.scanner.scan_files(self.selected_paths, check_missing=True)

        self.last_results = records
        self._render_results(records)

        mod_count = sum(1 for r in records if r.status == IntegrityStatus.MODIFIED)
        if mod_count > 0 and self.on_feedback:
            self.on_feedback(f"ALERT: {mod_count} file(s) modified since baseline!")
        elif self.on_feedback:
            self.on_feedback(f"Scan complete: {len(records)} file(s) audited successfully.")

    def save_baseline(self) -> None:
        """Set current scan records as the official baseline."""
        if not self.last_results:
            if self.on_feedback:
                self.on_feedback("Run an integrity scan first before saving a baseline.")
            return

        valid_records = [
            r for r in self.last_results
            if r.status in (IntegrityStatus.NEW, IntegrityStatus.MODIFIED, IntegrityStatus.UNCHANGED)
            and r.sha256_hash
        ]

        if not valid_records:
            if self.on_feedback:
                self.on_feedback("No valid hashes available to record as baseline.")
            return

        # Update in-memory baseline
        new_baseline = {r.file_path: r.sha256_hash for r in valid_records}
        self.scanner.set_baseline(new_baseline)

        # Persist to repository if available
        saved_db = self.scanner.save_baseline_to_repository(valid_records)

        # Re-run evaluation with the new baseline to update statuses to UNCHANGED
        if self.is_folder_mode and self.selected_folder:
            self.last_results = self.scanner.scan_directory(self.selected_folder, recursive=True)
        else:
            self.last_results = self.scanner.scan_files(self.selected_paths, check_missing=False)

        self._render_results(self.last_results)

        msg = f"Baseline updated with {len(valid_records)} file checksums."
        if saved_db > 0:
            msg += f" (Persisted {saved_db} records to database)"
        if self.on_feedback:
            self.on_feedback(msg)

    def clear_all(self) -> None:
        """Reset selection, results, and restore empty state."""
        self.selected_paths = []
        self.selected_folder = None
        self.is_folder_mode = False
        self.last_results = []
        self.lbl_target.config(
            text="No target files or directories selected. Choose files or a folder above.",
            fg=TEXT_DIMMED,
        )
        self._render_empty_state()
        if self.on_feedback:
            self.on_feedback("File integrity view cleared.")

    def _render_empty_state(self) -> None:
        """Show guide card when no scan has been executed."""
        for child in self.results_container.winfo_children():
            child.destroy()

        card = CardFrame(self.results_container, padx=24, pady=32)
        card.pack(fill=tk.BOTH, expand=True)

        icon_lbl = tk.Label(
            card,
            text="🛡️",
            font=("Segoe UI", 32),
            bg=BG_CARD,
            fg=ACCENT_SECONDARY,
        )
        icon_lbl.pack(pady=(0, 10))

        title_lbl = tk.Label(
            card,
            text="Awaiting Target Selection",
            font=FONT_SUBTITLE,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        title_lbl.pack(pady=(0, 6))

        instructions = (
            "1. Click '📄 Select Files' to inspect individual files, or '📁 Select Folder' for a batch audit.\n"
            "2. Click '⚡ Run Integrity Scan' to calculate cryptographic SHA-256 hashes.\n"
            "3. Click '💾 Save Baseline' to record the current hashes as the verified baseline for future comparison."
        )
        inst_lbl = tk.Label(
            card,
            text=instructions,
            font=FONT_BODY,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify=tk.LEFT,
            pady=8,
        )
        inst_lbl.pack()

    def _render_results(self, records: list[FileIntegrityRecord]) -> None:
        """Render metrics badges and detailed file integrity Treeview."""
        for child in self.results_container.winfo_children():
            child.destroy()

        total = len(records)
        unchanged = sum(1 for r in records if r.status == IntegrityStatus.UNCHANGED)
        modified = sum(1 for r in records if r.status == IntegrityStatus.MODIFIED)
        new_files = sum(1 for r in records if r.status == IntegrityStatus.NEW)
        missing = sum(1 for r in records if r.status == IntegrityStatus.MISSING)

        # 1. Metrics Overview Card
        metrics_card = CardFrame(self.results_container, padx=16, pady=14)
        metrics_card.pack(fill=tk.X, pady=(0, 14))

        m_header = tk.Label(
            metrics_card,
            text="INTEGRITY AUDIT SUMMARY",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_MUTED,
        )
        m_header.pack(anchor=tk.W, pady=(0, 8))

        badges_frame = tk.Frame(metrics_card, bg=BG_CARD)
        badges_frame.pack(fill=tk.X)

        self._add_metric_chip(badges_frame, f"Total: {total}", BG_CARD_HOVER, TEXT_PRIMARY)
        self._add_metric_chip(badges_frame, f"Unchanged: {unchanged}", "#064e3b", COLOR_SUCCESS)
        self._add_metric_chip(badges_frame, f"Modified: {modified}", "#7f1d1d", COLOR_DANGER)
        self._add_metric_chip(badges_frame, f"New: {new_files}", "#78350f", COLOR_WARNING)
        self._add_metric_chip(badges_frame, f"Missing: {missing}", "#4c1d95", ACCENT_SECONDARY)

        # 2. Detailed Results Table Card
        table_card = CardFrame(self.results_container, padx=16, pady=16)
        table_card.pack(fill=tk.BOTH, expand=True)

        t_title = tk.Label(
            table_card,
            text="MONITORED FILES & HASH VERIFICATION",
            font=FONT_SECTION_HEADER,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
        )
        t_title.pack(anchor=tk.W, pady=(0, 10))

        # Treeview Container
        tree_frame = tk.Frame(table_card, bg=BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("status", "filename", "size", "hash", "path")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=min(12, max(5, len(records))),
            selectmode="browse",
        )

        self.tree.heading("status", text="STATUS")
        self.tree.heading("filename", text="FILE NAME")
        self.tree.heading("size", text="SIZE")
        self.tree.heading("hash", text="SHA-256 CHECKSUM")
        self.tree.heading("path", text="FULL PATH")

        self.tree.column("status", width=110, anchor=tk.CENTER)
        self.tree.column("filename", width=180, anchor=tk.W)
        self.tree.column("size", width=80, anchor=tk.E)
        self.tree.column("hash", width=260, anchor=tk.W)
        self.tree.column("path", width=340, anchor=tk.W)

        # Tag configurations for color-coded status rows
        self.tree.tag_configure("UNCHANGED", foreground=COLOR_SUCCESS)
        self.tree.tag_configure("MODIFIED", foreground=COLOR_DANGER)
        self.tree.tag_configure("NEW", foreground=COLOR_WARNING)
        self.tree.tag_configure("MISSING", foreground=ACCENT_SECONDARY)
        self.tree.tag_configure("ERROR", foreground=COLOR_DANGER)

        for rec in records:
            display_hash = rec.sha256_hash if rec.sha256_hash else (rec.error_message or "N/A")
            self.tree.insert(
                "",
                tk.END,
                values=(
                    rec.status.value,
                    rec.file_name,
                    _format_size(rec.file_size),
                    display_hash,
                    rec.file_path,
                ),
                tags=(rec.status.value,),
            )

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

    def _add_metric_chip(self, parent: tk.Widget, text: str, bg: str, fg: str) -> None:
        """Add a compact status chip to a container."""
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

