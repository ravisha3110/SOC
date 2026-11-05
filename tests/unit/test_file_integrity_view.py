"""Unit tests for File Integrity Scanner Desktop GUI View."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

from frontend.file_integrity_view import FileIntegrityView, _format_size
from security.file_integrity import (
    FileIntegrityRecord,
    FileIntegrityScanner,
    IntegrityStatus,
)


@pytest.fixture
def tk_root() -> tk.Tk:
    """Fixture providing a hidden Tk root for GUI tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


def test_format_size() -> None:
    """Verify human-readable byte size formatting."""
    assert _format_size(0) == "0 B"
    assert _format_size(-10) == "0 B"
    assert _format_size(512) == "512 B"
    assert "KB" in _format_size(2048)
    assert "MB" in _format_size(5 * 1024 * 1024)
    assert "GB" in _format_size(2 * 1024 * 1024 * 1024)
    assert "TB" in _format_size(4 * 1024 * 1024 * 1024 * 1024)


def test_file_integrity_view_initialization(tk_root: tk.Tk) -> None:
    """Verify initialization of UI cards, buttons, and initial empty state."""
    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)

    assert view.btn_select_files is not None
    assert view.btn_select_folder is not None
    assert view.btn_run_scan is not None
    assert view.btn_save_baseline is not None
    assert view.btn_clear is not None
    assert "No target files" in view.lbl_target["text"]

    # Trigger canvas configure bindings
    event = MagicMock()
    event.width = 800
    view._on_canvas_configure(event)
    view._on_frame_configure(event)


def test_select_files_dialog(tk_root: tk.Tk) -> None:
    """Verify selecting files via file picker updates targets."""
    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)

    with patch("tkinter.filedialog.askopenfilenames", return_value=["/path/to/a.txt", "/path/to/b.txt"]):
        view.select_files_dialog()
        assert len(view.selected_paths) == 2
        assert "Selected 2 files" in view.lbl_target["text"]
        feedback_mock.assert_called_with("Selected 2 file(s) for integrity audit.")

    # When canceled
    with patch("tkinter.filedialog.askopenfilenames", return_value=()):
        view.select_files_dialog()
        assert len(view.selected_paths) == 2  # unchanged


def test_select_folder_dialog(tk_root: tk.Tk) -> None:
    """Verify selecting folder via folder picker updates targets."""
    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)

    with patch("tkinter.filedialog.askdirectory", return_value="/var/log"):
        view.select_folder_dialog()
        assert view.is_folder_mode is True
        assert view.selected_folder == "/var/log"
        assert len(view.selected_paths) == 0
        assert "Selected Directory: /var/log" in view.lbl_target["text"]
        feedback_mock.assert_called_with("Selected directory: log")

    # When canceled
    with patch("tkinter.filedialog.askdirectory", return_value=""):
        view.select_folder_dialog()
        assert view.selected_folder == "/var/log"


def test_run_scan_with_no_targets(tk_root: tk.Tk) -> None:
    """Verify scanning with no targets provides user feedback."""
    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)
    view.run_scan()
    feedback_mock.assert_called_with("Please select files or a directory to scan.")


def test_run_scan_files_mode(tk_root: tk.Tk, tmp_path: Path) -> None:
    """Verify executing scan in files mode renders results in treeview."""
    f1 = tmp_path / "test.txt"
    f1.write_text("Hello SOC", encoding="utf-8")

    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)
    view.selected_paths = [str(f1)]
    view.is_folder_mode = False

    view.run_scan()
    assert len(view.last_results) == 1
    assert view.tree is not None
    children = view.tree.get_children()
    assert len(children) == 1


def test_run_scan_folder_mode_with_modified_alert(tk_root: tk.Tk, tmp_path: Path) -> None:
    """Verify executing scan in folder mode and alerting on modifications."""
    f1 = tmp_path / "doc.txt"
    f1.write_text("Initial", encoding="utf-8")

    mock_scanner = MagicMock()
    mock_scanner.scan_directory.return_value = [
        FileIntegrityRecord(
            file_path=str(f1),
            file_name="doc.txt",
            file_size=10,
            sha256_hash="hash_mod",
            status=IntegrityStatus.MODIFIED,
            previous_hash="hash_old",
        )
    ]

    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, scanner=mock_scanner, on_feedback=feedback_mock)
    view.selected_folder = str(tmp_path)
    view.is_folder_mode = True

    view.run_scan()
    assert len(view.last_results) == 1
    feedback_mock.assert_called_with("ALERT: 1 file(s) modified since baseline!")


def test_save_baseline_workflow(tk_root: tk.Tk, tmp_path: Path) -> None:
    """Verify saving baseline updates baseline and re-evaluates files."""
    f1 = tmp_path / "auth.conf"
    f1.write_text("secure=true", encoding="utf-8")

    feedback_mock = MagicMock()
    scanner = FileIntegrityScanner()
    view = FileIntegrityView(tk_root, scanner=scanner, on_feedback=feedback_mock)

    # Save without prior scan
    view.save_baseline()
    feedback_mock.assert_called_with("Run an integrity scan first before saving a baseline.")

    # Scan file
    view.selected_paths = [str(f1)]
    view.run_scan()

    # Now save baseline
    view.save_baseline()
    assert str(f1) in scanner.baseline_cache or str(f1).replace("/", "\\") in scanner.baseline_cache
    assert any("Baseline updated" in call[0][0] for call in feedback_mock.call_args_list)


def test_save_baseline_with_no_valid_hashes(tk_root: tk.Tk) -> None:
    """Verify save baseline when only error records exist."""
    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)
    view.last_results = [
        FileIntegrityRecord(
            file_path="/missing/file.txt",
            file_name="file.txt",
            status=IntegrityStatus.ERROR,
            error_message="Error",
        )
    ]
    view.save_baseline()
    feedback_mock.assert_called_with("No valid hashes available to record as baseline.")


def test_clear_all(tk_root: tk.Tk) -> None:
    """Verify clearing resets paths, results, and returns to empty state."""
    feedback_mock = MagicMock()
    view = FileIntegrityView(tk_root, on_feedback=feedback_mock)
    view.selected_paths = ["/a/b.txt"]
    view.last_results = [MagicMock()]

    view.clear_all()
    assert len(view.selected_paths) == 0
    assert len(view.last_results) == 0
    assert "No target files" in view.lbl_target["text"]
    feedback_mock.assert_called_with("File integrity view cleared.")


def test_save_baseline_folder_mode_with_repository(tk_root: tk.Tk, tmp_path: Path) -> None:
    """Verify save baseline in folder mode re-scans directory and reports database count."""
    f1 = tmp_path / "app.py"
    f1.write_text("x = 1\n", encoding="utf-8")

    mock_repo = MagicMock()
    scanner = FileIntegrityScanner(baseline_repo=mock_repo)
    feedback_mock = MagicMock()

    view = FileIntegrityView(tk_root, scanner=scanner, on_feedback=feedback_mock)
    view.selected_folder = str(tmp_path)
    view.is_folder_mode = True

    view.run_scan()
    view.save_baseline()

    assert any("Persisted" in call[0][0] for call in feedback_mock.call_args_list)

