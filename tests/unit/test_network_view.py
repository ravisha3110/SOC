"""Unit tests for Network Activity Monitor Desktop GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

from frontend.network_view import NetworkActivityView
from security.network_monitor import (
    LocalNetworkMonitor,
    NetworkConnectionRecord,
    NetworkSummary,
)


@pytest.fixture
def tk_root() -> tk.Tk:
    """Fixture providing a hidden Tk root for GUI testing."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


def test_network_view_initialization(tk_root: tk.Tk) -> None:
    """Verify initialization of UI controls, summary cards, and treeview."""
    feedback_mock = MagicMock()
    mock_monitor = MagicMock()
    mock_monitor.get_active_connections.return_value = [
        NetworkConnectionRecord("127.0.0.1:80", "*:*", "LISTEN", "TCP", 1234, "server.exe"),
        NetworkConnectionRecord("192.168.1.10:50000", "1.1.1.1:443", "ESTABLISHED", "TCP", 5678, "browser.exe"),
    ]
    mock_monitor.get_summary.return_value = NetworkSummary(
        total_connections=2,
        established_count=1,
        listen_count=1,
        active_pids=2,
    )

    view = NetworkActivityView(tk_root, monitor=mock_monitor, on_feedback=feedback_mock)

    assert view.btn_refresh is not None
    assert view.btn_snapshot is not None
    assert view.btn_clear is not None
    assert view.cb_status is not None
    assert view.entry_search is not None
    assert view.tree is not None

    # Test canvas configure bindings
    event = MagicMock()
    event.width = 900
    view._on_canvas_configure(event)
    view._on_frame_configure(event)

    children = view.tree.get_children()
    assert len(children) == 2


def test_network_view_filtering_and_search(tk_root: tk.Tk) -> None:
    """Verify filtering and search entry interactions."""
    feedback_mock = MagicMock()
    mock_monitor = MagicMock()
    mock_monitor.get_active_connections.return_value = []
    mock_monitor.get_summary.return_value = NetworkSummary()

    view = NetworkActivityView(tk_root, monitor=mock_monitor, on_feedback=feedback_mock)

    view.status_filter_var.set("ESTABLISHED")
    view.search_query_var.set("192.168")
    view.refresh_connections()

    mock_monitor.get_active_connections.assert_called_with(
        status_filter="ESTABLISHED",
        search_query="192.168",
    )


def test_network_view_save_snapshot(tk_root: tk.Tk) -> None:
    """Verify save snapshot workflow."""
    feedback_mock = MagicMock()
    mock_monitor = MagicMock()
    mock_monitor.get_active_connections.return_value = [
        NetworkConnectionRecord("127.0.0.1:80", "*:*", "LISTEN"),
    ]
    mock_monitor.get_summary.return_value = NetworkSummary(total_connections=1)
    mock_monitor.save_snapshot_to_repository.return_value = 1

    view = NetworkActivityView(tk_root, monitor=mock_monitor, on_feedback=feedback_mock)
    view.save_snapshot()

    mock_monitor.save_snapshot_to_repository.assert_called_once()
    assert any("Persisted 1 network connection" in call[0][0] for call in feedback_mock.call_args_list)

    # When saved count is 0 (in-memory only)
    mock_monitor.save_snapshot_to_repository.return_value = 0
    view.last_records = [NetworkConnectionRecord("127.0.0.1:80", "*:*", "LISTEN")]
    view.save_snapshot()
    assert any("Snapshot complete (in-memory)" in call[0][0] for call in feedback_mock.call_args_list)

    # When no records exist
    view.last_records = []
    view.save_snapshot()
    feedback_mock.assert_called_with("No active connection records to snapshot.")


def test_network_view_clear_filters(tk_root: tk.Tk) -> None:
    """Verify reset button clears search inputs and restores defaults."""
    feedback_mock = MagicMock()
    mock_monitor = MagicMock()
    mock_monitor.get_active_connections.return_value = []
    mock_monitor.get_summary.return_value = NetworkSummary()

    view = NetworkActivityView(tk_root, monitor=mock_monitor, on_feedback=feedback_mock)
    view.status_filter_var.set("LISTEN")
    view.search_query_var.set("nginx")

    view.clear_filters()
    assert view.status_filter_var.get() == "ALL"
    assert view.search_query_var.get() == ""
    feedback_mock.assert_called_with("Connection filters cleared.")
