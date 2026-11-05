"""Unit tests for Local Network Activity Monitoring Engine."""

from __future__ import annotations

from collections import namedtuple
import socket
from unittest.mock import MagicMock, patch

import psutil
import pytest

from security.network_monitor import (
    LocalNetworkMonitor,
    NetworkConnectionRecord,
    NetworkSummary,
    SocketProtocol,
)

Addr = namedtuple("Addr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def test_connection_record_serialization() -> None:
    """Verify to_dict serialization of NetworkConnectionRecord."""
    rec = NetworkConnectionRecord(
        local_address="127.0.0.1:8080",
        remote_address="10.0.0.1:443",
        status="ESTABLISHED",
        protocol="TCP",
        pid=1234,
        process_name="python.exe",
    )
    d = rec.to_dict()
    assert d["local_address"] == "127.0.0.1:8080"
    assert d["status"] == "ESTABLISHED"
    assert d["pid"] == 1234
    assert d["process_name"] == "python.exe"


def test_summary_serialization() -> None:
    """Verify to_dict serialization of NetworkSummary."""
    summary = NetworkSummary(
        total_connections=10,
        established_count=5,
        listen_count=3,
        time_wait_count=1,
        close_wait_count=1,
        other_count=0,
        active_pids=4,
    )
    d = summary.to_dict()
    assert d["total_connections"] == 10
    assert d["established_count"] == 5
    assert d["active_pids"] == 4


def test_get_active_connections_mocked() -> None:
    """Verify parsing connections across various protocols and addresses."""
    mock_data = [
        MockConn(
            fd=1,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=Addr("127.0.0.1", 8000),
            raddr=Addr("127.0.0.1", 54321),
            status="ESTABLISHED",
            pid=1001,
        ),
        MockConn(
            fd=2,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            laddr=Addr("0.0.0.0", 53),
            raddr=None,
            status="NONE",
            pid=1002,
        ),
        MockConn(
            fd=3,
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            laddr=None,
            raddr=None,
            status="LISTEN",
            pid=None,
        ),
    ]

    monitor = LocalNetworkMonitor()

    def mock_process(pid: int) -> MagicMock:
        proc = MagicMock()
        proc.name.return_value = f"proc_{pid}"
        return proc

    with patch("psutil.net_connections", return_value=mock_data), \
         patch("psutil.Process", side_effect=mock_process):
        results = monitor.get_active_connections()

        assert len(results) == 3
        assert results[0].local_address == "127.0.0.1:8000"
        assert results[0].remote_address == "127.0.0.1:54321"
        assert results[0].protocol == "TCP"
        assert results[0].status == "ESTABLISHED"
        assert results[0].process_name == "proc_1001"

        assert results[1].protocol == "UDP"
        assert results[1].remote_address == "*:*"

        assert results[2].protocol == "OTHER"
        assert results[2].local_address == "*:*"
        assert results[2].pid is None


def test_get_active_connections_filtering() -> None:
    """Verify status filter and search query filtering."""
    mock_data = [
        MockConn(1, socket.AF_INET, socket.SOCK_STREAM, Addr("127.0.0.1", 80), None, "LISTEN", 10),
        MockConn(2, socket.AF_INET, socket.SOCK_STREAM, Addr("192.168.1.15", 55000), Addr("93.184.216.34", 443), "ESTABLISHED", 20),
        MockConn(3, socket.AF_INET, socket.SOCK_STREAM, Addr("127.0.0.1", 5432), Addr("127.0.0.1", 55001), "TIME_WAIT", 30),
    ]

    proc_names = {10: "nginx.exe", 20: "chrome.exe", 30: "postgres.exe"}

    def mock_process(pid: int) -> MagicMock:
        proc = MagicMock()
        proc.name.return_value = proc_names.get(pid, "unknown")
        return proc

    monitor = LocalNetworkMonitor()
    with patch("psutil.net_connections", return_value=mock_data), \
         patch("psutil.Process", side_effect=mock_process):

        # Status filter
        filtered_listen = monitor.get_active_connections(status_filter="LISTEN")
        assert len(filtered_listen) == 1
        assert filtered_listen[0].status == "LISTEN"
        assert filtered_listen[0].process_name == "nginx.exe"

        # Search filter
        filtered_search = monitor.get_active_connections(search_query="chrome")
        assert len(filtered_search) == 1
        assert filtered_search[0].pid == 20



def test_get_active_connections_permission_and_exceptions() -> None:
    """Verify graceful handling when psutil raises AccessDenied or general error."""
    monitor = LocalNetworkMonitor()

    with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
        assert monitor.get_active_connections() == []

    with patch("psutil.net_connections", side_effect=RuntimeError("System error")):
        assert monitor.get_active_connections() == []


def test_get_active_connections_process_access_denied() -> None:
    """Verify handling when inspecting process details raises AccessDenied."""
    mock_data = [
        MockConn(1, socket.AF_INET, socket.SOCK_STREAM, Addr("127.0.0.1", 443), None, "LISTEN", 4),
    ]
    monitor = LocalNetworkMonitor()

    with patch("psutil.net_connections", return_value=mock_data), \
         patch("psutil.Process", side_effect=psutil.AccessDenied()):
        results = monitor.get_active_connections()
        assert len(results) == 1
        assert results[0].process_name == "Restricted / System"


def test_get_summary_counts() -> None:
    """Verify summary computation for various socket statuses."""
    recs = [
        NetworkConnectionRecord("127.0.0.1:80", "*:*", "LISTEN", "TCP", 1),
        NetworkConnectionRecord("127.0.0.1:80", "*:*", "LISTEN", "TCP", 1),
        NetworkConnectionRecord("10.0.0.2:1234", "10.0.0.1:80", "ESTABLISHED", "TCP", 2),
        NetworkConnectionRecord("10.0.0.2:1235", "10.0.0.1:80", "TIME_WAIT", "TCP", 2),
        NetworkConnectionRecord("10.0.0.2:1236", "10.0.0.1:80", "CLOSE_WAIT", "TCP", 3),
        NetworkConnectionRecord("10.0.0.2:1237", "*:*", "SYN_SENT", "TCP", None),
    ]

    monitor = LocalNetworkMonitor()
    summary = monitor.get_summary(recs)

    assert summary.total_connections == 6
    assert summary.listen_count == 2
    assert summary.established_count == 1
    assert summary.time_wait_count == 1
    assert summary.close_wait_count == 1
    assert summary.other_count == 1
    assert summary.active_pids == 3  # PIDs 1, 2, 3


def test_save_snapshot_to_repository() -> None:
    """Verify saving snapshot sample to repository."""
    mock_repo = MagicMock()
    monitor = LocalNetworkMonitor(repository=mock_repo)

    recs = [
        NetworkConnectionRecord("127.0.0.1:80", "*:*", "LISTEN"),
        NetworkConnectionRecord("10.0.0.2:100", "1.1.1.1:443", "ESTABLISHED"),
    ]

    saved = monitor.save_snapshot_to_repository(recs, limit=5)
    assert saved == 2
    assert mock_repo.create.call_count == 2

    # When no repository
    monitor_no_repo = LocalNetworkMonitor(repository=None)
    assert monitor_no_repo.save_snapshot_to_repository(recs) == 0

    # When empty records
    assert monitor.save_snapshot_to_repository([]) == 0
