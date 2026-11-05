"""Local Network Activity Monitoring Engine.

Provides defensive visibility into local socket connections, endpoint ports,
and process identifiers for the CyberShield SOC workstation.

Key Academic Principles & Defensive Boundaries:
- Local Host Visibility Only: Restricts inspection strictly to the local machine's
  active socket tables.
- Zero Packet Sniffing / Content Capture: Does not intercept, inspect, or store
  payload traffic, passwords, or personal data.
- Zero Penetration Testing / External Scanning: Does not scan remote networks,
  sweep subnet ranges, or execute intrusive probes.
- Passive Inspection: Never terminates processes, blocks traffic, or modifies
  socket connection states.
- Graceful Error Handling: Catches permission restrictions on privileged system PIDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import socket
from typing import Any, Protocol

import psutil


class SocketProtocol(str, Enum):
    """Network transport layer protocols."""

    TCP = "TCP"
    UDP = "UDP"
    OTHER = "OTHER"


@dataclass
class NetworkConnectionRecord:
    """Represents a single active network connection endpoint on the local host.

    Attributes:
        local_address: Local IP and port (e.g. '127.0.0.1:8000').
        remote_address: Remote destination endpoint or '*' if listening.
        status: Sockets state (ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, NONE).
        protocol: Transport protocol (TCP, UDP).
        pid: Process ID owning the socket (None if restricted).
        process_name: Executable name associated with the PID (None if restricted).
        timestamp: ISO-8601 UTC timestamp of inspection.
    """

    local_address: str
    remote_address: str
    status: str
    protocol: str = SocketProtocol.TCP.value
    pid: int | None = None
    process_name: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to dictionary."""
        return {
            "local_address": self.local_address,
            "remote_address": self.remote_address,
            "status": self.status,
            "protocol": self.protocol,
            "pid": self.pid,
            "process_name": self.process_name,
            "timestamp": self.timestamp,
        }


@dataclass
class NetworkSummary:
    """Aggregate statistics for an active connection audit."""

    total_connections: int = 0
    established_count: int = 0
    listen_count: int = 0
    time_wait_count: int = 0
    close_wait_count: int = 0
    other_count: int = 0
    active_pids: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to dictionary."""
        return {
            "total_connections": self.total_connections,
            "established_count": self.established_count,
            "listen_count": self.listen_count,
            "time_wait_count": self.time_wait_count,
            "close_wait_count": self.close_wait_count,
            "other_count": self.other_count,
            "active_pids": self.active_pids,
        }


class NetworkLogRepositoryProtocol(Protocol):
    """Protocol for persisting network activity snapshots."""

    def create(
        self,
        local_address: str,
        remote_address: str,
        connection_status: str,
        log_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]: ...

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]: ...


class LocalNetworkMonitor:
    """Defensive local network socket monitor.

    Monitors host network connections using psutil and provides filtering,
    summary calculations, and database snapshot capabilities.
    """

    def __init__(
        self,
        repository: NetworkLogRepositoryProtocol | None = None,
    ) -> None:
        """Initialize the network monitor with an optional database repository."""
        self.repository = repository
        self._cached_records: list[NetworkConnectionRecord] = []

    def get_active_connections(
        self,
        status_filter: str | None = None,
        search_query: str | None = None,
    ) -> list[NetworkConnectionRecord]:
        """Retrieve active local network connections with optional filtering.

        Args:
            status_filter: Optional socket state filter (e.g. 'ESTABLISHED', 'LISTEN').
            search_query: Optional search keyword to filter by IP, port, or process name.

        Returns:
            list[NetworkConnectionRecord]: Filtered list of connection records.
        """
        records: list[NetworkConnectionRecord] = []

        try:
            raw_connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Permission restriction on some environments
            return []
        except Exception:
            return []

        # Cache process names by PID to avoid repetitive lookups
        process_cache: dict[int, str] = {}

        for conn in raw_connections:
            # Determine protocol
            if conn.type == socket.SOCK_STREAM:
                proto = SocketProtocol.TCP.value
            elif conn.type == socket.SOCK_DGRAM:
                proto = SocketProtocol.UDP.value
            else:
                proto = SocketProtocol.OTHER.value

            # Format local endpoint
            if conn.laddr:
                l_ip = conn.laddr.ip if hasattr(conn.laddr, "ip") else conn.laddr[0]
                l_port = conn.laddr.port if hasattr(conn.laddr, "port") else conn.laddr[1]
                local_addr = f"{l_ip}:{l_port}"
            else:
                local_addr = "*:*"

            # Format remote endpoint
            if conn.raddr:
                r_ip = conn.raddr.ip if hasattr(conn.raddr, "ip") else conn.raddr[0]
                r_port = conn.raddr.port if hasattr(conn.raddr, "port") else conn.raddr[1]
                remote_addr = f"{r_ip}:{r_port}"
            else:
                remote_addr = "*:*"

            status = conn.status if conn.status else "NONE"
            pid = conn.pid
            process_name: str | None = None

            if pid is not None:
                if pid in process_cache:
                    process_name = process_cache[pid]
                else:
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                        process_cache[pid] = process_name
                    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                        process_name = "Restricted / System"
                        process_cache[pid] = process_name

            records.append(
                NetworkConnectionRecord(
                    local_address=local_addr,
                    remote_address=remote_addr,
                    status=status.upper(),
                    protocol=proto,
                    pid=pid,
                    process_name=process_name,
                )
            )

        self._cached_records = records

        # Apply filtering
        filtered = records
        if status_filter and status_filter.upper() != "ALL":
            target_status = status_filter.upper()
            filtered = [r for r in filtered if r.status == target_status]

        if search_query and search_query.strip():
            q = search_query.strip().lower()
            filtered = [
                r for r in filtered
                if (
                    q in r.local_address.lower()
                    or q in r.remote_address.lower()
                    or (r.process_name and q in r.process_name.lower())
                    or (r.pid is not None and q in str(r.pid))
                    or q in r.protocol.lower()
                )
            ]

        return filtered

    def get_summary(
        self,
        records: list[NetworkConnectionRecord] | None = None,
    ) -> NetworkSummary:
        """Compute aggregate summary counts for connection states and PIDs.

        Args:
            records: List of connection records to summarize. If None, uses cached records.

        Returns:
            NetworkSummary: Summary metrics.
        """
        source = records if records is not None else self._cached_records
        summary = NetworkSummary(total_connections=len(source))
        unique_pids: set[int] = set()

        for r in source:
            st = r.status.upper()
            if st == "ESTABLISHED":
                summary.established_count += 1
            elif st == "LISTEN":
                summary.listen_count += 1
            elif st == "TIME_WAIT":
                summary.time_wait_count += 1
            elif st == "CLOSE_WAIT":
                summary.close_wait_count += 1
            else:
                summary.other_count += 1

            if r.pid is not None:
                unique_pids.add(r.pid)

        summary.active_pids = len(unique_pids)
        return summary

    def save_snapshot_to_repository(
        self,
        records: list[NetworkConnectionRecord] | None = None,
        limit: int = 15,
    ) -> int:
        """Save a representative sample of active connections to the database repository.

        Avoids continuous mass storage while providing useful audit snapshots.

        Args:
            records: Optional connection list. Defaults to cached records.
            limit: Maximum count of connection entries to persist.

        Returns:
            int: Count of persisted connection log records.
        """
        if self.repository is None:
            return 0

        source = records if records is not None else self._cached_records
        if not source:
            return 0

        # Prioritize ESTABLISHED and LISTEN sockets
        prioritized = sorted(
            source,
            key=lambda r: (0 if r.status == "ESTABLISHED" else 1 if r.status == "LISTEN" else 2),
        )
        sample = prioritized[:limit]

        saved = 0
        for conn in sample:
            self.repository.create(
                local_address=conn.local_address,
                remote_address=conn.remote_address,
                connection_status=conn.status,
            )
            saved += 1

        return saved

