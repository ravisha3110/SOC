"""Integration tests for Local Network Monitor with SQLite repository."""

from __future__ import annotations

from pathlib import Path

import pytest

from database.repositories.network_log_repository import NetworkLogRepository
from database.sqlite_manager import SQLiteManager
from security.network_monitor import (
    LocalNetworkMonitor,
    NetworkConnectionRecord,
)


@pytest.fixture
def sqlite_db(tmp_path: Path) -> SQLiteManager:
    """Fixture providing initialized SQLite database."""
    db_path = tmp_path / "test_net.db"
    manager = SQLiteManager(db_path=db_path)
    manager.initialize_database()
    yield manager
    manager.close()


def test_network_monitor_sqlite_lifecycle(sqlite_db: SQLiteManager) -> None:
    """Verify LocalNetworkMonitor snapshots persist cleanly into SQLite network_logs table."""
    repo = NetworkLogRepository(sqlite_db)
    monitor = LocalNetworkMonitor(repository=repo)

    test_connections = [
        NetworkConnectionRecord(
            local_address="127.0.0.1:8000",
            remote_address="127.0.0.1:52134",
            status="ESTABLISHED",
            protocol="TCP",
            pid=4321,
            process_name="uvicorn.exe",
        ),
        NetworkConnectionRecord(
            local_address="0.0.0.0:8000",
            remote_address="*:*",
            status="LISTEN",
            protocol="TCP",
            pid=4321,
            process_name="uvicorn.exe",
        ),
    ]

    # Save snapshot
    persisted_count = monitor.save_snapshot_to_repository(test_connections, limit=5)
    assert persisted_count == 2

    # Query from SQLite
    db_logs = repo.list_all(limit=10)
    assert len(db_logs) == 2
    local_addrs = [log["local_address"] for log in db_logs]
    assert "127.0.0.1:8000" in local_addrs
    assert "0.0.0.0:8000" in local_addrs

    # Delete log entry
    first_id = db_logs[0]["id"]
    assert repo.delete(first_id) is True
    assert len(repo.list_all()) == 1

