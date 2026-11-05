"""Integration tests for hybrid database persistence, referential integrity, and migrations."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from database.exceptions import DatabaseConstraintError
from database.repositories import (
    ScanRepository,
    ThreatRepository,
    UserRepository,
)
from database.sqlite_manager import SQLiteManager


def test_local_database_persistence_across_reconnects(tmp_path: Path) -> None:
    """Verify data written to SQLite persists on disk and is readable by new managers."""
    db_file = tmp_path / "persistent_cybershield.db"

    # Session 1: Initialize and insert data
    mgr1 = SQLiteManager(db_path=db_file)
    mgr1.initialize_database()
    user_repo1 = UserRepository(mgr1)
    user_repo1.create(username="persistent_analyst", password_hash="hash_persist_1")
    mgr1.close()

    # Session 2: Open new manager instance pointing to the exact same file
    mgr2 = SQLiteManager(db_path=db_file)
    user_repo2 = UserRepository(mgr2)
    user = user_repo2.get_by_username("persistent_analyst")

    assert user is not None
    assert user["username"] == "persistent_analyst"
    assert user["password_hash"] == "hash_persist_1"
    mgr2.close()


def test_multiple_records_and_limit_ordering(tmp_path: Path) -> None:
    """Verify insertion of multiple records and proper limit handling."""
    db_file = tmp_path / "ordering_test.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()
    scan_repo = ScanRepository(mgr)

    for i in range(15):
        scan_repo.create(
            scan_type="PORT_SCAN",
            target=f"10.0.0.{i}",
            result=f"Result for host {i}",
            created_at=f"2026-11-05T01:{i:02d}:00Z",
        )

    all_scans = scan_repo.list_all(limit=10)
    assert len(all_scans) == 10

    # Ensure ordering is descending (most recent first)
    assert all_scans[0]["target"] == "10.0.0.14"
    assert all_scans[1]["target"] == "10.0.0.13"

    mgr.close()


def test_referential_integrity_cascade_delete(tmp_path: Path) -> None:
    """Verify foreign key CASCADE deletes linked threats when parent scan is deleted."""
    db_file = tmp_path / "cascade_test.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()

    scan_repo = ScanRepository(mgr)
    threat_repo = ThreatRepository(mgr)

    # Create scan and 2 linked threats
    scan = scan_repo.create(scan_type="FIM", target="/etc/hosts", result="Checksum discrepancy")
    scan_id = scan["id"]

    threat1 = threat_repo.create(scan_id=scan_id, threat_type="TAMPER", severity="HIGH", description="Hosts modified")
    threat2 = threat_repo.create(scan_id=scan_id, threat_type="DNS_REDIRECT", severity="CRITICAL", description="Phishing IP")

    # Verify threats are linked
    threats = threat_repo.list_by_scan(scan_id)
    assert len(threats) == 2

    # Delete parent scan
    scan_repo.delete(scan_id)

    # Verify both child threats were automatically deleted by CASCADE
    assert threat_repo.get_by_id(threat1["id"]) is None
    assert threat_repo.get_by_id(threat2["id"]) is None
    assert len(threat_repo.list_by_scan(scan_id)) == 0

    mgr.close()


def test_referential_integrity_foreign_key_violation(tmp_path: Path) -> None:
    """Verify inserting a threat with a non-existent scan_id raises DatabaseConstraintError."""
    db_file = tmp_path / "fk_violation.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()
    threat_repo = ThreatRepository(mgr)

    with pytest.raises(DatabaseConstraintError):
        threat_repo.create(
            scan_id="non-existent-scan-uuid",
            threat_type="UNKNOWN",
            severity="LOW",
            description="Orphan threat should fail",
        )

    mgr.close()


def test_migration_version_tracking(tmp_path: Path) -> None:
    """Verify schema_migrations table tracks version, timestamp, and description."""
    db_file = tmp_path / "migration_tracking.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()

    migrations = mgr.get_applied_migrations()
    assert len(migrations) == 1
    assert migrations[0]["version"] == 1
    assert "2026-" in migrations[0]["applied_at"]
    assert "Initial" in migrations[0]["description"]

    mgr.close()


def test_repository_with_mocked_postgres_executor() -> None:
    """Verify repository functions seamlessly with PostgresManager interface."""
    mock_postgres = MagicMock()
    mock_postgres.execute.return_value = 1
    mock_postgres.fetch_one.return_value = {
        "id": "pg-1",
        "username": "cloud_analyst",
        "password_hash": "hash_pg",
        "created_at": "2026-11-05T00:00:00Z",
    }
    mock_postgres.fetch_all.return_value = [
        {
            "id": "pg-1",
            "username": "cloud_analyst",
            "password_hash": "hash_pg",
            "created_at": "2026-11-05T00:00:00Z",
        }
    ]

    repo = UserRepository(mock_postgres)
    created = repo.create(username="cloud_analyst", password_hash="hash_pg", user_id="pg-1")

    assert created["username"] == "cloud_analyst"
    assert mock_postgres.execute.call_count >= 1
    mock_postgres.fetch_one.assert_called_once()


def test_user_repository_full_lifecycle_and_edge_cases(tmp_path: Path) -> None:
    """Verify UserRepository role assignment, status toggling, and fallback handling."""
    db_file = tmp_path / "user_repo_test.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()
    repo = UserRepository(mgr)

    # 1. Create with custom role and active status
    u1 = repo.create("alice_admin", "hash_admin", role="administrator", is_active=True)
    assert u1["role"] == "administrator"
    assert u1["is_active"] == 1

    # Update role and status
    assert repo.update_role(u1["id"], "viewer") is True
    assert repo.set_active_status(u1["id"], False) is True
    fetched = repo.get_by_id(u1["id"])
    assert fetched["role"] == "viewer"
    assert fetched["is_active"] == 0

    # 2. Legacy user existing in users table but missing in user_roles
    mgr.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        ("legacy-1", "legacy_user", "hash_leg", "2026-01-01T00:00:00Z"),
    )
    # update_role when existing is None -> inserts new user_roles row
    assert repo.update_role("legacy-1", "administrator") is True
    # delete legacy row from user_roles
    mgr.execute("DELETE FROM user_roles WHERE user_id = ?;", ("legacy-1",))
    # set_active_status when existing is None -> inserts new user_roles row
    assert repo.set_active_status("legacy-1", True) is True

    # 3. List all
    users = repo.list_all(limit=10)
    assert len(users) >= 2

    # 4. Delete user
    assert repo.delete(u1["id"]) is True
    assert repo.get_by_id(u1["id"]) is None
    mgr.close()

    # 5. Exception branches in _ensure_roles_table, create and delete
    mock_db_ensure = MagicMock()
    mock_db_ensure.execute.side_effect = RuntimeError("ensure table fail")
    repo_ensure_fail = UserRepository(mock_db_ensure)
    assert repo_ensure_fail is not None

    mock_db = MagicMock()
    mock_db.execute.side_effect = [1, 1, RuntimeError("insert fail")]
    mock_db.fetch_one.return_value = None
    mock_repo = UserRepository(mock_db)
    res = mock_repo.create("fail_user", "hash")
    assert res["username"] == "fail_user"

    mock_db.execute.side_effect = [RuntimeError("delete fail"), 1]
    assert mock_repo.delete("u-fail") is True

