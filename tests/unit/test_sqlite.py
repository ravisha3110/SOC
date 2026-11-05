"""Unit tests for SQLiteManager local database management."""

from __future__ import annotations

from pathlib import Path
import sqlite3
from unittest.mock import MagicMock, patch
import pytest

from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
    DatabaseMigrationError,
)
from database.schema import ALL_APPLICATION_TABLES
from database.sqlite_manager import SQLiteManager


@pytest.fixture
def sqlite_mgr(tmp_path: Path) -> SQLiteManager:
    """Create a SQLiteManager with a temporary database file."""
    db_file = tmp_path / "test_cybershield.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()
    yield mgr
    mgr.close()


def test_sqlite_initialization_and_table_creation(sqlite_mgr: SQLiteManager) -> None:
    """Verify that database initializes and creates all mandatory tables."""
    assert sqlite_mgr.db_path.is_file()

    with sqlite_mgr.get_connection() as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}

    for expected_table in ALL_APPLICATION_TABLES:
        assert expected_table in tables, f"Table {expected_table} was not created"
    assert "schema_migrations" in tables


def test_sqlite_repeated_initialization_is_idempotent(sqlite_mgr: SQLiteManager) -> None:
    """Verify that calling initialize_database repeatedly does not reset or duplicate tables."""
    # Insert a user record
    sqlite_mgr.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        ("usr-1", "admin_analyst", "hash123", "2026-11-05T00:00:00Z"),
    )

    # Re-run initialization
    sqlite_mgr.initialize_database()

    # User record must still exist unharmed
    user = sqlite_mgr.fetch_one("SELECT * FROM users WHERE id = ?;", ("usr-1",))
    assert user is not None
    assert user["username"] == "admin_analyst"


def test_sqlite_in_memory_mode() -> None:
    """Verify in-memory SQLite mode initializes cleanly without creating files."""
    mem_mgr = SQLiteManager(db_path=":memory:")
    mem_mgr.initialize_database()

    mem_mgr.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        ("mem-1", "memory_user", "hash456", "2026-11-05T00:00:00Z"),
    )
    user = mem_mgr.fetch_one("SELECT * FROM users WHERE id = ?;", ("mem-1",))
    assert user is not None
    assert user["username"] == "memory_user"

    mem_mgr.close()
    assert mem_mgr._memory_conn is None


def test_sqlite_crud_operations(sqlite_mgr: SQLiteManager) -> None:
    """Verify basic CRUD query methods on SQLiteManager."""
    # Create
    sqlite_mgr.execute(
        "INSERT INTO scan_history (id, scan_type, target, result, created_at) VALUES (?, ?, ?, ?, ?);",
        ("scn-1", "PORT_SCAN", "127.0.0.1", "All ports closed", "2026-11-05T00:00:00Z"),
    )

    # Read (fetch_one)
    scan = sqlite_mgr.fetch_one("SELECT * FROM scan_history WHERE id = ?;", ("scn-1",))
    assert scan is not None
    assert scan["target"] == "127.0.0.1"

    # Read (fetch_all)
    all_scans = sqlite_mgr.fetch_all("SELECT * FROM scan_history WHERE scan_type = ?;", ("PORT_SCAN",))
    assert len(all_scans) == 1

    # Update
    sqlite_mgr.execute("UPDATE scan_history SET result = ? WHERE id = ?;", ("1 open port", "scn-1"))
    updated = sqlite_mgr.fetch_one("SELECT result FROM scan_history WHERE id = ?;", ("scn-1",))
    assert updated["result"] == "1 open port"

    # Delete
    deleted_rows = sqlite_mgr.execute("DELETE FROM scan_history WHERE id = ?;", ("scn-1",))
    assert deleted_rows == 1
    assert sqlite_mgr.fetch_one("SELECT * FROM scan_history WHERE id = ?;", ("scn-1",)) is None


def test_sqlite_uuid_handling(sqlite_mgr: SQLiteManager) -> None:
    """Verify that UUID strings function properly as primary and foreign keys."""
    scan_uuid = "550e8400-e29b-41d4-a716-446655440000"
    threat_uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

    sqlite_mgr.execute(
        "INSERT INTO scan_history (id, scan_type, target, result, created_at) VALUES (?, ?, ?, ?, ?);",
        (scan_uuid, "VULN_SCAN", "192.168.1.10", "1 threat found", "2026-11-05T00:00:00Z"),
    )

    sqlite_mgr.execute(
        "INSERT INTO threats (id, scan_id, threat_type, severity, description, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?);",
        (threat_uuid, scan_uuid, "DEFAULT_CREDS", "HIGH", "Default password in use", "2026-11-05T00:00:00Z"),
    )

    threat = sqlite_mgr.fetch_one("SELECT * FROM threats WHERE id = ?;", (threat_uuid,))
    assert threat is not None
    assert threat["scan_id"] == scan_uuid


def test_sqlite_transaction_commit(sqlite_mgr: SQLiteManager) -> None:
    """Verify that statements inside transaction commit successfully."""
    with sqlite_mgr.transaction() as conn:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            ("tx-1", "user1", "hash1", "2026-11-05T00:00:00Z"),
        )
        conn.execute(
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            ("tx-2", "user2", "hash2", "2026-11-05T00:00:00Z"),
        )

    users = sqlite_mgr.fetch_all("SELECT * FROM users WHERE id IN ('tx-1', 'tx-2');")
    assert len(users) == 2


def test_sqlite_transaction_rollback_on_error(sqlite_mgr: SQLiteManager) -> None:
    """Verify that an exception in transaction rolls back all pending changes."""
    with pytest.raises(DatabaseError):
        with sqlite_mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                ("rb-1", "rollback_user", "hash", "2026-11-05T00:00:00Z"),
            )
            # Intentionally trigger an error
            raise ValueError("Forced error to test rollback")

    # rb-1 must NOT have been saved
    assert sqlite_mgr.fetch_one("SELECT * FROM users WHERE id = ?;", ("rb-1",)) is None


def test_sqlite_unique_constraint_violation(sqlite_mgr: SQLiteManager) -> None:
    """Verify inserting duplicate unique values raises DatabaseConstraintError."""
    sqlite_mgr.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        ("u1", "duplicate_user", "hash1", "2026-11-05T00:00:00Z"),
    )

    with pytest.raises(DatabaseConstraintError):
        sqlite_mgr.execute(
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
            ("u2", "duplicate_user", "hash2", "2026-11-05T00:00:00Z"),
        )


def test_sqlite_invalid_syntax_error(sqlite_mgr: SQLiteManager) -> None:
    """Verify SQL syntax errors raise DatabaseError cleanly."""
    with pytest.raises(DatabaseError):
        sqlite_mgr.execute("INVALID SQL SYNTAX STATEMENT;")

    with pytest.raises(DatabaseError):
        sqlite_mgr.fetch_one("SELECT FROM WHERE;")

    with pytest.raises(DatabaseError):
        sqlite_mgr.fetch_all("SELECT FROM WHERE;")


def test_sqlite_applied_migrations_retrieval(sqlite_mgr: SQLiteManager) -> None:
    """Verify get_applied_migrations returns version 1 metadata."""
    migrations = sqlite_mgr.get_applied_migrations()
    assert len(migrations) == 1
    assert migrations[0]["version"] == 1
    assert "Initial" in migrations[0]["description"]


def test_sqlite_connection_error_mapping() -> None:
    """Verify sqlite3.Error during connection creation raises DatabaseConnectionError."""
    mgr = SQLiteManager(db_path=":memory:")
    with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("Permission denied")):
        with pytest.raises(DatabaseConnectionError):
            mgr._create_raw_connection()


def test_sqlite_migration_error_mapping(tmp_path: Path) -> None:
    """Verify failure during migration execution raises DatabaseMigrationError."""
    mgr = SQLiteManager(db_path=tmp_path / "mig_fail.db")
    with patch.object(mgr, "get_connection") as mock_get_conn:
        mock_conn = MagicMock()
        mock_conn.execute.side_effect = sqlite3.OperationalError("Disk I/O error")
        mock_get_conn.return_value.__enter__.return_value = mock_conn

        with pytest.raises(DatabaseMigrationError):
            mgr.initialize_database()


def test_sqlite_transaction_constraint_violation(sqlite_mgr: SQLiteManager) -> None:
    """Verify transaction rolls back and raises DatabaseConstraintError on IntegrityError."""
    sqlite_mgr.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
        ("tx-dup-1", "unique_name", "hash", "2026-11-05T00:00:00Z"),
    )

    with pytest.raises(DatabaseConstraintError):
        with sqlite_mgr.transaction() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);",
                ("tx-dup-2", "unique_name", "hash2", "2026-11-05T00:00:00Z"),
            )

