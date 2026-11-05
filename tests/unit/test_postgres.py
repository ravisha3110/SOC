"""Unit tests for PostgresManager cloud Neon database connectivity (using mocks).

Ensures 100% offline test execution without requiring actual Neon credentials or internet.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import psycopg
import pytest

from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
    DatabaseMigrationError,
)
from database.postgres_manager import PostgresManager, sanitize_db_url


def test_sanitize_db_url() -> None:
    """Verify credentials in database connection URLs are masked."""
    # Standard URL with password
    url = "postgresql://analyst_user:SuperSecretPassword123@ep-cool-shield.neon.tech/cybershield?sslmode=require"
    sanitized = sanitize_db_url(url)
    assert "SuperSecretPassword123" not in sanitized
    assert ":***@" in sanitized
    assert "analyst_user" in sanitized
    assert "ep-cool-shield.neon.tech" in sanitized

    # URL without password
    no_pass_url = "postgresql://analyst_user@ep-cool-shield.neon.tech/cybershield"
    assert sanitize_db_url(no_pass_url) == no_pass_url

    # Empty URL
    assert sanitize_db_url("") == "[NOT CONFIGURED]"


def test_postgres_manager_configuration_resolution() -> None:
    """Verify configuration resolution from explicit args and environment variables."""
    # 1. Explicit arg
    mgr1 = PostgresManager(database_url="postgresql://usr:pass@host/db")
    assert mgr1.is_configured is True
    assert ":***@" in mgr1.sanitized_url

    # 2. NEON_DATABASE_URL environment variable
    with patch.dict(os.environ, {"NEON_DATABASE_URL": "postgresql://env_u:env_p@host/db"}, clear=True):
        mgr2 = PostgresManager()
        assert mgr2.is_configured is True
        assert "env_u" in mgr2.sanitized_url

    # 3. Standard DATABASE_URL fallback
    with patch.dict(os.environ, {"DATABASE_URL": "postgresql://db_u:db_p@host/db"}, clear=True):
        mgr3 = PostgresManager()
        assert mgr3.is_configured is True
        assert "db_u" in mgr3.sanitized_url

    # 4. Unconfigured
    with patch.dict(os.environ, {}, clear=True):
        mgr4 = PostgresManager(database_url="")
        assert mgr4.is_configured is False
        assert mgr4.sanitized_url == "[NOT CONFIGURED]"


def test_missing_database_url_behavior() -> None:
    """Verify that unconfigured manager fails gracefully without unhandled exceptions."""
    with patch.dict(os.environ, {"NEON_DATABASE_URL": "", "DATABASE_URL": ""}):
        mgr = PostgresManager(database_url="")
        assert mgr.is_configured is False

        # test_connection returns False with informative reason
        assert mgr.test_connection() is False
        assert "not configured" in mgr.last_error.lower()

        # get_connection raises clean DatabaseConnectionError
        with pytest.raises(DatabaseConnectionError):
            with mgr.get_connection():
                pass


def test_mocked_connection_success() -> None:
    """Verify test_connection returns True when psycopg.connect succeeds."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect") as mock_connect:
        mock_connect.return_value.__enter__.return_value = mock_conn

        success = mgr.test_connection(timeout_seconds=2)
        assert success is True
        assert mgr.last_error is None
        mock_connect.assert_called_once()


def test_mocked_connection_failure_masks_credentials() -> None:
    """Verify that connection failures record a sanitized error message."""
    mgr = PostgresManager(database_url="postgresql://usr:SensitiveSecret@ep-test.neon.tech/db")

    with patch("psycopg.connect", side_effect=psycopg.OperationalError("Simulated DNS timeout")):
        success = mgr.test_connection(timeout_seconds=1)
        assert success is False
        assert mgr.last_error is not None
        assert "SensitiveSecret" not in mgr.last_error


def test_postgres_crud_operations_mocked() -> None:
    """Verify execute, fetch_one, and fetch_all query parameterization and execution."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.rowcount = 1
    mock_cursor.fetchone.return_value = {"id": "u1", "username": "analyst"}
    mock_cursor.fetchall.return_value = [{"id": "u1", "username": "analyst"}]
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect", return_value=mock_conn):
        # Test execute (verifies ? placeholder is translated to %s)
        affected = mgr.execute("INSERT INTO users (id, username) VALUES (?, ?);", ("u1", "analyst"))
        assert affected == 1
        mock_cursor.execute.assert_called_with("INSERT INTO users (id, username) VALUES (%s, %s);", ("u1", "analyst"))

        # Test fetch_one
        row = mgr.fetch_one("SELECT * FROM users WHERE id = ?;", ("u1",))
        assert row["username"] == "analyst"

        # Test fetch_all
        rows = mgr.fetch_all("SELECT * FROM users;")
        assert len(rows) == 1


def test_postgres_transaction_commit_and_rollback_mocked() -> None:
    """Verify transaction commits on success and rolls back on exception."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")

    mock_conn = MagicMock()

    with patch("psycopg.connect", return_value=mock_conn):
        # 1. Successful transaction
        with mgr.transaction() as conn:
            pass
        mock_conn.commit.assert_called_once()

        # 2. Failed transaction with rollback
        mock_conn.reset_mock()
        with pytest.raises(DatabaseError):
            with mgr.transaction() as conn:
                raise ValueError("Simulated step failure")
        mock_conn.rollback.assert_called_once()


def test_postgres_constraint_error_mapping_mocked() -> None:
    """Verify psycopg.IntegrityError maps to DatabaseConstraintError."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = psycopg.IntegrityError("duplicate key value violates unique constraint")
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect", return_value=mock_conn):
        with pytest.raises(DatabaseConstraintError):
            mgr.execute("INSERT INTO users VALUES ('dup');")


def test_postgres_initialization_migration_mocked() -> None:
    """Verify initialize_database runs migration DDL and records version in migrations table."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    # Simulate empty migrations table
    mock_cursor.fetchall.return_value = []
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect", return_value=mock_conn):
        mgr.initialize_database()
        assert mock_cursor.execute.call_count >= 3
        mock_conn.commit.assert_called()


def test_postgres_applied_migrations_mocked() -> None:
    """Verify get_applied_migrations query execution."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [{"version": 1, "applied_at": "2026-11-05T00:00:00Z", "description": "Init"}]
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect", return_value=mock_conn):
        migrations = mgr.get_applied_migrations()
        assert len(migrations) == 1
        assert migrations[0]["version"] == 1


def test_postgres_test_connection_non_one_result() -> None:
    """Verify test_connection returns False if query result is not 1."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (0,)
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect") as mock_connect:
        mock_connect.return_value.__enter__.return_value = mock_conn
        assert mgr.test_connection() is False


def test_postgres_test_connection_generic_exception() -> None:
    """Verify test_connection records generic failure when an unknown exception occurs."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")
    with patch("psycopg.connect", side_effect=RuntimeError("System socket fault")):
        assert mgr.test_connection() is False
        assert "RuntimeError" in mgr.last_error


def test_postgres_get_connection_operational_error() -> None:
    """Verify get_connection raises DatabaseConnectionError on psycopg.OperationalError."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")
    with patch("psycopg.connect", side_effect=psycopg.OperationalError("Host unreachable")):
        with pytest.raises(DatabaseConnectionError):
            with mgr.get_connection():
                pass


def test_postgres_transaction_integrity_error_mapping() -> None:
    """Verify transaction rolls back and raises DatabaseConstraintError on psycopg.IntegrityError."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")
    mock_conn = MagicMock()

    with patch("psycopg.connect", return_value=mock_conn):
        with pytest.raises(DatabaseConstraintError):
            with mgr.transaction() as conn:
                raise psycopg.IntegrityError("Foreign key violation")
        mock_conn.rollback.assert_called_once()


def test_postgres_migration_error_mapping() -> None:
    """Verify initialize_database raises DatabaseMigrationError on psycopg.Error."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = psycopg.Error("Migration table creation failure")
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect", return_value=mock_conn):
        with pytest.raises(DatabaseMigrationError):
            mgr.initialize_database()


def test_postgres_query_error_mappings() -> None:
    """Verify execute, fetch_one, and fetch_all raise DatabaseError on psycopg.Error."""
    mgr = PostgresManager(database_url="postgresql://usr:pass@ep-test.neon.tech/db")
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = psycopg.Error("Syntax error")
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    with patch("psycopg.connect", return_value=mock_conn):
        with pytest.raises(DatabaseError):
            mgr.execute("SELECT 1")

        with pytest.raises(DatabaseError):
            mgr.fetch_one("SELECT 1")

        with pytest.raises(DatabaseError):
            mgr.fetch_all("SELECT 1")


def test_sanitize_db_url_fallback() -> None:
    """Verify sanitize_db_url falls back to regex masking on unparseable inputs."""
    with patch("database.postgres_manager.urlparse", side_effect=ValueError("Parse failed")):
        url = "postgresql://my_user:secret123@hostname:5432/db"
        sanitized = sanitize_db_url(url)
        assert "secret123" not in sanitized
        assert ":***@" in sanitized

