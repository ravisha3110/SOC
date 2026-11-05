"""CyberShield Local SQLite Database Manager.

Manages offline data storage, schema migrations, parameterized queries,
transactions, and connection lifecycles using Python's standard sqlite3 module.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any, Generator, Sequence

from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
    DatabaseMigrationError,
)
from database.schema import SQLITE_MIGRATION_001


class SQLiteManager:
    """Manages the local SQLite database for offline operations."""

    def __init__(self, db_path: str | Path = "database/cybershield.db") -> None:
        self.db_path_str = str(db_path)
        self.is_memory = self.db_path_str == ":memory:"
        self._memory_conn: sqlite3.Connection | None = None

        if not self.is_memory:
            self.db_path = Path(db_path).resolve()
            # Ensure parent directories exist
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.db_path = Path(":memory:")

    def _create_raw_connection(self) -> sqlite3.Connection:
        """Create a new raw connection with Row factory and foreign keys enabled."""
        try:
            target = ":memory:" if self.is_memory else str(self.db_path)
            conn = sqlite3.connect(target, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except sqlite3.Error as exc:
            raise DatabaseConnectionError(f"Failed to connect to SQLite at {self.db_path_str}: {exc}") from exc

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a managed database connection context."""
        if self.is_memory:
            if self._memory_conn is None:
                self._memory_conn = self._create_raw_connection()
            yield self._memory_conn
        else:
            conn = self._create_raw_connection()
            try:
                yield conn
            finally:
                conn.close()

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Execute multiple statements inside a managed atomic transaction."""
        with self.get_connection() as conn:
            try:
                yield conn
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise DatabaseConstraintError(f"Transaction constraint violation: {exc}") from exc
            except Exception as exc:
                conn.rollback()
                raise DatabaseError(f"Transaction failed and was rolled back: {exc}") from exc

    def initialize_database(self) -> None:
        """Apply all pending versioned migrations to the local database safely."""
        with self.get_connection() as conn:
            try:
                # 1. Ensure migrations table exists
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TEXT NOT NULL,
                        description TEXT NOT NULL
                    );
                    """
                )
                conn.commit()

                # 2. Check applied migrations
                cursor = conn.execute("SELECT version FROM schema_migrations ORDER BY version ASC;")
                applied_versions = {row["version"] for row in cursor.fetchall()}

                # 3. Apply migration 001 if pending
                if 1 not in applied_versions:
                    conn.executescript(SQLITE_MIGRATION_001)
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?);",
                        (1, now_iso, "Initial application schema with 6 core tables"),
                    )
                    conn.commit()

            except sqlite3.Error as exc:
                raise DatabaseMigrationError(f"SQLite migration failed: {exc}") from exc

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        """Execute a parameterized DML statement (INSERT/UPDATE/DELETE).

        Args:
            query: SQL statement with ? placeholders.
            params: Values tuple to bind safely.

        Returns:
            int: Number of affected rows or last inserted row ID.
        """
        # Convert any %s placeholders to ? for SQLite compatibility
        formatted_query = query.replace("%s", "?")
        with self.get_connection() as conn:
            try:
                cursor = conn.execute(formatted_query, params)
                conn.commit()
                return cursor.rowcount
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise DatabaseConstraintError(f"Constraint violation: {exc}") from exc
            except sqlite3.Error as exc:
                conn.rollback()
                raise DatabaseError(f"SQLite query execution error: {exc}") from exc

    def fetch_one(self, query: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        """Fetch a single record as a dictionary.

        Args:
            query: SQL query with ? placeholders.
            params: Parameter values tuple.

        Returns:
            dict or None if no record matches.
        """
        formatted_query = query.replace("%s", "?")
        with self.get_connection() as conn:
            try:
                cursor = conn.execute(formatted_query, params)
                row = cursor.fetchone()
                return dict(row) if row is not None else None
            except sqlite3.Error as exc:
                raise DatabaseError(f"SQLite query error: {exc}") from exc

    def fetch_all(self, query: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        """Fetch all matching records as a list of dictionaries.

        Args:
            query: SQL query with ? placeholders.
            params: Parameter values tuple.

        Returns:
            list[dict]: List of matching records.
        """
        formatted_query = query.replace("%s", "?")
        with self.get_connection() as conn:
            try:
                cursor = conn.execute(formatted_query, params)
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            except sqlite3.Error as exc:
                raise DatabaseError(f"SQLite query error: {exc}") from exc

    def get_applied_migrations(self) -> list[dict[str, Any]]:
        """Return list of all applied schema migrations."""
        return self.fetch_all("SELECT version, applied_at, description FROM schema_migrations ORDER BY version ASC;")

    def close(self) -> None:
        """Close any cached connection (primarily for in-memory databases)."""
        if self._memory_conn is not None:
            try:
                self._memory_conn.close()
            except Exception:  # pragma: no cover
                pass
            self._memory_conn = None
