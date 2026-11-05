"""CyberShield Cloud Neon PostgreSQL Database Manager.

Manages cloud PostgreSQL connections, migrations, and operations using Psycopg 3.
Ensures zero credential exposure in logs or exceptions, and provides safe connection
probing that fails gracefully when offline or when credentials are not configured.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
import re
from typing import Any, Generator, Sequence
from urllib.parse import urlparse

import psycopg
from psycopg.rows import dict_row

from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
    DatabaseMigrationError,
)
from database.schema import POSTGRES_MIGRATION_001


def sanitize_db_url(url: str) -> str:
    """Mask credentials in database URL to prevent credential leakage in logs/errors.

    Args:
        url: Full connection URL string.

    Returns:
        str: Sanitized URL with password masked as '***'.
    """
    if not url:
        return "[NOT CONFIGURED]"
    try:
        parsed = urlparse(url)
        if parsed.password:
            sanitized = url.replace(f":{parsed.password}@", ":***@")
            return sanitized
        return url
    except Exception:
        # Fallback regex mask for non-standard formats
        return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", url)


class PostgresManager:
    """Manages cloud Neon PostgreSQL database operations using Psycopg 3."""

    def __init__(self, database_url: str | None = None) -> None:
        if database_url is not None:
            self.raw_url = database_url.strip()
        else:
            self.raw_url = (
                os.getenv("NEON_DATABASE_URL")
                or os.getenv("DATABASE_URL")
                or ""
            ).strip()
        self.sanitized_url = sanitize_db_url(self.raw_url)
        self.last_error: str | None = None

    @property
    def is_configured(self) -> bool:
        """Check whether a non-empty cloud database URL is provided."""
        return bool(self.raw_url)

    def test_connection(self, timeout_seconds: int = 3) -> bool:
        """Probe cloud PostgreSQL connectivity without raising unhandled exceptions.

        Returns:
            bool: True if connection succeeded, False otherwise.
        """
        if not self.is_configured:
            self.last_error = "Database URL is not configured."
            return False

        try:
            with psycopg.connect(
                self.raw_url,
                connect_timeout=timeout_seconds,
                autocommit=True,
            ) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1;")
                    result = cur.fetchone()
                    if result and result[0] == 1:
                        self.last_error = None
                        return True
            return False
        except psycopg.OperationalError as exc:
            # Mask any internal details
            self.last_error = f"Network or authentication failure: {type(exc).__name__}"
            return False
        except Exception as exc:
            self.last_error = f"Connection failure: {type(exc).__name__}"
            return False

    @contextmanager
    def get_connection(self) -> Generator[psycopg.Connection, None, None]:
        """Provide a managed PostgreSQL connection with dict_row factory."""
        if not self.is_configured:
            raise DatabaseConnectionError("Cannot connect to cloud database: NEON_DATABASE_URL is not set.")

        try:
            conn = psycopg.connect(
                self.raw_url,
                row_factory=dict_row,
                autocommit=False,
            )
        except psycopg.OperationalError as exc:
            raise DatabaseConnectionError(
                f"Failed to connect to Neon PostgreSQL ({self.sanitized_url}): {type(exc).__name__}"
            ) from exc

        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:  # pragma: no cover
                pass

    @contextmanager
    def transaction(self) -> Generator[psycopg.Connection, None, None]:
        """Execute multiple statements inside an atomic PostgreSQL transaction."""
        with self.get_connection() as conn:
            try:
                yield conn
                conn.commit()
            except psycopg.IntegrityError as exc:
                conn.rollback()
                raise DatabaseConstraintError(f"PostgreSQL constraint violation: {exc}") from exc
            except Exception as exc:
                conn.rollback()
                raise DatabaseError(f"PostgreSQL transaction failed and was rolled back: {exc}") from exc

    def initialize_database(self) -> None:
        """Apply pending migrations to the PostgreSQL database safely."""
        with self.get_connection() as conn:
            try:
                with conn.cursor() as cur:
                    # 1. Ensure migrations table exists
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS schema_migrations (
                            version INTEGER PRIMARY KEY,
                            applied_at TIMESTAMPTZ NOT NULL,
                            description TEXT NOT NULL
                        );
                        """
                    )
                    conn.commit()

                    # 2. Check applied migrations
                    cur.execute("SELECT version FROM schema_migrations ORDER BY version ASC;")
                    rows = cur.fetchall()
                    applied_versions = {r["version"] for r in rows}

                    # 3. Apply migration 001 if pending
                    if 1 not in applied_versions:
                        cur.execute(POSTGRES_MIGRATION_001)
                        now_dt = datetime.now(timezone.utc)
                        cur.execute(
                            "INSERT INTO schema_migrations (version, applied_at, description) VALUES (%s, %s, %s);",
                            (1, now_dt, "Initial application schema with 6 core tables"),
                        )
                        conn.commit()
            except psycopg.Error as exc:
                raise DatabaseMigrationError(f"PostgreSQL migration failed: {exc}") from exc

    def execute(self, query: str, params: Sequence[Any] = ()) -> int:
        """Execute a parameterized DML query (INSERT/UPDATE/DELETE)."""
        formatted_query = query.replace("?", "%s")
        with self.get_connection() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(formatted_query, params)
                    conn.commit()
                    return cur.rowcount
            except psycopg.IntegrityError as exc:
                conn.rollback()
                raise DatabaseConstraintError(f"PostgreSQL constraint violation: {exc}") from exc
            except psycopg.Error as exc:
                conn.rollback()
                raise DatabaseError(f"PostgreSQL query execution error: {exc}") from exc

    def fetch_one(self, query: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        """Fetch a single record as a dictionary."""
        formatted_query = query.replace("?", "%s")
        with self.get_connection() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(formatted_query, params)
                    row = cur.fetchone()
                    return dict(row) if row is not None else None
            except psycopg.Error as exc:
                raise DatabaseError(f"PostgreSQL query error: {exc}") from exc

    def fetch_all(self, query: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        """Fetch all matching records as a list of dictionaries."""
        formatted_query = query.replace("?", "%s")
        with self.get_connection() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(formatted_query, params)
                    rows = cur.fetchall()
                    return [dict(r) for r in rows]
            except psycopg.Error as exc:
                raise DatabaseError(f"PostgreSQL query error: {exc}") from exc

    def get_applied_migrations(self) -> list[dict[str, Any]]:
        """Return list of all applied schema migrations."""
        return self.fetch_all("SELECT version, applied_at, description FROM schema_migrations ORDER BY version ASC;")
