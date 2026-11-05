"""User Repository.

Handles user profile data storage and retrieval.
Notice: Does NOT store plaintext passwords; only stores cryptographic hashes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import uuid


class DatabaseExecutor(Protocol):
    """Protocol for database query execution (satisfied by both SQLite and Postgres managers)."""

    def execute(self, query: str, params: tuple | list = ()) -> int: ...
    def fetch_one(self, query: str, params: tuple | list = ()) -> dict[str, Any] | None: ...
    def fetch_all(self, query: str, params: tuple | list = ()) -> list[dict[str, Any]]: ...


class UserRepository:
    """Data access repository for users table with role-based access metadata."""

    def __init__(self, db: DatabaseExecutor) -> None:
        self.db = db
        self._ensure_role_table()

    def _ensure_role_table(self) -> None:
        """Ensure the auxiliary user_roles table exists for RBAC metadata."""
        try:
            self.db.execute(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    is_active INTEGER NOT NULL DEFAULT 1
                );
                """
            )
        except Exception:
            # Table already initialized or managed by migrations
            pass

    def create(
        self,
        username: str,
        password_hash: str,
        user_id: str | None = None,
        created_at: str | None = None,
        role: str = "analyst",
        is_active: bool | int = 1,
    ) -> dict[str, Any]:
        """Create a new user record.

        Args:
            username: Unique username string.
            password_hash: Cryptographic hash of password (never plaintext).
            user_id: Optional explicit UUID string.
            created_at: Optional ISO-8601 timestamp string.
            role: Assigned role ('administrator', 'analyst', 'viewer').
            is_active: Account status flag (1 for active, 0 for disabled).

        Returns:
            dict: The created user record.
        """
        record_id = user_id or str(uuid.uuid4())
        created_time = created_at or datetime.now(timezone.utc).isoformat()
        normalized_role = role.strip().lower()
        active_flag = 1 if is_active else 0

        query = "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?);"
        self.db.execute(query, (record_id, username.strip(), password_hash, created_time))

        try:
            role_query = "INSERT INTO user_roles (user_id, role, is_active) VALUES (?, ?, ?);"
            self.db.execute(role_query, (record_id, normalized_role, active_flag))
        except Exception:
            pass

        return self.get_by_id(record_id) or {
            "id": record_id,
            "username": username.strip(),
            "password_hash": password_hash,
            "created_at": created_time,
            "role": normalized_role,
            "is_active": active_flag,
        }

    def get_by_id(self, user_id: str) -> dict[str, Any] | None:
        """Fetch user by primary key ID with role and status."""
        query = (
            "SELECT u.id, u.username, u.password_hash, u.created_at, "
            "COALESCE(r.role, 'analyst') AS role, "
            "COALESCE(r.is_active, 1) AS is_active "
            "FROM users u "
            "LEFT JOIN user_roles r ON u.id = r.user_id "
            "WHERE u.id = ?;"
        )
        return self.db.fetch_one(query, (user_id,))

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        """Fetch user by unique username with role and status."""
        query = (
            "SELECT u.id, u.username, u.password_hash, u.created_at, "
            "COALESCE(r.role, 'analyst') AS role, "
            "COALESCE(r.is_active, 1) AS is_active "
            "FROM users u "
            "LEFT JOIN user_roles r ON u.id = r.user_id "
            "WHERE u.username = ?;"
        )
        return self.db.fetch_one(query, (username.strip(),))

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all users up to the specified limit with role and status."""
        query = (
            "SELECT u.id, u.username, u.password_hash, u.created_at, "
            "COALESCE(r.role, 'analyst') AS role, "
            "COALESCE(r.is_active, 1) AS is_active "
            "FROM users u "
            "LEFT JOIN user_roles r ON u.id = r.user_id "
            "ORDER BY u.created_at DESC LIMIT ?;"
        )
        return self.db.fetch_all(query, (limit,))

    def update_role(self, user_id: str, new_role: str) -> bool:
        """Update role for a specified user."""
        normalized_role = new_role.strip().lower()
        existing = self.db.fetch_one("SELECT user_id FROM user_roles WHERE user_id = ?;", (user_id,))
        if existing:
            affected = self.db.execute("UPDATE user_roles SET role = ? WHERE user_id = ?;", (normalized_role, user_id))
        else:
            affected = self.db.execute(
                "INSERT INTO user_roles (user_id, role, is_active) VALUES (?, ?, 1);",
                (user_id, normalized_role),
            )
        return affected > 0

    def set_active_status(self, user_id: str, is_active: bool | int) -> bool:
        """Enable or disable user account access."""
        active_flag = 1 if is_active else 0
        existing = self.db.fetch_one("SELECT user_id FROM user_roles WHERE user_id = ?;", (user_id,))
        if existing:
            affected = self.db.execute("UPDATE user_roles SET is_active = ? WHERE user_id = ?;", (active_flag, user_id))
        else:
            affected = self.db.execute(
                "INSERT INTO user_roles (user_id, role, is_active) VALUES (?, 'analyst', ?);",
                (user_id, active_flag),
            )
        return affected > 0

    def delete(self, user_id: str) -> bool:
        """Delete user record and associated role metadata by ID."""
        try:
            self.db.execute("DELETE FROM user_roles WHERE user_id = ?;", (user_id,))
        except Exception:
            pass
        query = "DELETE FROM users WHERE id = ?;"
        affected = self.db.execute(query, (user_id,))
        return affected > 0

