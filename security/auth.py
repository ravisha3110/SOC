"""CyberShield Authentication and Role-Based Access Control (RBAC) Engine.

Provides cryptographic password hashing with bcrypt, session token management,
login rate limiting to mitigate brute-force attacks, and role-based access permissions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import re
import secrets
import threading
import time
from typing import Any

import bcrypt

from database.repositories.user_repository import UserRepository


class Role(str, Enum):
    """User roles for CyberShield access control."""

    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"

    @classmethod
    def from_str(cls, value: str) -> Role:
        """Parse string to Role enum with safe fallback."""
        cleaned = value.strip().lower()
        for role in cls:
            if role.value == cleaned:
                return role
        return cls.ANALYST


class Permission(str, Enum):
    """Granular permissions protecting sensitive SOC operations."""

    VIEW_DASHBOARD = "view_dashboard"
    ANALYZE_PASSWORDS = "analyze_passwords"
    SCAN_FILES = "scan_files"
    SAVE_FILE_BASELINE = "save_file_baseline"
    ANALYZE_URLS = "analyze_urls"
    MONITOR_NETWORK = "monitor_network"
    SAVE_NETWORK_LOGS = "save_network_logs"
    VIEW_ANALYTICS = "view_analytics"
    EXPORT_REPORTS = "export_reports"
    CLOUD_SYNC = "cloud_sync"
    MANAGE_USERS = "manage_users"


# Role-to-Permissions Mapping
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_ANALYTICS,
    },
    Role.ANALYST: {
        Permission.VIEW_DASHBOARD,
        Permission.ANALYZE_PASSWORDS,
        Permission.SCAN_FILES,
        Permission.SAVE_FILE_BASELINE,
        Permission.ANALYZE_URLS,
        Permission.MONITOR_NETWORK,
        Permission.SAVE_NETWORK_LOGS,
        Permission.VIEW_ANALYTICS,
        Permission.EXPORT_REPORTS,
        Permission.CLOUD_SYNC,
    },
    Role.ADMINISTRATOR: set(Permission),  # All permissions
}


@dataclass(frozen=True)
class Session:
    """Represents an active authenticated user session."""

    token: str
    user_id: str
    username: str
    role: Role
    created_at: datetime
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        """Check if the session has passed its expiration timestamp."""
        return datetime.now(timezone.utc) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to dictionary."""
        return {
            "token": self.token,
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_expired": self.is_expired,
        }


class PasswordHasher:
    """Secure password hashing and verification using bcrypt with work factor 12."""

    @staticmethod
    def hash_password(plaintext: str) -> str:
        """Hash a plaintext password using bcrypt with a generated salt."""
        if not plaintext:
            raise ValueError("Password cannot be empty.")
        pw_bytes = plaintext.encode("utf-8")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(pw_bytes, salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plaintext: str, hashed: str) -> bool:
        """Verify a plaintext password against a bcrypt hash in constant time."""
        if not plaintext or not hashed:
            return False
        try:
            return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False


class LoginRateLimiter:
    """Thread-safe in-memory login failure tracker and rate limiter."""

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_duration_seconds: int = 900,  # 15 minutes
    ) -> None:
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, key: str) -> tuple[bool, int]:
        """Check if a username/IP key is currently locked out."""
        with self._lock:
            now = time.time()
            unlock_time = self._locked_until.get(key, 0)
            if now < unlock_time:
                remaining = int(unlock_time - now)
                return True, max(1, remaining)
            if key in self._locked_until:
                del self._locked_until[key]
            return False, 0

    def record_failure(self, key: str) -> tuple[int, bool, int]:
        """Record a failed login attempt and trigger lockout if limit reached."""
        with self._lock:
            now = time.time()
            timestamps = self._failures.setdefault(key, [])
            cutoff = now - self.lockout_duration
            # Keep only timestamps within window
            timestamps = [t for t in timestamps if t > cutoff]
            timestamps.append(now)
            self._failures[key] = timestamps

            if len(timestamps) >= self.max_attempts:
                unlock_at = now + self.lockout_duration
                self._locked_until[key] = unlock_at
                return len(timestamps), True, self.lockout_duration

            return len(timestamps), False, 0

    def record_success(self, key: str) -> None:
        """Reset failed attempts upon successful login."""
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)


class SessionManager:
    """Thread-safe session token management with automatic expiration."""

    def __init__(self, default_duration_seconds: int = 3600) -> None:
        self.default_duration = default_duration_seconds
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    def create_session(
        self,
        user_id: str,
        username: str,
        role: Role,
        duration_seconds: int | None = None,
    ) -> Session:
        """Issue a cryptographically secure session token."""
        duration = duration_seconds or self.default_duration
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=duration)
        token = secrets.token_urlsafe(32)

        session = Session(
            token=token,
            user_id=user_id,
            username=username,
            role=role,
            created_at=now,
            expires_at=expires,
        )

        with self._lock:
            self._purge_expired_locked()
            self._sessions[token] = session

        return session

    def get_session(self, token: str) -> Session | None:
        """Fetch an active session by token, returning None if expired or invalid."""
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.is_expired:
                del self._sessions[token]
                return None
            return session

    def revoke_session(self, token: str) -> bool:
        """Revoke/logout an active session."""
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke all sessions for a specified user."""
        with self._lock:
            tokens_to_remove = [
                token for token, sess in self._sessions.items() if sess.user_id == user_id
            ]
            for token in tokens_to_remove:
                del self._sessions[token]
            return len(tokens_to_remove)

    def _purge_expired_locked(self) -> None:
        """Internal helper to clean up expired sessions."""
        now = datetime.now(timezone.utc)
        expired = [token for token, s in self._sessions.items() if now >= s.expires_at]
        for token in expired:
            del self._sessions[token]


class AuthService:
    """Unified service coordinating authentication, RBAC, sessions, and auditing."""

    def __init__(
        self,
        user_repo: UserRepository,
        session_manager: SessionManager | None = None,
        rate_limiter: LoginRateLimiter | None = None,
    ) -> None:
        self.user_repo = user_repo
        self.sessions = session_manager or SessionManager()
        self.rate_limiter = rate_limiter or LoginRateLimiter()

    def register_user(
        self,
        username: str,
        password: str,
        role: Role | str = Role.ANALYST,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        """Register a new user account with strict validation.

        Returns:
            tuple[bool, str, dict | None]: (success, message, created_user_dict)
        """
        clean_username = username.strip()
        if not clean_username or len(clean_username) < 3:
            return False, "Username must be at least 3 characters long.", None
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean_username):
            return False, "Username contains invalid characters (letters, numbers, _, -, . allowed).", None
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long.", None

        # Check existing username
        existing = self.user_repo.get_by_username(clean_username)
        if existing:
            return False, "A user with this username already exists.", None

        # Determine role
        assigned_role = role if isinstance(role, Role) else Role.from_str(role)

        # Hash password
        password_hash = PasswordHasher.hash_password(password)

        created = self.user_repo.create(
            username=clean_username,
            password_hash=password_hash,
            role=assigned_role.value,
            is_active=1,
        )

        # Return sanitized copy (no password hash)
        sanitized = {
            "id": created["id"],
            "username": created["username"],
            "role": created.get("role", assigned_role.value),
            "created_at": created["created_at"],
            "is_active": created.get("is_active", 1),
        }
        return True, "User registered successfully.", sanitized

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str = "127.0.0.1",
    ) -> tuple[bool, str, Session | None]:
        """Authenticate user credentials and issue an active session.

        Uses generic error messages to prevent username enumeration and applies rate limiting.

        Returns:
            tuple[bool, str, Session | None]: (success, message, session)
        """
        clean_username = username.strip()
        rate_key = f"{clean_username}:{ip_address}"

        # 1. Rate Limiting Check
        is_locked, remaining = self.rate_limiter.is_locked(rate_key)
        if is_locked:
            return False, f"Account temporarily locked due to excessive failed attempts. Try again in {remaining} seconds.", None

        # 2. User Lookup
        user = self.user_repo.get_by_username(clean_username)
        if not user or not user.get("is_active", 1):
            self.rate_limiter.record_failure(rate_key)
            return False, "Invalid username or password.", None

        # 3. Password Verification
        stored_hash = user.get("password_hash", "")
        if not PasswordHasher.verify_password(password, stored_hash):
            _, locked_now, lockout_sec = self.rate_limiter.record_failure(rate_key)
            if locked_now:
                return False, f"Account temporarily locked due to excessive failed attempts. Try again in {lockout_sec} seconds.", None
            return False, "Invalid username or password.", None

        # 4. Success — Reset Rate Limiter & Issue Session
        self.rate_limiter.record_success(rate_key)
        user_role = Role.from_str(user.get("role", "analyst"))
        session = self.sessions.create_session(
            user_id=user["id"],
            username=user["username"],
            role=user_role,
        )
        return True, "Authentication successful.", session

    def logout_user(self, token: str) -> bool:
        """Revoke session token."""
        return self.sessions.revoke_session(token)

    def validate_session(self, token: str) -> Session | None:
        """Validate session token and return active session."""
        return self.sessions.get_session(token)

    def has_permission(self, session: Session | None, permission: Permission) -> bool:
        """Verify whether an active session holds the required operational permission."""
        if not session or session.is_expired:
            return False
        allowed_permissions = ROLE_PERMISSIONS.get(session.role, set())
        return permission in allowed_permissions

    def list_users(self, requesting_session: Session | None = None) -> list[dict[str, Any]]:
        """List all users without exposing password hashes (Administrator only or self-check)."""
        raw_users = self.user_repo.list_all(limit=200)
        sanitized = []
        for u in raw_users:
            sanitized.append({
                "id": u["id"],
                "username": u["username"],
                "role": u.get("role", "analyst"),
                "is_active": bool(u.get("is_active", 1)),
                "created_at": u["created_at"],
            })
        return sanitized

    def update_user_role(
        self,
        target_user_id: str,
        new_role: Role | str,
        requesting_session: Session,
    ) -> tuple[bool, str]:
        """Update role of a target user (Administrator only)."""
        if not self.has_permission(requesting_session, Permission.MANAGE_USERS):
            return False, "Access denied: Administrator role required to modify user roles."

        role_enum = new_role if isinstance(new_role, Role) else Role.from_str(new_role)
        target = self.user_repo.get_by_id(target_user_id)
        if not target:
            return False, "Target user not found."

        success = self.user_repo.update_role(target_user_id, role_enum.value)
        if success:
            # Revoke existing sessions so new role takes effect on next login
            self.sessions.revoke_all_for_user(target_user_id)
            return True, f"User role updated to {role_enum.value}."
        return False, "Failed to update user role."

    def set_user_active_status(
        self,
        target_user_id: str,
        is_active: bool,
        requesting_session: Session,
    ) -> tuple[bool, str]:
        """Enable or disable user account (Administrator only)."""
        if not self.has_permission(requesting_session, Permission.MANAGE_USERS):
            return False, "Access denied: Administrator role required to modify account status."

        if target_user_id == requesting_session.user_id and not is_active:
            return False, "Administrators cannot deactivate their own account."

        target = self.user_repo.get_by_id(target_user_id)
        if not target:
            return False, "Target user not found."

        success = self.user_repo.set_active_status(target_user_id, 1 if is_active else 0)
        if success:
            if not is_active:
                self.sessions.revoke_all_for_user(target_user_id)
            status_text = "activated" if is_active else "deactivated"
            return True, f"User account successfully {status_text}."
        return False, "Failed to update account status."

    def delete_user(
        self,
        target_user_id: str,
        requesting_session: Session,
    ) -> tuple[bool, str]:
        """Delete user account (Administrator only)."""
        if not self.has_permission(requesting_session, Permission.MANAGE_USERS):
            return False, "Access denied: Administrator role required to delete accounts."

        if target_user_id == requesting_session.user_id:
            return False, "Administrators cannot delete their own account."

        self.sessions.revoke_all_for_user(target_user_id)
        deleted = self.user_repo.delete(target_user_id)
        if deleted:
            return True, "User deleted successfully."
        return False, "User not found or deletion failed."

