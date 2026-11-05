"""Unit tests for CyberShield Authentication and RBAC Engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from database.repositories.user_repository import UserRepository
from security.auth import (
    AuthService,
    LoginRateLimiter,
    PasswordHasher,
    Permission,
    Role,
    Session,
    SessionManager,
)


# =============================================================================
# 1. Role and Hasher Tests
# =============================================================================

def test_role_parsing() -> None:
    """Verify role string parsing and fallback handling."""
    assert Role.from_str("administrator") == Role.ADMINISTRATOR
    assert Role.from_str("Analyst") == Role.ANALYST
    assert Role.from_str("VIEWER") == Role.VIEWER
    assert Role.from_str("unknown_role") == Role.ANALYST


def test_password_hasher_success_and_verification() -> None:
    """Verify bcrypt password hashing and verification."""
    password = "SuperSecretPassphrase2026!"
    hashed = PasswordHasher.hash_password(password)

    assert hashed.startswith("$2b$")
    assert PasswordHasher.verify_password(password, hashed) is True
    assert PasswordHasher.verify_password("WrongPassword123!", hashed) is False
    assert PasswordHasher.verify_password("", hashed) is False
    assert PasswordHasher.verify_password(password, "") is False


def test_password_hasher_empty_and_corrupt() -> None:
    """Verify error handling on empty plaintext or corrupted hash."""
    with pytest.raises(ValueError, match="cannot be empty"):
        PasswordHasher.hash_password("")

    assert PasswordHasher.verify_password("any", "not_a_valid_bcrypt_hash") is False


# =============================================================================
# 2. Rate Limiter Tests
# =============================================================================

def test_rate_limiter_lockout_and_reset() -> None:
    """Verify lockout after repeated failures and reset on success."""
    limiter = LoginRateLimiter(max_attempts=3, lockout_duration_seconds=60)
    key = "analyst_alice:127.0.0.1"

    # 1. Initial state
    locked, rem = limiter.is_locked(key)
    assert not locked
    assert rem == 0

    # 2. Record 2 failures -> not locked
    limiter.record_failure(key)
    attempts, locked, rem = limiter.record_failure(key)
    assert attempts == 2
    assert not locked

    # 3. 3rd failure -> locked
    attempts, locked, rem = limiter.record_failure(key)
    assert attempts == 3
    assert locked
    assert rem > 0

    is_l, rem_l = limiter.is_locked(key)
    assert is_l
    assert rem_l > 0

    # 4. Reset on success
    limiter.record_success(key)
    is_l_after, _ = limiter.is_locked(key)
    assert not is_l_after


def test_rate_limiter_expiration() -> None:
    """Verify lock expiration clears lockout."""
    limiter = LoginRateLimiter(max_attempts=1, lockout_duration_seconds=1)
    key = "user:ip"
    limiter.record_failure(key)

    with patch("time.time", return_value=100000.0):
        # Manually trigger lock
        limiter._locked_until[key] = 99999.0  # past lock
        is_l, _ = limiter.is_locked(key)
        assert not is_l
        assert key not in limiter._locked_until


# =============================================================================
# 3. Session Manager Tests
# =============================================================================

def test_session_manager_lifecycle() -> None:
    """Verify session creation, lookup, serialization, and expiration."""
    sm = SessionManager(default_duration_seconds=10)
    sess = sm.create_session(user_id="u-123", username="soc_bob", role=Role.ANALYST)

    assert sess.username == "soc_bob"
    assert sess.role == Role.ANALYST
    assert not sess.is_expired

    d = sess.to_dict()
    assert d["username"] == "soc_bob"
    assert d["role"] == "analyst"

    # Lookup
    fetched = sm.get_session(sess.token)
    assert fetched is not None
    assert fetched.user_id == "u-123"

    # Non-existent or empty token
    assert sm.get_session("") is None
    assert sm.get_session("non_existent_token") is None

    # Revoke session
    assert sm.revoke_session(sess.token) is True
    assert sm.get_session(sess.token) is None
    assert sm.revoke_session("non_existent_token") is False


def test_session_manager_expiry_and_multi_revoke() -> None:
    """Verify expired sessions return None and multi-session revocation."""
    sm = SessionManager()
    expired_sess = Session(
        token="exp_token",
        user_id="u-exp",
        username="expired_user",
        role=Role.VIEWER,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    sm._sessions["exp_token"] = expired_sess

    # Creating a new session triggers _purge_expired_locked
    s_new = sm.create_session("u-new", "new_user", Role.ANALYST)
    assert "exp_token" not in sm._sessions

    # get_session should purge expired session if present
    sm._sessions["exp_token_2"] = expired_sess
    assert sm.get_session("exp_token_2") is None

    # Revoke all for user
    s1 = sm.create_session("u-multi", "multi_user", Role.ANALYST)
    s2 = sm.create_session("u-multi", "multi_user", Role.ANALYST)
    assert sm.revoke_all_for_user("u-multi") == 2
    assert sm.get_session(s1.token) is None
    assert sm.get_session(s2.token) is None


# =============================================================================
# 4. AuthService Tests
# =============================================================================

@pytest.fixture
def mock_user_repo() -> MagicMock:
    """Fixture providing a mocked UserRepository."""
    repo = MagicMock(spec=UserRepository)
    repo.get_by_username.return_value = None
    repo.get_by_id.return_value = None
    repo.create.side_effect = lambda username, password_hash, role="analyst", is_active=1, **kwargs: {
        "id": "u-mock-id",
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "is_active": is_active,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return repo


def test_auth_service_registration_validation(mock_user_repo: MagicMock) -> None:
    """Verify registration input validation rules."""
    service = AuthService(mock_user_repo)

    # 1. Short username
    ok, msg, _ = service.register_user("ab", "ValidPassword123!")
    assert not ok
    assert "at least 3 characters" in msg

    # 2. Invalid characters
    ok, msg, _ = service.register_user("user@bad!char", "ValidPassword123!")
    assert not ok
    assert "invalid characters" in msg

    # 3. Short password
    ok, msg, _ = service.register_user("valid_user", "short")
    assert not ok
    assert "at least 8 characters" in msg

    # 4. Duplicate username
    mock_user_repo.get_by_username.return_value = {"id": "existing"}
    ok, msg, _ = service.register_user("duplicate_user", "ValidPassword123!")
    assert not ok
    assert "already exists" in msg


def test_auth_service_registration_success(mock_user_repo: MagicMock) -> None:
    """Verify successful user registration and password hashing."""
    service = AuthService(mock_user_repo)
    ok, msg, user = service.register_user("security_analyst", "SecurePassword123!", role=Role.ANALYST)

    assert ok is True
    assert "successfully" in msg
    assert user is not None
    assert user["username"] == "security_analyst"
    assert user["role"] == "analyst"
    assert "password_hash" not in user  # Never expose hash


def test_auth_service_authentication_flow(mock_user_repo: MagicMock) -> None:
    """Verify login authentication, failed attempts, and lockout."""
    service = AuthService(mock_user_repo)
    pw = "CorrectHorseStaple2026!"
    hashed_pw = PasswordHasher.hash_password(pw)

    mock_user_repo.get_by_username.return_value = {
        "id": "u-auth-1",
        "username": "lead_auditor",
        "password_hash": hashed_pw,
        "role": "administrator",
        "is_active": 1,
    }

    # 1. Success login
    ok, msg, session = service.authenticate_user("lead_auditor", pw)
    assert ok is True
    assert session is not None
    assert session.username == "lead_auditor"
    assert session.role == Role.ADMINISTRATOR

    # Validate session
    assert service.validate_session(session.token) is not None

    # 2. Logout
    assert service.logout_user(session.token) is True
    assert service.validate_session(session.token) is None

    # 3. Invalid password
    ok, msg, s_fail = service.authenticate_user("lead_auditor", "WrongPass123!")
    assert not ok
    assert "Invalid username or password" in msg
    assert s_fail is None

    # Test lockout trigger on max attempts
    service.rate_limiter.max_attempts = 2
    ok_l, msg_l, _ = service.authenticate_user("lead_auditor", "WrongPass123!")
    assert not ok_l
    assert "temporarily locked" in msg_l

    # Test already locked account attempt
    ok_al, msg_al, _ = service.authenticate_user("lead_auditor", pw)
    assert not ok_al
    assert "temporarily locked" in msg_al

    # 4. Unknown user
    mock_user_repo.get_by_username.return_value = None
    ok, msg, _ = service.authenticate_user("ghost_agent", "AnyPassword123!")
    assert not ok
    assert "Invalid username or password" in msg

    # 5. Inactive user
    mock_user_repo.get_by_username.return_value = {
        "id": "u-disabled",
        "username": "disabled_user",
        "password_hash": hashed_pw,
        "is_active": 0,
    }
    ok, msg, _ = service.authenticate_user("disabled_user", pw)
    assert not ok
    assert "Invalid username or password" in msg


def test_auth_service_rbac_permissions() -> None:
    """Verify role-based access control permissions matrix."""
    service = AuthService(MagicMock())
    now = datetime.now(timezone.utc)

    viewer = Session("t1", "u1", "viewer", Role.VIEWER, now, now + timedelta(hours=1))
    analyst = Session("t2", "u2", "analyst", Role.ANALYST, now, now + timedelta(hours=1))
    admin = Session("t3", "u3", "admin", Role.ADMINISTRATOR, now, now + timedelta(hours=1))

    # Viewer
    assert service.has_permission(viewer, Permission.VIEW_DASHBOARD) is True
    assert service.has_permission(viewer, Permission.SCAN_FILES) is False
    assert service.has_permission(viewer, Permission.CLOUD_SYNC) is False
    assert service.has_permission(viewer, Permission.MANAGE_USERS) is False

    # Analyst
    assert service.has_permission(analyst, Permission.VIEW_DASHBOARD) is True
    assert service.has_permission(analyst, Permission.SCAN_FILES) is True
    assert service.has_permission(analyst, Permission.ANALYZE_URLS) is True
    assert service.has_permission(analyst, Permission.CLOUD_SYNC) is True
    assert service.has_permission(analyst, Permission.MANAGE_USERS) is False

    # Administrator
    assert service.has_permission(admin, Permission.VIEW_DASHBOARD) is True
    assert service.has_permission(admin, Permission.CLOUD_SYNC) is True
    assert service.has_permission(admin, Permission.MANAGE_USERS) is True

    # Expired or None session
    assert service.has_permission(None, Permission.VIEW_DASHBOARD) is False
    exp_sess = Session("t4", "u4", "exp", Role.ADMINISTRATOR, now - timedelta(hours=2), now - timedelta(hours=1))
    assert service.has_permission(exp_sess, Permission.VIEW_DASHBOARD) is False


def test_auth_service_admin_user_management(mock_user_repo: MagicMock) -> None:
    """Verify administrator user management actions (roles, status, deletion)."""
    service = AuthService(mock_user_repo)
    now = datetime.now(timezone.utc)
    admin = Session("t-adm", "admin-1", "root", Role.ADMINISTRATOR, now, now + timedelta(hours=1))
    analyst = Session("t-ana", "analyst-1", "bob", Role.ANALYST, now, now + timedelta(hours=1))

    mock_user_repo.list_all.return_value = [
        {"id": "u1", "username": "alice", "role": "analyst", "is_active": 1, "created_at": "2026-11-05"},
    ]
    mock_user_repo.get_by_id.return_value = {"id": "u1", "username": "alice", "role": "analyst", "is_active": 1}
    mock_user_repo.update_role.return_value = True
    mock_user_repo.set_active_status.return_value = True
    mock_user_repo.delete.return_value = True

    # 1. List users
    users = service.list_users(admin)
    assert len(users) == 1
    assert users[0]["username"] == "alice"

    # 2. Update role (unauthorized analyst)
    ok, msg = service.update_user_role("u1", Role.ADMINISTRATOR, analyst)
    assert not ok
    assert "Access denied" in msg

    # Update role (admin success)
    ok, msg = service.update_user_role("u1", Role.ADMINISTRATOR, admin)
    assert ok is True
    assert "updated to administrator" in msg

    # Update role (target not found)
    mock_user_repo.get_by_id.return_value = None
    ok, msg = service.update_user_role("u-unknown", Role.VIEWER, admin)
    assert not ok
    assert "not found" in msg

    # 3. Status change
    mock_user_repo.get_by_id.return_value = {"id": "u1", "username": "alice"}
    # Admin self-deactivation prevented
    ok, msg = service.set_user_active_status("admin-1", False, admin)
    assert not ok
    assert "cannot deactivate their own account" in msg

    # Admin deactivates target
    ok, msg = service.set_user_active_status("u1", False, admin)
    assert ok is True
    assert "deactivated" in msg

    # Unauthorized analyst status change
    ok, msg = service.set_user_active_status("u1", False, analyst)
    assert not ok
    assert "Access denied" in msg

    # 4. Deletion
    # Admin self-delete prevented
    ok, msg = service.delete_user("admin-1", admin)
    assert not ok
    assert "cannot delete their own account" in msg

    # Admin deletes target
    ok, msg = service.delete_user("u1", admin)
    assert ok is True
    assert "deleted successfully" in msg

    # Unauthorized analyst deletion
    ok, msg = service.delete_user("u1", analyst)
    assert not ok
    assert "Access denied" in msg

    # Negative branches when repository operations fail
    mock_user_repo.get_by_id.return_value = {"id": "u1", "username": "alice"}
    mock_user_repo.update_role.return_value = False
    ok, msg = service.update_user_role("u1", Role.VIEWER, admin)
    assert not ok
    assert "Failed to update user role" in msg

    mock_user_repo.get_by_id.return_value = None
    ok, msg = service.set_user_active_status("u-ghost", True, admin)
    assert not ok
    assert "Target user not found" in msg

    mock_user_repo.get_by_id.return_value = {"id": "u1", "username": "alice"}
    mock_user_repo.set_active_status.return_value = False
    ok, msg = service.set_user_active_status("u1", True, admin)
    assert not ok
    assert "Failed to update account status" in msg

    mock_user_repo.delete.return_value = False
    ok, msg = service.delete_user("u1", admin)
    assert not ok
    assert "deletion failed" in msg
