"""Integration tests for Authentication, RBAC, and Hybrid Cloud Sync API routes."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from backend.api import create_app
from backend.services.database_service import (
    DatabaseService,
    reset_database_service,
)
from database.postgres_manager import PostgresManager
from security.auth import Role


@pytest.fixture
def api_client() -> TestClient:
    """Provide a TestClient connected to an isolated test SQLite database."""
    service = DatabaseService(backend_type="sqlite", db_path=":memory:", auto_init=True)
    # Ensure offline postgres for fast, deterministic unit test
    service.cloud_sync_engine.postgres = PostgresManager(database_url="")
    reset_database_service(service)
    app = create_app()
    client = TestClient(app)
    yield client
    reset_database_service(None)


def test_auth_api_registration_and_login_flow(api_client: TestClient) -> None:
    """Verify registration, login, profile query, and logout via HTTP endpoints."""
    # 1. Register a new analyst
    reg_payload = {
        "username": "api_analyst",
        "password": "SecurePassword2026!",
        "role": "analyst",
    }
    reg_resp = api_client.post("/api/auth/register", json=reg_payload)
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    assert reg_data["username"] == "api_analyst"
    assert reg_data["role"] == "analyst"
    assert "password_hash" not in reg_data
    analyst_id = reg_data["id"]

    # Test dependency provider get_user_repo
    from backend.dependencies import get_user_repo
    from backend.services.database_service import get_database_service
    assert get_user_repo(get_database_service()) is not None

    # Register validation failure
    bad_resp = api_client.post("/api/auth/register", json={"username": "ab", "password": "123"})
    assert bad_resp.status_code == 422  # Pydantic schema validation

    # Register duplicate failure
    dup_resp = api_client.post("/api/auth/register", json=reg_payload)
    assert dup_resp.status_code == 400
    assert "already exists" in dup_resp.json()["detail"]

    # 2. Login
    login_resp = api_client.post(
        "/api/auth/login",
        json={"username": "api_analyst", "password": "SecurePassword2026!"},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert "token" in login_data
    token = login_data["token"]
    assert login_data["user"]["username"] == "api_analyst"

    # Login failure
    fail_resp = api_client.post(
        "/api/auth/login",
        json={"username": "api_analyst", "password": "WrongPassword!"},
    )
    assert fail_resp.status_code == 401

    # Trigger lockout (5 failures)
    for _ in range(4):
        api_client.post(
            "/api/auth/login",
            json={"username": "api_analyst", "password": "WrongPassword!"},
        )
    lockout_resp = api_client.post(
        "/api/auth/login",
        json={"username": "api_analyst", "password": "WrongPassword!"},
    )
    assert lockout_resp.status_code == 429
    assert "locked" in lockout_resp.json()["detail"]

    # 3. /me endpoint
    # Without token
    assert api_client.get("/api/auth/me").status_code == 401
    # With invalid token
    assert api_client.get("/api/auth/me", headers={"X-Session-Token": "bogus"}).status_code == 401
    # With valid token
    me_resp = api_client.get("/api/auth/me", headers={"X-Session-Token": token})
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "api_analyst"

    # 4. Logout
    logout_resp = api_client.post("/api/auth/logout", headers={"X-Session-Token": token})
    assert logout_resp.status_code == 200

    # Token revoked
    assert api_client.get("/api/auth/me", headers={"X-Session-Token": token}).status_code == 401


def test_auth_api_admin_management_and_rbac(api_client: TestClient) -> None:
    """Verify administrator-only user management endpoints and RBAC enforcement."""
    # 1. Register Administrator
    admin_reg = api_client.post(
        "/api/auth/register",
        json={"username": "admin_root", "password": "AdminPassword2026!", "role": "administrator"},
    )
    assert admin_reg.status_code == 201
    admin_id = admin_reg.json()["id"]

    # Register regular Analyst
    analyst_reg = api_client.post(
        "/api/auth/register",
        json={"username": "regular_user", "password": "UserPassword2026!", "role": "analyst"},
    )
    assert analyst_reg.status_code == 201
    analyst_id = analyst_reg.json()["id"]

    # 2. Login both
    admin_token = api_client.post(
        "/api/auth/login",
        json={"username": "admin_root", "password": "AdminPassword2026!"},
    ).json()["token"]

    analyst_token = api_client.post(
        "/api/auth/login",
        json={"username": "regular_user", "password": "UserPassword2026!"},
    ).json()["token"]

    # 3. Test list users
    # Forbidden for analyst
    assert api_client.get("/api/auth/users", headers={"X-Session-Token": analyst_token}).status_code == 403
    # Allowed for admin
    users_resp = api_client.get("/api/auth/users", headers={"X-Session-Token": admin_token})
    assert users_resp.status_code == 200
    assert users_resp.json()["total"] >= 2

    # 4. Update role
    role_resp = api_client.patch(
        f"/api/auth/users/{analyst_id}/role",
        headers={"X-Session-Token": admin_token},
        json={"role": "viewer"},
    )
    assert role_resp.status_code == 200
    assert "updated" in role_resp.json()["message"]

    # Role update error on unknown user
    assert api_client.patch(
        "/api/auth/users/non-existent-user/role",
        headers={"X-Session-Token": admin_token},
        json={"role": "analyst"},
    ).status_code == 400

    # Status update error on unknown user
    assert api_client.patch(
        "/api/auth/users/non-existent-user/status",
        headers={"X-Session-Token": admin_token},
        json={"is_active": True},
    ).status_code == 400

    # Delete error on unknown user
    assert api_client.delete(
        "/api/auth/users/non-existent-user",
        headers={"X-Session-Token": admin_token},
    ).status_code == 400

    # 5. Update status
    # Self-deactivation forbidden
    self_deact = api_client.patch(
        f"/api/auth/users/{admin_id}/status",
        headers={"X-Session-Token": admin_token},
        json={"is_active": False},
    )
    assert self_deact.status_code == 400

    # Deactivate analyst
    deact_resp = api_client.patch(
        f"/api/auth/users/{analyst_id}/status",
        headers={"X-Session-Token": admin_token},
        json={"is_active": False},
    )
    assert deact_resp.status_code == 200

    # 6. Delete user
    # Self-deletion forbidden
    self_del = api_client.delete(f"/api/auth/users/{admin_id}", headers={"X-Session-Token": admin_token})
    assert self_del.status_code == 400

    # Delete analyst
    del_resp = api_client.delete(f"/api/auth/users/{analyst_id}", headers={"X-Session-Token": admin_token})
    assert del_resp.status_code == 200


def test_sync_api_endpoints(api_client: TestClient) -> None:
    """Verify hybrid cloud sync status query and trigger endpoints."""
    # Register and login an analyst
    api_client.post(
        "/api/auth/register",
        json={"username": "sync_operator", "password": "SyncPassword2026!", "role": "analyst"},
    )
    token = api_client.post(
        "/api/auth/login",
        json={"username": "sync_operator", "password": "SyncPassword2026!"},
    ).json()["token"]

    # Register viewer
    api_client.post(
        "/api/auth/register",
        json={"username": "sync_viewer", "password": "ViewerPassword2026!", "role": "viewer"},
    )
    v_token = api_client.post(
        "/api/auth/login",
        json={"username": "sync_viewer", "password": "ViewerPassword2026!"},
    ).json()["token"]

    # Viewer forbidden on sync endpoints
    assert api_client.get("/api/sync/status", headers={"X-Session-Token": v_token}).status_code == 403
    assert api_client.post("/api/sync/trigger", headers={"X-Session-Token": v_token}, json={}).status_code == 403

    # 1. GET /api/sync/status
    status_resp = api_client.get("/api/sync/status", headers={"X-Session-Token": token})
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert "cloud_status" in status_data
    assert "is_connected" in status_data
    assert "total_local_records" in status_data

    # 2. POST /api/sync/trigger
    sync_resp = api_client.post(
        "/api/sync/trigger",
        headers={"X-Session-Token": token},
        json={"direction": "BIDIRECTIONAL", "max_retries": 1},
    )
    assert sync_resp.status_code == 200
    sync_data = sync_resp.json()
    assert "status" in sync_data
    assert "records_uploaded" in sync_data
    assert "records_downloaded" in sync_data
    assert "conflicts" in sync_data
