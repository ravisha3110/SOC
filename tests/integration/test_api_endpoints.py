"""Integration tests for CyberShield FastAPI REST API endpoints."""

from __future__ import annotations

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from backend.api import create_app
from backend.services.database_service import (
    DatabaseService,
    reset_database_service,
)
from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
)


@pytest.fixture
def test_client() -> TestClient:
    """Fixture providing a TestClient connected to an isolated in-memory SQLite database."""
    service = DatabaseService(backend_type="sqlite", db_path=":memory:", auto_init=True)
    reset_database_service(service)
    app = create_app()
    client = TestClient(app)
    yield client
    reset_database_service(None)


# -----------------------------------------------------------------------------
# 1. OpenAPI & Documentation Endpoints
# -----------------------------------------------------------------------------

def test_openapi_documentation_endpoints(test_client: TestClient) -> None:
    """Verify that OpenAPI documentation is generated and accessible."""
    docs_resp = test_client.get("/docs")
    assert docs_resp.status_code == 200

    redoc_resp = test_client.get("/redoc")
    assert redoc_resp.status_code == 200

    schema_resp = test_client.get("/openapi.json")
    assert schema_resp.status_code == 200
    schema_json = schema_resp.json()
    assert "CyberShield Threat Analytics API" in schema_json["info"]["title"]
    assert "/api/health" in schema_json["paths"]
    assert "/api/scans" in schema_json["paths"]
    assert "/api/threats" in schema_json["paths"]
    assert "/api/files" in schema_json["paths"]
    assert "/api/urls" in schema_json["paths"]
    assert "/api/network" in schema_json["paths"]


# -----------------------------------------------------------------------------
# 2. Health Endpoints
# -----------------------------------------------------------------------------

def test_application_health(test_client: TestClient) -> None:
    """Verify GET /api/health returns 200 OK and valid metadata."""
    response = test_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "CyberShield" in data["app_name"]
    assert data["version"] == "0.1.0"


def test_database_health_success(test_client: TestClient) -> None:
    """Verify GET /api/health/database returns 200 OK when database is responsive."""
    response = test_client.get("/api/health/database")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["connected"] is True
    assert data["backend"] == "sqlite"


def test_database_health_failure(test_client: TestClient) -> None:
    """Verify GET /api/health/database returns 503 when database is unresponsive."""
    with patch("backend.services.database_service.DatabaseService.check_database_health") as mock_health:
        mock_health.return_value = {
            "status": "unhealthy",
            "backend": "sqlite",
            "connected": False,
            "target": "database/cybershield.db",
            "details": "Connection refused",
        }
        response = test_client.get("/api/health/database")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["connected"] is False


# -----------------------------------------------------------------------------
# 3. Security Scans Endpoints
# -----------------------------------------------------------------------------

def test_scan_crud_flow(test_client: TestClient) -> None:
    """Verify complete lifecycle for security scan records."""
    # 1. Create a scan
    payload = {
        "scan_type": "PORT_SCAN",
        "target": "192.168.1.100",
        "result": '{"open_ports": [22, 80, 443]}',
    }
    create_resp = test_client.post("/api/scans", json=payload)
    assert create_resp.status_code == 201
    created_scan = create_resp.json()
    assert created_scan["scan_type"] == "PORT_SCAN"
    assert created_scan["target"] == "192.168.1.100"
    scan_id = created_scan["id"]

    # 2. Get scan by ID
    get_resp = test_client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == scan_id

    # 3. List scans with pagination
    list_resp = test_client.get("/api/scans?limit=10&offset=0")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1
    assert len(list_data["items"]) >= 1
    assert list_data["items"][0]["id"] == scan_id


def test_scan_get_not_found(test_client: TestClient) -> None:
    """Verify GET /api/scans/{scan_id} returns 404 for nonexistent ID."""
    response = test_client.get("/api/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# -----------------------------------------------------------------------------
# 4. Threats Endpoints
# -----------------------------------------------------------------------------

def test_threat_crud_flow(test_client: TestClient) -> None:
    """Verify threat finding creation, query by scan, and single get."""
    # First create a parent scan
    scan_resp = test_client.post(
        "/api/scans",
        json={
            "scan_type": "AUTH_AUDIT",
            "target": "auth.server.local",
            "result": "Multiple failed attempts",
        },
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # Create a threat attached to the scan
    threat_payload = {
        "scan_id": scan_id,
        "threat_type": "BRUTE_FORCE",
        "severity": "high",
        "description": "50 failed SSH logins from single IP",
    }
    create_threat = test_client.post("/api/threats", json=threat_payload)
    assert create_threat.status_code == 201
    threat_data = create_threat.json()
    assert threat_data["severity"] == "HIGH"
    threat_id = threat_data["id"]

    # Get threat by ID
    get_resp = test_client.get(f"/api/threats/{threat_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == threat_id

    # List threats filtered by scan_id
    filter_resp = test_client.get(f"/api/threats?scan_id={scan_id}")
    assert filter_resp.status_code == 200
    filter_data = filter_resp.json()
    assert filter_data["total"] == 1
    assert filter_data["items"][0]["id"] == threat_id


def test_threat_create_fails_for_nonexistent_scan(test_client: TestClient) -> None:
    """Verify creating a threat for an invalid scan_id returns 400 Bad Request."""
    invalid_scan_id = "00000000-0000-0000-0000-000000000000"
    threat_payload = {
        "scan_id": invalid_scan_id,
        "threat_type": "CVE_VULN",
        "severity": "CRITICAL",
        "description": "Remote code execution",
    }
    response = test_client.post("/api/threats", json=threat_payload)
    assert response.status_code == 400
    assert "does not exist" in response.json()["detail"].lower()


def test_threat_get_not_found(test_client: TestClient) -> None:
    """Verify GET /api/threats/{threat_id} returns 404 for missing threat."""
    response = test_client.get("/api/threats/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


# -----------------------------------------------------------------------------
# 5. File Integrity Endpoints
# -----------------------------------------------------------------------------

def test_file_integrity_crud_and_conflict(test_client: TestClient) -> None:
    """Verify file integrity baseline registration, duplicate conflict, and listing."""
    file_payload = {
        "file_name": "C:/Windows/System32/drivers/etc/hosts",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "record_id": "11111111-1111-1111-1111-111111111111",
    }
    create_resp = test_client.post("/api/files", json=file_payload)
    assert create_resp.status_code == 201
    assert create_resp.json()["file_name"] == file_payload["file_name"]

    # Duplicate primary key insertion should return 409 Conflict
    dup_resp = test_client.post("/api/files", json=file_payload)
    assert dup_resp.status_code == 409
    assert "constraint violation" in dup_resp.json()["detail"].lower()

    # List files
    list_resp = test_client.get("/api/files")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1


# -----------------------------------------------------------------------------
# 6. URL Security Analysis Endpoints
# -----------------------------------------------------------------------------

def test_url_analysis_crud_and_validation(test_client: TestClient) -> None:
    """Verify URL analysis registration, listing, and score validation."""
    url_payload = {
        "url": "https://suspicious-domain.tk/verify-account",
        "risk_score": 87.5,
        "risk_level": "malicious",
    }
    create_resp = test_client.post("/api/urls", json=url_payload)
    assert create_resp.status_code == 201
    assert create_resp.json()["risk_level"] == "MALICIOUS"
    assert create_resp.json()["risk_score"] == 87.5

    # List URLs
    list_resp = test_client.get("/api/urls")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # Out of bounds risk_score -> 422 Unprocessable Entity
    invalid_resp = test_client.post(
        "/api/urls",
        json={"url": "https://test.com", "risk_score": 150.0, "risk_level": "MALICIOUS"},
    )
    assert invalid_resp.status_code == 422


# -----------------------------------------------------------------------------
# 7. Network Connection Log Endpoints
# -----------------------------------------------------------------------------

def test_network_log_crud_and_listing(test_client: TestClient) -> None:
    """Verify network connection log creation and listing."""
    net_payload = {
        "local_address": "127.0.0.1:54321",
        "remote_address": "93.184.216.34:443",
        "connection_status": "established",
    }
    create_resp = test_client.post("/api/network", json=net_payload)
    assert create_resp.status_code == 201
    assert create_resp.json()["connection_status"] == "ESTABLISHED"

    # List network logs
    list_resp = test_client.get("/api/network")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1


# -----------------------------------------------------------------------------
# 8. Pagination and Query Limits
# -----------------------------------------------------------------------------

def test_pagination_limits_and_validation(test_client: TestClient) -> None:
    """Verify pagination bounds and validation behavior."""
    # Negative limit -> 422
    neg_resp = test_client.get("/api/scans?limit=-1")
    assert neg_resp.status_code == 422

    # Excessive limit (>100) -> 422
    over_resp = test_client.get("/api/scans?limit=500")
    assert over_resp.status_code == 422

    # Negative offset -> 422
    off_resp = test_client.get("/api/scans?offset=-5")
    assert off_resp.status_code == 422


# -----------------------------------------------------------------------------
# 9. Error Sanitization & Exception Handlers
# -----------------------------------------------------------------------------

def test_database_connection_error_sanitization(test_client: TestClient) -> None:
    """Verify DatabaseConnectionError returns 503 and masks internal credentials."""
    secret_db_url = "postgresql://admin:super_secret_password@db.neon.tech/cyber"
    with patch(
        "database.repositories.ScanRepository.create",
        side_effect=DatabaseConnectionError(f"Failed connecting to {secret_db_url}"),
    ):
        response = test_client.post(
            "/api/scans",
            json={"scan_type": "TEST", "target": "10.0.0.1", "result": "ok"},
        )
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert "super_secret_password" not in detail
        assert "Database connection unavailable" in detail


def test_internal_database_error_sanitization(test_client: TestClient) -> None:
    """Verify unexpected DatabaseError returns 500 without leaking stack traces."""
    with patch(
        "database.repositories.ScanRepository.create",
        side_effect=DatabaseError("FATAL: syntax error near confidential_table_token"),
    ):
        response = test_client.post(
            "/api/scans",
            json={"scan_type": "TEST", "target": "10.0.0.1", "result": "ok"},
        )
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "confidential_table_token" not in detail
        assert "internal database error" in detail.lower()


def test_threat_database_constraint_error_handling(test_client: TestClient) -> None:
    """Verify DatabaseConstraintError during threat creation raises 400 Bad Request."""
    scan_resp = test_client.post(
        "/api/scans",
        json={"scan_type": "TEST", "target": "10.0.0.1", "result": "ok"},
    )
    scan_id = scan_resp.json()["id"]

    with patch(
        "database.repositories.ThreatRepository.create",
        side_effect=DatabaseConstraintError("Foreign key violation"),
    ):
        response = test_client.post(
            "/api/threats",
            json={
                "scan_id": scan_id,
                "threat_type": "MALWARE",
                "severity": "HIGH",
                "description": "Found trojan",
            },
        )
        assert response.status_code == 400
        assert "Foreign key violation" in response.json()["detail"]


def test_threat_listing_without_filter(test_client: TestClient) -> None:
    """Verify listing threats without scan_id query parameter retrieves all threats."""
    resp = test_client.get("/api/threats")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


def test_record_not_found_global_exception_handler(test_client: TestClient) -> None:
    """Verify RecordNotFoundError is mapped to 404 Not Found by global handler."""
    from database.exceptions import RecordNotFoundError
    with patch("database.repositories.ScanRepository.get_by_id", side_effect=RecordNotFoundError("Record missing")):
        resp = test_client.get("/api/scans/12345678-1234-5678-1234-567812345678")
        assert resp.status_code == 404
        assert "Record missing" in resp.json()["detail"]


def test_database_constraint_error_global_handler(test_client: TestClient) -> None:
    """Verify uncaught DatabaseConstraintError returns 409 Conflict via global handler."""
    with patch(
        "database.repositories.ScanRepository.create",
        side_effect=DatabaseConstraintError("Unique index duplicate"),
    ):
        resp = test_client.post(
            "/api/scans",
            json={"scan_type": "PORT_SCAN", "target": "10.0.0.1", "result": "ok"},
        )
        assert resp.status_code == 409
        assert "Unique index duplicate" in resp.json()["detail"]


def test_cors_middleware_headers(test_client: TestClient) -> None:
    """Verify CORS response headers permit localhost origins."""
    resp = test_client.options(
        "/api/health",
        headers={
            "Origin": "http://127.0.0.1:8000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.headers.get("access-control-allow-origin") == "http://127.0.0.1:8000"
