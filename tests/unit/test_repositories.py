"""Unit tests for database repositories using a temporary SQLite database."""

from __future__ import annotations

from pathlib import Path
import pytest

from database.repositories import (
    FileIntegrityRepository,
    NetworkLogRepository,
    ScanRepository,
    ThreatRepository,
    URLAnalysisRepository,
    UserRepository,
)
from database.sqlite_manager import SQLiteManager


@pytest.fixture
def test_db(tmp_path: Path) -> SQLiteManager:
    """Provide an initialized SQLite database in a temporary directory."""
    db_file = tmp_path / "repo_test.db"
    mgr = SQLiteManager(db_path=db_file)
    mgr.initialize_database()
    yield mgr
    mgr.close()


# =============================================================================
# 1. User Repository Tests
# =============================================================================

def test_user_repository_crud(test_db: SQLiteManager) -> None:
    repo = UserRepository(test_db)

    # Create
    user = repo.create(username="soc_lead", password_hash="$2b$12$e8YkHashStringSample")
    assert user["username"] == "soc_lead"
    assert "id" in user
    user_id = user["id"]

    # Read by ID
    fetched_by_id = repo.get_by_id(user_id)
    assert fetched_by_id is not None
    assert fetched_by_id["username"] == "soc_lead"

    # Read by Username
    fetched_by_username = repo.get_by_username("soc_lead")
    assert fetched_by_username is not None
    assert fetched_by_username["id"] == user_id

    # List
    all_users = repo.list_all()
    assert len(all_users) == 1

    # Non-existent user
    assert repo.get_by_id("non-existent-id") is None
    assert repo.get_by_username("ghost_user") is None

    # Delete
    assert repo.delete(user_id) is True
    assert repo.get_by_id(user_id) is None
    assert repo.delete(user_id) is False


# =============================================================================
# 2. Scan History Repository Tests
# =============================================================================

def test_scan_repository_crud(test_db: SQLiteManager) -> None:
    repo = ScanRepository(test_db)

    # Create
    scan = repo.create(
        scan_type="PORT_SCAN",
        target="192.168.1.1",
        result="Found ports 22, 80, 443 open",
    )
    assert scan["scan_type"] == "PORT_SCAN"
    scan_id = scan["id"]

    # Read
    fetched = repo.get_by_id(scan_id)
    assert fetched is not None
    assert fetched["target"] == "192.168.1.1"

    # List
    scans = repo.list_all(limit=10)
    assert len(scans) == 1

    # Delete
    assert repo.delete(scan_id) is True
    assert repo.get_by_id(scan_id) is None


# =============================================================================
# 3. Threat Repository Tests
# =============================================================================

def test_threat_repository_crud(test_db: SQLiteManager) -> None:
    scan_repo = ScanRepository(test_db)
    threat_repo = ThreatRepository(test_db)

    scan = scan_repo.create(scan_type="LOG_AUDIT", target="auth.log", result="Multiple auth failures")
    scan_id = scan["id"]

    # Create threat
    threat = threat_repo.create(
        scan_id=scan_id,
        threat_type="SSH_BRUTE_FORCE",
        severity="CRITICAL",
        description="Repeated failed root login attempts from external IP",
    )
    assert threat["severity"] == "CRITICAL"
    threat_id = threat["id"]

    # Read by ID
    fetched = threat_repo.get_by_id(threat_id)
    assert fetched is not None
    assert fetched["threat_type"] == "SSH_BRUTE_FORCE"

    # List by Scan ID
    threats_for_scan = threat_repo.list_by_scan(scan_id)
    assert len(threats_for_scan) == 1
    assert threats_for_scan[0]["id"] == threat_id

    # List All
    all_threats = threat_repo.list_all()
    assert len(all_threats) == 1

    # Delete
    assert threat_repo.delete(threat_id) is True
    assert threat_repo.get_by_id(threat_id) is None


# =============================================================================
# 4. File Integrity Repository Tests
# =============================================================================

def test_file_integrity_repository_crud(test_db: SQLiteManager) -> None:
    repo = FileIntegrityRepository(test_db)

    file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    record = repo.create(file_name="/etc/shadow", file_hash=file_hash)
    rec_id = record["id"]

    # Read by ID
    fetched = repo.get_by_id(rec_id)
    assert fetched is not None
    assert fetched["file_name"] == "/etc/shadow"

    # Read by Hash
    fetched_by_hash = repo.get_by_hash(file_hash)
    assert fetched_by_hash is not None
    assert fetched_by_hash["id"] == rec_id

    # List All
    all_recs = repo.list_all()
    assert len(all_recs) == 1

    # Delete
    assert repo.delete(rec_id) is True
    assert repo.get_by_id(rec_id) is None


# =============================================================================
# 5. URL Analysis Repository Tests
# =============================================================================

def test_url_analysis_repository_crud(test_db: SQLiteManager) -> None:
    repo = URLAnalysisRepository(test_db)

    analysis = repo.create(
        url="http://malicious-phishing-test.com/login",
        risk_score=85.5,
        risk_level="MALICIOUS",
    )
    rec_id = analysis["id"]

    # Read by ID
    fetched = repo.get_by_id(rec_id)
    assert fetched is not None
    assert fetched["risk_level"] == "MALICIOUS"
    assert fetched["risk_score"] == 85.5

    # Read by URL
    fetched_by_url = repo.get_by_url("http://malicious-phishing-test.com/login")
    assert fetched_by_url is not None
    assert fetched_by_url["id"] == rec_id

    # List All
    records = repo.list_all()
    assert len(records) == 1

    # Delete
    assert repo.delete(rec_id) is True
    assert repo.get_by_id(rec_id) is None


# =============================================================================
# 6. Network Log Repository Tests
# =============================================================================

def test_network_log_repository_crud(test_db: SQLiteManager) -> None:
    repo = NetworkLogRepository(test_db)

    log = repo.create(
        local_address="192.168.1.10:49212",
        remote_address="203.0.113.5:443",
        connection_status="ESTABLISHED",
    )
    rec_id = log["id"]

    # Read by ID
    fetched = repo.get_by_id(rec_id)
    assert fetched is not None
    assert fetched["connection_status"] == "ESTABLISHED"

    # List All
    logs = repo.list_all()
    assert len(logs) == 1

    # Delete
    assert repo.delete(rec_id) is True
    assert repo.get_by_id(rec_id) is None

