"""Unit tests for backend Pydantic validation schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.schemas.file import (
    FileIntegrityCreate,
    FileIntegrityResponse,
    FileListResponse,
)
from backend.schemas.network import (
    NetworkListResponse,
    NetworkLogCreate,
    NetworkLogResponse,
)
from backend.schemas.scan import (
    ScanCreate,
    ScanListResponse,
    ScanResponse,
)
from backend.schemas.threat import (
    ThreatCreate,
    ThreatListResponse,
    ThreatResponse,
)
from backend.schemas.url import (
    URLAnalysisCreate,
    URLAnalysisResponse,
    URLListResponse,
)


def test_scan_create_valid() -> None:
    """Verify valid ScanCreate payload instantiation."""
    payload = ScanCreate(
        scan_type="PORT_SCAN",
        target="127.0.0.1",
        result='{"open": [80]}',
    )
    assert payload.scan_type == "PORT_SCAN"
    assert payload.target == "127.0.0.1"
    assert payload.result == '{"open": [80]}'
    assert payload.scan_id is None


def test_scan_create_with_uuid_and_validation() -> None:
    """Verify ScanCreate validates UUID and forbids extra fields."""
    valid_uuid = "12345678-1234-5678-1234-567812345678"
    payload = ScanCreate(
        scan_type="PORT_SCAN",
        target="127.0.0.1",
        result="clean",
        scan_id=valid_uuid,
        created_at="2026-11-05T12:00:00Z",
    )
    assert payload.scan_id == valid_uuid

    with pytest.raises(ValidationError):
        ScanCreate(
            scan_type="PORT_SCAN",
            target="127.0.0.1",
            result="clean",
            scan_id="invalid-uuid-string",
        )

    with pytest.raises(ValidationError):
        ScanCreate(
            scan_type="PORT_SCAN",
            target="127.0.0.1",
            result="clean",
            extra_field="disallowed",  # type: ignore[call-arg]
        )


def test_scan_response_and_list() -> None:
    """Verify ScanResponse and ScanListResponse instantiation."""
    resp = ScanResponse(
        id="12345678-1234-5678-1234-567812345678",
        scan_type="PORT_SCAN",
        target="10.0.0.1",
        result="Findings",
        created_at="2026-11-05T00:00:00Z",
    )
    assert resp.id == "12345678-1234-5678-1234-567812345678"

    listing = ScanListResponse(items=[resp], total=1, limit=50, offset=0)
    assert listing.total == 1
    assert len(listing.items) == 1


def test_threat_create_validation() -> None:
    """Verify ThreatCreate severity normalization and UUID checks."""
    valid_scan = "12345678-1234-5678-1234-567812345678"
    valid_threat = "87654321-4321-8765-4321-876543210987"

    threat = ThreatCreate(
        scan_id=valid_scan,
        threat_type="BRUTE_FORCE",
        severity="critical",  # Lowercase should normalize to uppercase
        description="SSH Brute force detected",
        threat_id=valid_threat,
    )
    assert threat.severity == "CRITICAL"
    assert threat.scan_id == valid_scan
    assert threat.threat_id == valid_threat

    # Invalid severity
    with pytest.raises(ValidationError):
        ThreatCreate(
            scan_id=valid_scan,
            threat_type="BRUTE_FORCE",
            severity="FATAL_ERROR",
            description="Bad severity",
        )

    # Invalid scan_id UUID
    with pytest.raises(ValidationError):
        ThreatCreate(
            scan_id="non-uuid",
            threat_type="BRUTE_FORCE",
            severity="HIGH",
            description="Bad UUID",
        )

    # Invalid threat_id UUID
    with pytest.raises(ValidationError):
        ThreatCreate(
            scan_id=valid_scan,
            threat_type="BRUTE_FORCE",
            severity="HIGH",
            description="Bad threat ID",
            threat_id="not-a-uuid",
        )


def test_threat_response_and_list() -> None:
    """Verify ThreatResponse and ThreatListResponse models."""
    threat = ThreatResponse(
        id="87654321-4321-8765-4321-876543210987",
        scan_id="12345678-1234-5678-1234-567812345678",
        threat_type="CVE_VULN",
        severity="HIGH",
        description="Outdated Apache version",
        created_at="2026-11-05T00:00:00Z",
    )
    assert threat.severity == "HIGH"
    list_resp = ThreatListResponse(items=[threat], total=1, limit=50, offset=0)
    assert list_resp.total == 1


def test_file_integrity_validation() -> None:
    """Verify FileIntegrityCreate hash validation and lowercase normalization."""
    valid_sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    valid_uuid = "12345678-1234-5678-1234-567812345678"
    file_record = FileIntegrityCreate(
        file_name="/etc/passwd",
        file_hash=valid_sha256,
        record_id=valid_uuid,
    )
    assert file_record.file_hash == valid_sha256.lower()
    assert file_record.record_id == valid_uuid

    # Invalid non-hex hash
    with pytest.raises(ValidationError):
        FileIntegrityCreate(
            file_name="/etc/hosts",
            file_hash="NOT_HEX_CHARS_AT_ALL_SHOULD_FAIL_VALIDATION!!",
        )

    # Invalid record_id UUID
    with pytest.raises(ValidationError):
        FileIntegrityCreate(
            file_name="/etc/hosts",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            record_id="invalid-uuid",
        )

    # Valid response
    resp = FileIntegrityResponse(
        id="12345678-1234-5678-1234-567812345678",
        file_name="/etc/passwd",
        file_hash=valid_sha256.lower(),
        created_at="2026-11-05T00:00:00Z",
    )
    assert resp.file_name == "/etc/passwd"
    listing = FileListResponse(items=[resp], total=1, limit=50, offset=0)
    assert listing.total == 1


def test_url_analysis_validation() -> None:
    """Verify URLAnalysisCreate score range and classification validation."""
    valid_uuid = "12345678-1234-5678-1234-567812345678"
    valid_url = URLAnalysisCreate(
        url="https://malicious-site.example.com",
        risk_score=92.5,
        risk_level="malicious",
        analysis_id=valid_uuid,
    )
    assert valid_url.risk_level == "MALICIOUS"
    assert valid_url.risk_score == 92.5
    assert valid_url.analysis_id == valid_uuid

    # Out of bounds risk_score (>100)
    with pytest.raises(ValidationError):
        URLAnalysisCreate(
            url="https://test.example.com",
            risk_score=105.0,
            risk_level="MALICIOUS",
        )

    # Out of bounds risk_score (<0)
    with pytest.raises(ValidationError):
        URLAnalysisCreate(
            url="https://test.example.com",
            risk_score=-5.0,
            risk_level="SAFE",
        )

    # Invalid risk_level
    with pytest.raises(ValidationError):
        URLAnalysisCreate(
            url="https://test.example.com",
            risk_score=50.0,
            risk_level="UNKNOWN_LEVEL",
        )

    # Invalid URL without scheme or domain dot
    with pytest.raises(ValidationError):
        URLAnalysisCreate(
            url="invalid_domain_string",
            risk_score=50.0,
            risk_level="SAFE",
        )

    # Invalid analysis_id UUID
    with pytest.raises(ValidationError):
        URLAnalysisCreate(
            url="https://test.example.com",
            risk_score=50.0,
            risk_level="SAFE",
            analysis_id="bad-uuid",
        )

    # Valid response model
    resp = URLAnalysisResponse(
        id="12345678-1234-5678-1234-567812345678",
        url="https://secure.example.com",
        risk_score=5.0,
        risk_level="SAFE",
        created_at="2026-11-05T00:00:00Z",
    )
    assert resp.risk_score == 5.0
    listing = URLListResponse(items=[resp], total=1, limit=50, offset=0)
    assert listing.total == 1


def test_network_log_validation() -> None:
    """Verify NetworkLogCreate connection normalization and UUID checks."""
    valid_uuid = "12345678-1234-5678-1234-567812345678"
    net_log = NetworkLogCreate(
        local_address="127.0.0.1:8000",
        remote_address="192.168.1.50:54321",
        connection_status="established",
        log_id=valid_uuid,
    )
    assert net_log.connection_status == "ESTABLISHED"
    assert net_log.log_id == valid_uuid

    # Invalid log_id UUID
    with pytest.raises(ValidationError):
        NetworkLogCreate(
            local_address="127.0.0.1:8000",
            remote_address="192.168.1.50:54321",
            connection_status="ESTABLISHED",
            log_id="not-a-uuid",
        )

    # Valid response model
    resp = NetworkLogResponse(
        id="12345678-1234-5678-1234-567812345678",
        local_address="127.0.0.1:8000",
        remote_address="192.168.1.50:54321",
        connection_status="ESTABLISHED",
        created_at="2026-11-05T00:00:00Z",
    )
    assert resp.connection_status == "ESTABLISHED"
    listing = NetworkListResponse(items=[resp], total=1, limit=50, offset=0)
    assert listing.total == 1
