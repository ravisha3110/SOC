"""Pydantic schemas for Threat Findings."""

from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class ThreatCreate(BaseModel):
    """Request payload for logging a security threat finding."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(
        ...,
        description="UUID of the parent scan_history entry.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    threat_type: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Threat category (e.g. BRUTE_FORCE, WEAK_CIPHER, HASH_MISMATCH).",
        examples=["BRUTE_FORCE"],
    )
    severity: str = Field(
        ...,
        description="Severity classification: CRITICAL, HIGH, MEDIUM, or LOW.",
        examples=["HIGH"],
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Detailed technical finding and remediation guidance.",
        examples=["Multiple failed authentication attempts detected from unauthorized IP."],
    )
    threat_id: Optional[str] = Field(
        default=None,
        description="Optional explicit UUID v4 string.",
    )
    created_at: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Optional ISO-8601 timestamp string.",
    )

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id_uuid(cls, value: str) -> str:
        if not UUID_REGEX.match(value):
            raise ValueError("scan_id must be a valid UUID string (e.g. 12345678-1234-5678-1234-567812345678)")
        return value

    @field_validator("threat_id")
    @classmethod
    def validate_threat_id_uuid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not UUID_REGEX.match(value):
            raise ValueError("threat_id must be a valid UUID string")
        return value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}")
        return normalized


class ThreatResponse(BaseModel):
    """Response payload for a security threat finding."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique UUID identifier.")
    scan_id: str = Field(..., description="UUID of the parent scan_history entry.")
    threat_type: str = Field(..., description="Threat category.")
    severity: str = Field(..., description="Severity classification.")
    description: str = Field(..., description="Technical description.")
    created_at: str = Field(..., description="Detection timestamp.")


class ThreatListResponse(BaseModel):
    """Paginated list response for threats."""

    items: list[ThreatResponse] = Field(default_factory=list, description="List of threat records.")
    total: int = Field(..., ge=0, description="Total number of matching threat records.")
    limit: int = Field(..., ge=1, description="Page limit used for query.")
    offset: int = Field(..., ge=0, description="Offset used for query.")

