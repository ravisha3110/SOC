"""Pydantic schemas for Security Scans."""

from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class ScanCreate(BaseModel):
    """Request payload for creating a security scan record."""

    model_config = ConfigDict(extra="forbid")

    scan_type: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Category of the scan (e.g. PORT_SCAN, FILE_INTEGRITY, URL_SCAN).",
        examples=["PORT_SCAN"],
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Inspection target (IP, port, file path, URL, host).",
        examples=["192.168.1.1"],
    )
    result: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Detailed findings text or serialized JSON summary.",
        examples=['{"open_ports": [80, 443]}'],
    )
    scan_id: Optional[str] = Field(
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
    def validate_uuid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not UUID_REGEX.match(value):
            raise ValueError("scan_id must be a valid UUID string (e.g. 12345678-1234-5678-1234-567812345678)")
        return value


class ScanResponse(BaseModel):
    """Response payload for a security scan record."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique UUID identifier.")
    scan_type: str = Field(..., description="Category of the scan.")
    target: str = Field(..., description="Inspection target.")
    result: str = Field(..., description="Technical findings summary.")
    created_at: str = Field(..., description="Timestamp of scan execution.")


class ScanListResponse(BaseModel):
    """Paginated list response for security scans."""

    items: list[ScanResponse] = Field(default_factory=list, description="List of scan records.")
    total: int = Field(..., ge=0, description="Total number of matching scan records.")
    limit: int = Field(..., ge=1, description="Page limit used for query.")
    offset: int = Field(..., ge=0, description="Offset used for query.")

