"""Pydantic schemas for File Integrity Baseline records."""

from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_REGEX = re.compile(r"^[0-9a-fA-F]{32,128}$")


class FileIntegrityCreate(BaseModel):
    """Request payload for registering a file integrity baseline checksum."""

    model_config = ConfigDict(extra="forbid")

    file_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Path or filename being monitored (no private file contents stored).",
        examples=["/etc/hosts"],
    )
    file_hash: str = Field(
        ...,
        min_length=32,
        max_length=128,
        description="Cryptographic checksum (e.g. SHA-256 hex string).",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )
    record_id: Optional[str] = Field(
        default=None,
        description="Optional explicit UUID v4 string.",
    )
    created_at: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Optional ISO-8601 timestamp string.",
    )

    @field_validator("record_id")
    @classmethod
    def validate_uuid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not UUID_REGEX.match(value):
            raise ValueError("record_id must be a valid UUID string")
        return value

    @field_validator("file_hash")
    @classmethod
    def validate_hash_format(cls, value: str) -> str:
        clean = value.strip()
        if not HEX_REGEX.match(clean):
            raise ValueError("file_hash must be a valid hexadecimal checksum string (32-128 hex chars)")
        return clean.lower()


class FileIntegrityResponse(BaseModel):
    """Response payload for a file integrity baseline record."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique UUID identifier.")
    file_name: str = Field(..., description="Monitored file path or name.")
    file_hash: str = Field(..., description="Cryptographic checksum.")
    created_at: str = Field(..., description="Baseline creation timestamp.")


class FileListResponse(BaseModel):
    """Paginated list response for file integrity records."""

    items: list[FileIntegrityResponse] = Field(default_factory=list, description="List of file integrity records.")
    total: int = Field(..., ge=0, description="Total number of matching records.")
    limit: int = Field(..., ge=1, description="Page limit used for query.")
    offset: int = Field(..., ge=0, description="Offset used for query.")

