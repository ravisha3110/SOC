"""Pydantic schemas for URL Analysis records."""

from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
VALID_RISK_LEVELS = {"SAFE", "SUSPICIOUS", "MALICIOUS"}


class URLAnalysisCreate(BaseModel):
    """Request payload for logging a URL safety analysis."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="Target URL analyzed.",
        examples=["https://example.com/login"],
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Numerical risk assessment score from 0.0 (safe) to 100.0 (maximum danger).",
        examples=[15.5],
    )
    risk_level: str = Field(
        ...,
        description="Classification: SAFE, SUSPICIOUS, or MALICIOUS.",
        examples=["SAFE"],
    )
    analysis_id: Optional[str] = Field(
        default=None,
        description="Optional explicit UUID v4 string.",
    )
    created_at: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Optional ISO-8601 timestamp string.",
    )

    @field_validator("analysis_id")
    @classmethod
    def validate_uuid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not UUID_REGEX.match(value):
            raise ValueError("analysis_id must be a valid UUID string")
        return value

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in VALID_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of: {', '.join(sorted(VALID_RISK_LEVELS))}")
        return normalized

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, value: str) -> str:
        clean = value.strip()
        if not (clean.startswith("http://") or clean.startswith("https://") or "://" in clean or "." in clean):
            raise ValueError("url must be a valid web address or domain")
        return clean


class URLAnalysisResponse(BaseModel):
    """Response payload for a URL analysis record."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique UUID identifier.")
    url: str = Field(..., description="Target URL analyzed.")
    risk_score: float = Field(..., description="Risk score (0.0 - 100.0).")
    risk_level: str = Field(..., description="Risk classification.")
    created_at: str = Field(..., description="Analysis timestamp.")


class URLListResponse(BaseModel):
    """Paginated list response for URL analysis records."""

    items: list[URLAnalysisResponse] = Field(default_factory=list, description="List of URL records.")
    total: int = Field(..., ge=0, description="Total number of matching records.")
    limit: int = Field(..., ge=1, description="Page limit used for query.")
    offset: int = Field(..., ge=0, description="Offset used for query.")

