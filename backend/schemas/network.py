"""Pydantic schemas for Network Connection Log records."""

from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class NetworkLogCreate(BaseModel):
    """Request payload for logging a network socket connection event."""

    model_config = ConfigDict(extra="forbid")

    local_address: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Local socket address and port (e.g. 127.0.0.1:8000).",
        examples=["127.0.0.1:54321"],
    )
    remote_address: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Remote socket destination address and port.",
        examples=["93.184.216.34:443"],
    )
    connection_status: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Connection state (e.g. ESTABLISHED, LISTEN, TIME_WAIT, BLOCKED).",
        examples=["ESTABLISHED"],
    )
    log_id: Optional[str] = Field(
        default=None,
        description="Optional explicit UUID v4 string.",
    )
    created_at: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Optional ISO-8601 timestamp string.",
    )

    @field_validator("log_id")
    @classmethod
    def validate_uuid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not UUID_REGEX.match(value):
            raise ValueError("log_id must be a valid UUID string")
        return value

    @field_validator("connection_status")
    @classmethod
    def normalize_status(cls, value: str) -> str:
        return value.strip().upper()


class NetworkLogResponse(BaseModel):
    """Response payload for a network log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique UUID identifier.")
    local_address: str = Field(..., description="Local socket address.")
    remote_address: str = Field(..., description="Remote destination address.")
    connection_status: str = Field(..., description="Socket state.")
    created_at: str = Field(..., description="Timestamp of observation.")


class NetworkListResponse(BaseModel):
    """Paginated list response for network log records."""

    items: list[NetworkLogResponse] = Field(default_factory=list, description="List of network records.")
    total: int = Field(..., ge=0, description="Total number of matching records.")
    limit: int = Field(..., ge=1, description="Page limit used for query.")
    offset: int = Field(..., ge=0, description="Offset used for query.")

