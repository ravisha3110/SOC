"""CyberShield Hybrid Cloud Synchronization Schemas."""

from __future__ import annotations

from typing import Annotated, Any
from pydantic import BaseModel, ConfigDict, Field


class SyncTriggerRequest(BaseModel):
    """Payload to trigger manual cloud synchronization."""

    direction: Annotated[str, Field(default="BIDIRECTIONAL", pattern=r"^(BIDIRECTIONAL|UPLOAD_ONLY|DOWNLOAD_ONLY)$")]
    max_retries: Annotated[int, Field(default=3, ge=1, le=5)]


class SyncStatusResponse(BaseModel):
    """Telemetry report of current cloud connection and pending items."""

    cloud_status: str
    is_connected: bool
    masked_target_url: str
    last_synced_at: str | None
    total_local_records: int


class SyncConflictResponse(BaseModel):
    """Representation of an attribute conflict detected during sync."""

    table_name: str
    record_id: str
    conflict_reason: str
    detected_at: str
    local_data: dict[str, Any]
    cloud_data: dict[str, Any]


class SyncReportResponse(BaseModel):
    """Comprehensive post-synchronization audit report."""

    status: str
    cloud_status: str
    direction: str
    started_at: str
    completed_at: str
    records_uploaded: int
    records_downloaded: int
    conflicts_detected: int
    conflicts: list[SyncConflictResponse]
    errors: list[str]
    table_stats: dict[str, dict[str, int]]

