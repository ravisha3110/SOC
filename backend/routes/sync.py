"""Hybrid Cloud Synchronization API Endpoints."""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from backend.dependencies import (
    get_cloud_sync_engine,
    get_current_session,
    require_role,
)
from backend.schemas.sync import (
    SyncConflictResponse,
    SyncReportResponse,
    SyncStatusResponse,
    SyncTriggerRequest,
)
from security.auth import Role, Session
from security.cloud_sync import CloudSyncEngine, SyncDirection

router = APIRouter(prefix="/api/sync", tags=["Hybrid Cloud Synchronization"])


@router.get(
    "/status",
    response_model=SyncStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current cloud connection status and sync stats",
)
def get_sync_status(
    session: Annotated[Session, Depends(require_role([Role.ADMINISTRATOR, Role.ANALYST]))],
    sync_engine: Annotated[CloudSyncEngine, Depends(get_cloud_sync_engine)],
) -> SyncStatusResponse:
    """Retrieve cloud Neon PostgreSQL connectivity telemetry and pending record metrics."""
    overview = sync_engine.get_status_overview()
    return SyncStatusResponse(**overview)


@router.post(
    "/trigger",
    response_model=SyncReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger manual SQLite-to-Neon cloud synchronization",
)
def trigger_synchronization(
    payload: SyncTriggerRequest,
    session: Annotated[Session, Depends(require_role([Role.ADMINISTRATOR, Role.ANALYST]))],
    sync_engine: Annotated[CloudSyncEngine, Depends(get_cloud_sync_engine)],
) -> SyncReportResponse:
    """Execute on-demand cloud synchronization with automatic conflict detection and retry logic."""
    direction = SyncDirection(payload.direction)
    summary = sync_engine.synchronize(
        direction=direction,
        max_retries=payload.max_retries,
    )
    conflicts = [
        SyncConflictResponse(
            table_name=c.table_name,
            record_id=c.record_id,
            conflict_reason=c.conflict_reason,
            detected_at=c.detected_at,
            local_data=c.local_data,
            cloud_data=c.cloud_data,
        )
        for c in summary.conflicts
    ]
    return SyncReportResponse(
        status=summary.status,
        cloud_status=summary.cloud_status.value,
        direction=summary.direction.value,
        started_at=summary.started_at,
        completed_at=summary.completed_at,
        records_uploaded=summary.records_uploaded,
        records_downloaded=summary.records_downloaded,
        conflicts_detected=summary.conflicts_detected,
        conflicts=conflicts,
        errors=summary.errors,
        table_stats=summary.table_stats,
    )

