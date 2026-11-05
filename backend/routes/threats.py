"""Threat Findings endpoints."""

from __future__ import annotations

from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.dependencies import (
    PaginationParams,
    get_pagination,
    get_scan_repo,
    get_service,
    get_threat_repo,
)
from backend.schemas.threat import ThreatCreate, ThreatListResponse, ThreatResponse
from backend.services.database_service import DatabaseService
from database.exceptions import DatabaseConstraintError
from database.repositories import ScanRepository, ThreatRepository

router = APIRouter(prefix="/api/threats", tags=["Threat Findings"])


@router.post(
    "",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Log Threat Finding",
    description="Record a specific vulnerability or security threat detected during a scan.",
)
def create_threat(
    payload: ThreatCreate,
    threat_repo: Annotated[ThreatRepository, Depends(get_threat_repo)],
    scan_repo: Annotated[ScanRepository, Depends(get_scan_repo)],
) -> ThreatResponse:
    """Create a new threat finding linked to a scan history record."""
    parent_scan = scan_repo.get_by_id(payload.scan_id)
    if not parent_scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Parent scan with ID '{payload.scan_id}' does not exist.",
        )

    try:
        record = threat_repo.create(
            scan_id=payload.scan_id,
            threat_type=payload.threat_type,
            severity=payload.severity,
            description=payload.description,
            threat_id=payload.threat_id,
            created_at=payload.created_at,
        )
    except DatabaseConstraintError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return ThreatResponse.model_validate(record)


@router.get(
    "",
    response_model=ThreatListResponse,
    summary="List Threat Findings",
    description="Retrieve paginated threat findings, optionally filtered by parent scan ID.",
)
def list_threats(
    pagination: Annotated[PaginationParams, Depends(get_pagination)],
    threat_repo: Annotated[ThreatRepository, Depends(get_threat_repo)],
    service: Annotated[DatabaseService, Depends(get_service)],
    scan_id: Annotated[Optional[str], Query(description="Filter threats by parent scan ID")] = None,
) -> ThreatListResponse:
    """List paginated threat findings."""
    if scan_id:
        all_records = threat_repo.list_by_scan(scan_id)
    else:
        all_records = threat_repo.list_all(limit=1000)

    items, total = service.paginate(all_records, limit=pagination.limit, offset=pagination.offset)
    return ThreatListResponse(
        items=[ThreatResponse.model_validate(item) for item in items],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get(
    "/{threat_id}",
    response_model=ThreatResponse,
    summary="Get Threat Finding by ID",
    description="Retrieve full details of a specific threat finding.",
)
def get_threat(
    threat_id: str,
    threat_repo: Annotated[ThreatRepository, Depends(get_threat_repo)],
) -> ThreatResponse:
    """Fetch single threat finding by UUID."""
    record = threat_repo.get_by_id(threat_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat finding with ID '{threat_id}' not found.",
        )
    return ThreatResponse.model_validate(record)

