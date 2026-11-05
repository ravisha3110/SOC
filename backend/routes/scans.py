"""Security Scan endpoints."""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from backend.dependencies import PaginationParams, get_pagination, get_scan_repo, get_service
from backend.schemas.scan import ScanCreate, ScanListResponse, ScanResponse
from backend.services.database_service import DatabaseService
from database.repositories import ScanRepository

router = APIRouter(prefix="/api/scans", tags=["Security Scans"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Security Scan Record",
    description="Record a new historical security scan entry across any security module.",
)
def create_scan(
    payload: ScanCreate,
    repo: Annotated[ScanRepository, Depends(get_scan_repo)],
) -> ScanResponse:
    """Create a new security scan entry."""
    record = repo.create(
        scan_type=payload.scan_type,
        target=payload.target,
        result=payload.result,
        scan_id=payload.scan_id,
        created_at=payload.created_at,
    )
    return ScanResponse.model_validate(record)


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List Security Scans",
    description="Retrieve paginated security scan entries in descending chronological order.",
)
def list_scans(
    pagination: Annotated[PaginationParams, Depends(get_pagination)],
    repo: Annotated[ScanRepository, Depends(get_scan_repo)],
    service: Annotated[DatabaseService, Depends(get_service)],
) -> ScanListResponse:
    """List paginated security scan entries."""
    all_records = repo.list_all(limit=1000)
    items, total = service.paginate(all_records, limit=pagination.limit, offset=pagination.offset)
    return ScanListResponse(
        items=[ScanResponse.model_validate(item) for item in items],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get Security Scan by ID",
    description="Retrieve full technical details of a specific security scan entry.",
)
def get_scan(
    scan_id: str,
    repo: Annotated[ScanRepository, Depends(get_scan_repo)],
) -> ScanResponse:
    """Fetch single security scan by UUID."""
    record = repo.get_by_id(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )
    return ScanResponse.model_validate(record)

