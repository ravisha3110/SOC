"""File Integrity Baseline endpoints."""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from backend.dependencies import PaginationParams, get_file_repo, get_pagination, get_service
from backend.schemas.file import FileIntegrityCreate, FileIntegrityResponse, FileListResponse
from backend.services.database_service import DatabaseService
from database.exceptions import DatabaseConstraintError
from database.repositories import FileIntegrityRepository

router = APIRouter(prefix="/api/files", tags=["File Integrity"])


@router.post(
    "",
    response_model=FileIntegrityResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register File Integrity Baseline",
    description="Register a cryptographic checksum for a monitored file (no file content stored).",
)
def create_file_record(
    payload: FileIntegrityCreate,
    repo: Annotated[FileIntegrityRepository, Depends(get_file_repo)],
) -> FileIntegrityResponse:
    """Register a new file baseline hash."""
    try:
        record = repo.create(
            file_name=payload.file_name,
            file_hash=payload.file_hash,
            record_id=payload.record_id,
            created_at=payload.created_at,
        )
    except DatabaseConstraintError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Database constraint violation: {str(exc)}",
        ) from exc

    return FileIntegrityResponse.model_validate(record)


@router.get(
    "",
    response_model=FileListResponse,
    summary="List File Integrity Baselines",
    description="Retrieve paginated file baseline records in descending chronological order.",
)
def list_file_records(
    pagination: Annotated[PaginationParams, Depends(get_pagination)],
    repo: Annotated[FileIntegrityRepository, Depends(get_file_repo)],
    service: Annotated[DatabaseService, Depends(get_service)],
) -> FileListResponse:
    """List paginated file baseline records."""
    all_records = repo.list_all(limit=1000)
    items, total = service.paginate(all_records, limit=pagination.limit, offset=pagination.offset)
    return FileListResponse(
        items=[FileIntegrityResponse.model_validate(item) for item in items],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )
