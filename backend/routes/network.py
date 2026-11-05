"""Network Connection Log endpoints."""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, status

from backend.dependencies import PaginationParams, get_network_repo, get_pagination, get_service
from backend.schemas.network import NetworkListResponse, NetworkLogCreate, NetworkLogResponse
from backend.services.database_service import DatabaseService
from database.repositories import NetworkLogRepository

router = APIRouter(prefix="/api/network", tags=["Network Telemetry"])


@router.post(
    "",
    response_model=NetworkLogResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record Network Connection Event",
    description="Save a snapshot of local and remote socket connection telemetry.",
)
def create_network_log(
    payload: NetworkLogCreate,
    repo: Annotated[NetworkLogRepository, Depends(get_network_repo)],
) -> NetworkLogResponse:
    """Record a network connection log entry."""
    record = repo.create(
        local_address=payload.local_address,
        remote_address=payload.remote_address,
        connection_status=payload.connection_status,
        log_id=payload.log_id,
        created_at=payload.created_at,
    )
    return NetworkLogResponse.model_validate(record)


@router.get(
    "",
    response_model=NetworkListResponse,
    summary="List Network Connection Events",
    description="Retrieve paginated network connection logs in descending chronological order.",
)
def list_network_logs(
    pagination: Annotated[PaginationParams, Depends(get_pagination)],
    repo: Annotated[NetworkLogRepository, Depends(get_network_repo)],
    service: Annotated[DatabaseService, Depends(get_service)],
) -> NetworkListResponse:
    """List paginated network telemetry logs."""
    all_records = repo.list_all(limit=1000)
    items, total = service.paginate(all_records, limit=pagination.limit, offset=pagination.offset)
    return NetworkListResponse(
        items=[NetworkLogResponse.model_validate(item) for item in items],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )

