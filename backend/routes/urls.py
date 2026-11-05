"""URL Safety Analysis endpoints."""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, status

from backend.dependencies import PaginationParams, get_pagination, get_service, get_url_repo
from backend.schemas.url import URLAnalysisCreate, URLAnalysisResponse, URLListResponse
from backend.services.database_service import DatabaseService
from database.repositories import URLAnalysisRepository

router = APIRouter(prefix="/api/urls", tags=["URL Analysis"])


@router.post(
    "",
    response_model=URLAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record URL Security Analysis",
    description="Save risk assessment metrics and safety ratings for an analyzed URL.",
)
def create_url_analysis(
    payload: URLAnalysisCreate,
    repo: Annotated[URLAnalysisRepository, Depends(get_url_repo)],
) -> URLAnalysisResponse:
    """Record a URL analysis evaluation."""
    record = repo.create(
        url=payload.url,
        risk_score=payload.risk_score,
        risk_level=payload.risk_level,
        analysis_id=payload.analysis_id,
        created_at=payload.created_at,
    )
    return URLAnalysisResponse.model_validate(record)


@router.get(
    "",
    response_model=URLListResponse,
    summary="List URL Security Analyses",
    description="Retrieve paginated URL inspection records in descending chronological order.",
)
def list_url_analyses(
    pagination: Annotated[PaginationParams, Depends(get_pagination)],
    repo: Annotated[URLAnalysisRepository, Depends(get_url_repo)],
    service: Annotated[DatabaseService, Depends(get_service)],
) -> URLListResponse:
    """List paginated URL analysis evaluations."""
    all_records = repo.list_all(limit=1000)
    items, total = service.paginate(all_records, limit=pagination.limit, offset=pagination.offset)
    return URLListResponse(
        items=[URLAnalysisResponse.model_validate(item) for item in items],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )

