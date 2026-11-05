"""Health check and diagnostic endpoints."""

from __future__ import annotations

from typing import Annotated, Any
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from backend.dependencies import get_service
from backend.services.database_service import DatabaseService
from config.settings import get_config

router = APIRouter(prefix="/api/health", tags=["System Health"])


@router.get(
    "",
    summary="Application Health Probe",
    description="Check whether the CyberShield FastAPI service is running and responsive.",
    response_description="Service status and metadata",
)
def get_application_health() -> dict[str, str]:
    """Return runtime service health and environment metadata."""
    config = get_config()
    return {
        "status": "online",
        "app_name": config.app_name,
        "version": config.app_version,
        "environment": config.environment,
    }


@router.get(
    "/database",
    summary="Database Connectivity Probe",
    description="Inspect connectivity and responsiveness of the active database storage backend.",
    response_description="Database health details",
)
def get_database_health(
    service: Annotated[DatabaseService, Depends(get_service)],
) -> Any:
    """Return database backend responsiveness status."""
    health_data = service.check_database_health()
    if health_data.get("connected", False):
        return JSONResponse(status_code=status.HTTP_200_OK, content=health_data)
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=health_data)

