"""FastAPI Dependency Injection Providers."""

from __future__ import annotations

from typing import Annotated, Callable
from fastapi import Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from backend.services.database_service import DatabaseService, get_database_service
from database.repositories import (
    FileIntegrityRepository,
    NetworkLogRepository,
    ScanRepository,
    ThreatRepository,
    URLAnalysisRepository,
    UserRepository,
)
from security.auth import AuthService, Permission, Role, Session
from security.cloud_sync import CloudSyncEngine


class PaginationParams(BaseModel):
    """Common pagination parameters for listing endpoints."""

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=50, ge=1, le=100, description="Maximum number of records to return.")
    offset: int = Field(default=0, ge=0, description="Number of records to skip.")


def get_pagination(
    limit: Annotated[int, Query(ge=1, le=100, description="Maximum number of records to return")] = 50,
    offset: Annotated[int, Query(ge=0, description="Number of records to skip")] = 0,
) -> PaginationParams:
    """Dependency provider for sanitized pagination parameters."""
    return PaginationParams(limit=limit, offset=offset)


def get_service() -> DatabaseService:
    """Dependency provider for the application DatabaseService."""
    return get_database_service()


def get_scan_repo(service: Annotated[DatabaseService, Depends(get_service)]) -> ScanRepository:
    """Dependency provider for ScanRepository."""
    return service.scan_repo


def get_threat_repo(service: Annotated[DatabaseService, Depends(get_service)]) -> ThreatRepository:
    """Dependency provider for ThreatRepository."""
    return service.threat_repo


def get_file_repo(service: Annotated[DatabaseService, Depends(get_service)]) -> FileIntegrityRepository:
    """Dependency provider for FileIntegrityRepository."""
    return service.file_repo


def get_url_repo(service: Annotated[DatabaseService, Depends(get_service)]) -> URLAnalysisRepository:
    """Dependency provider for URLAnalysisRepository."""
    return service.url_repo


def get_network_repo(service: Annotated[DatabaseService, Depends(get_service)]) -> NetworkLogRepository:
    """Dependency provider for NetworkLogRepository."""
    return service.network_repo


def get_user_repo(service: Annotated[DatabaseService, Depends(get_service)]) -> UserRepository:
    """Dependency provider for UserRepository."""
    return service.user_repo


def get_auth_service(service: Annotated[DatabaseService, Depends(get_service)]) -> AuthService:
    """Dependency provider for AuthService."""
    return service.auth_service


def get_cloud_sync_engine(service: Annotated[DatabaseService, Depends(get_service)]) -> CloudSyncEngine:
    """Dependency provider for CloudSyncEngine."""
    return service.cloud_sync_engine


def get_current_session(
    x_session_token: Annotated[str | None, Header(alias="X-Session-Token")] = None,
    auth_service: Annotated[AuthService, Depends(get_auth_service)] = None,
) -> Session:
    """Validate incoming session token from X-Session-Token header."""
    if not x_session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: missing X-Session-Token header.",
        )
    session = auth_service.validate_session(x_session_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired. Please re-authenticate.",
        )
    return session


def require_role(allowed_roles: list[Role]) -> Callable[[Session], Session]:
    """Factory creating an RBAC role-enforcement dependency."""
    def _role_checker(session: Annotated[Session, Depends(get_current_session)]) -> Session:
        if session.role not in allowed_roles:
            role_names = ", ".join([r.value for r in allowed_roles])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Requires one of [{role_names}] roles.",
            )
        return session
    return _role_checker

