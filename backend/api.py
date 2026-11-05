"""CyberShield FastAPI Application.

Provides a modular REST API interface for CyberShield threat intelligence,
connecting the desktop client and external services to local SQLite and cloud Neon PostgreSQL.
"""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.routes import (
    auth_router,
    files_router,
    health_router,
    network_router,
    scans_router,
    sync_router,
    threats_router,
    urls_router,
)
from config.settings import AppConfig, get_config
from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
    RecordNotFoundError,
)

logger = logging.getLogger("cybershield.api")


def create_app(config: Optional[AppConfig] = None) -> FastAPI:
    """Application factory for CyberShield FastAPI backend.

    Args:
        config: Optional application configuration container.

    Returns:
        FastAPI: Configured FastAPI application instance.
    """
    app_config = config or get_config()

    application = FastAPI(
        title="CyberShield Threat Analytics API",
        version=app_config.app_version,
        description=(
            "REST API interface for the CyberShield SOC Cybersecurity Platform. "
            "Exposes structured endpoints for security scans, vulnerability findings, "
            "file integrity checksums, URL safety ratings, and network telemetry."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Restrict CORS to local development machine only (never allow wildcard origin in security apps)
    allowed_origins = [
        "http://127.0.0.1",
        "http://localhost",
        f"http://127.0.0.1:{app_config.api_port}",
        f"http://localhost:{app_config.api_port}",
    ]
    application.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Global Exception Handlers (Ensure sensitive database credentials/traces are NEVER exposed)
    @application.exception_handler(DatabaseConnectionError)
    async def db_connection_exception_handler(_: Request, exc: DatabaseConnectionError) -> JSONResponse:
        logger.error("Database connection failure: %s", str(exc))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database connection unavailable. Please check storage backend."},
        )

    @application.exception_handler(DatabaseConstraintError)
    async def db_constraint_exception_handler(_: Request, exc: DatabaseConstraintError) -> JSONResponse:
        logger.warning("Database constraint violation: %s", str(exc))
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": f"Database constraint violation: {str(exc)}"},
        )

    @application.exception_handler(RecordNotFoundError)
    async def not_found_exception_handler(_: Request, exc: RecordNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": str(exc)},
        )

    @application.exception_handler(DatabaseError)
    async def general_db_exception_handler(_: Request, exc: DatabaseError) -> JSONResponse:
        logger.error("Internal database error: %s", str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal database error occurred while processing the request."},
        )

    # Include modular sub-routers
    application.include_router(auth_router)
    application.include_router(health_router)
    application.include_router(scans_router)
    application.include_router(threats_router)
    application.include_router(files_router)
    application.include_router(urls_router)
    application.include_router(network_router)
    application.include_router(sync_router)

    return application


# Top-level ASGI application instance for Uvicorn
app = create_app()

