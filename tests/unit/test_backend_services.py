"""Unit tests for backend DatabaseService and dependency providers."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import pytest

from backend.dependencies import (
    PaginationParams,
    get_file_repo,
    get_network_repo,
    get_pagination,
    get_scan_repo,
    get_service,
    get_threat_repo,
    get_url_repo,
)
from backend.services.database_service import (
    DatabaseService,
    get_database_service,
    reset_database_service,
)
from config.settings import AppConfig


@pytest.fixture
def in_memory_service() -> DatabaseService:
    """Fixture providing an in-memory SQLite database service."""
    service = DatabaseService(backend_type="sqlite", db_path=":memory:", auto_init=True)
    return service


def test_sqlite_service_initialization_and_health(in_memory_service: DatabaseService) -> None:
    """Verify SQLite database service initializes repositories and reports healthy."""
    assert in_memory_service.backend == "sqlite"
    assert in_memory_service.scan_repo is not None
    assert in_memory_service.threat_repo is not None
    assert in_memory_service.file_repo is not None
    assert in_memory_service.url_repo is not None
    assert in_memory_service.network_repo is not None

    health = in_memory_service.check_database_health()
    assert health["status"] == "healthy"
    assert health["connected"] is True
    assert health["backend"] == "sqlite"


def test_sqlite_service_health_unhealthy_on_query_failure(in_memory_service: DatabaseService) -> None:
    """Verify SQLite health returns unhealthy when query fails."""
    with patch.object(in_memory_service.manager, "fetch_one", side_effect=Exception("Disk I/O error")):
        health = in_memory_service.check_database_health()
        assert health["status"] == "unhealthy"
        assert health["connected"] is False
        assert "Disk I/O error" in health["details"]


def test_sqlite_service_health_unexpected_probe_result(in_memory_service: DatabaseService) -> None:
    """Verify SQLite health returns unhealthy when probe row is missing or malformed."""
    with patch.object(in_memory_service.manager, "fetch_one", return_value={"probe": 0}):
        health = in_memory_service.check_database_health()
        assert health["status"] == "unhealthy"
        assert health["connected"] is False


def test_postgres_service_health_not_configured() -> None:
    """Verify Postgres health returns unhealthy when database URL is not configured."""
    with patch.dict(os.environ, {"NEON_DATABASE_URL": "", "DATABASE_URL": ""}):
        from config.settings import AppConfig
        cfg = AppConfig(
            app_name="CyberShield",
            app_version="0.1.0",
            environment="test",
            debug=True,
            theme="dark",
            sqlite_db_path=":memory:",
            neon_database_url="",
            api_host="127.0.0.1",
            api_port=8000,
        )
        service = DatabaseService(backend_type="postgres", database_url="", config=cfg, auto_init=False)
        assert service.backend == "postgres"

        health = service.check_database_health()
        assert health["status"] == "unhealthy"
        assert health["connected"] is False
        assert "not configured" in health["details"].lower()


def test_postgres_service_health_mocked_connected() -> None:
    """Verify Postgres health returns healthy when connection test succeeds."""
    service = DatabaseService(
        backend_type="postgres",
        database_url="postgresql://usr:sec@ep.neon.tech/db?sslmode=require",
        auto_init=False,
    )
    with patch.object(service.manager, "test_connection", return_value=True):
        health = service.check_database_health()
        assert health["status"] == "healthy"
        assert health["connected"] is True
        assert "usr:***@" in health["target"]


def test_postgres_service_health_mocked_connection_failure() -> None:
    """Verify Postgres health returns unhealthy when connection test returns False."""
    service = DatabaseService(
        backend_type="postgres",
        database_url="postgresql://usr:sec@ep.neon.tech/db?sslmode=require",
        auto_init=False,
    )
    with patch.object(service.manager, "test_connection", return_value=False):
        health = service.check_database_health()
        assert health["status"] == "unhealthy"
        assert health["connected"] is False


def test_postgres_service_health_mocked_exception() -> None:
    """Verify Postgres health returns unhealthy when connection test raises exception."""
    service = DatabaseService(
        backend_type="postgres",
        database_url="postgresql://usr:sec@ep.neon.tech/db?sslmode=require",
        auto_init=False,
    )
    with patch.object(service.manager, "test_connection", side_effect=Exception("Network unreachable")):
        health = service.check_database_health()
        assert health["status"] == "unhealthy"
        assert health["connected"] is False
        assert "Network unreachable" in health["details"]


def test_database_service_paginate_helper() -> None:
    """Verify paginate static method computes totals and slices lists accurately."""
    sample_items = [{"id": i} for i in range(10)]
    sliced, total = DatabaseService.paginate(sample_items, limit=3, offset=2)
    assert total == 10
    assert len(sliced) == 3
    assert sliced[0]["id"] == 2
    assert sliced[-1]["id"] == 4


def test_database_service_singleton_and_reset(in_memory_service: DatabaseService) -> None:
    """Verify get_database_service singleton lifecycle and reset behavior."""
    reset_database_service(None)
    first_inst = get_database_service()
    assert first_inst is not None

    reset_database_service(in_memory_service)
    assert get_database_service() is in_memory_service
    reset_database_service(None)


def test_dependency_providers(in_memory_service: DatabaseService) -> None:
    """Verify that dependency injection providers extract expected objects."""
    reset_database_service(in_memory_service)
    try:
        service = get_service()
        assert service is in_memory_service
        assert get_scan_repo(service) is in_memory_service.scan_repo
        assert get_threat_repo(service) is in_memory_service.threat_repo
        assert get_file_repo(service) is in_memory_service.file_repo
        assert get_url_repo(service) is in_memory_service.url_repo
        assert get_network_repo(service) is in_memory_service.network_repo

        pagination = get_pagination(limit=25, offset=10)
        assert isinstance(pagination, PaginationParams)
        assert pagination.limit == 25
        assert pagination.offset == 10
    finally:
        reset_database_service(None)


def test_postgres_auto_init_success_and_failure() -> None:
    """Verify Postgres auto-init executes migrations on success and handles failures gracefully."""
    db_url = "postgresql://user:pass@ep.neon.tech/db?sslmode=require"
    with patch("database.postgres_manager.PostgresManager.test_connection", return_value=True), \
         patch("database.postgres_manager.PostgresManager.initialize_database") as mock_init:
        svc = DatabaseService(backend_type="postgres", database_url=db_url, auto_init=True)
        assert svc.backend == "postgres"
        mock_init.assert_called_once()

    with patch("database.postgres_manager.PostgresManager.test_connection", side_effect=Exception("Timeout")), \
         patch("database.postgres_manager.PostgresManager.initialize_database") as mock_init_fail:
        svc_fail = DatabaseService(backend_type="postgres", database_url=db_url, auto_init=True)
        assert svc_fail.backend == "postgres"
        mock_init_fail.assert_not_called()


def test_sqlite_auto_init_failure_handled_gracefully() -> None:
    """Verify SQLite auto-init handles initialization exceptions without crashing."""
    with patch("database.sqlite_manager.SQLiteManager.initialize_database", side_effect=Exception("Read-only filesystem")):
        svc = DatabaseService(backend_type="sqlite", db_path=":memory:", auto_init=True)
        assert svc.backend == "sqlite"
