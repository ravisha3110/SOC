"""Database Service Layer.

Provides unified database access and repository coordination for the FastAPI backend,
supporting both local SQLite and cloud Neon PostgreSQL with graceful degradation.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from config.settings import AppConfig, get_config
from database.exceptions import DatabaseConnectionError, DatabaseError
from database.postgres_manager import PostgresManager, sanitize_db_url
from database.repositories import (
    FileIntegrityRepository,
    NetworkLogRepository,
    ScanRepository,
    ThreatRepository,
    URLAnalysisRepository,
    UserRepository,
)
from security.auth import AuthService
from security.cloud_sync import CloudSyncEngine
from database.sqlite_manager import SQLiteManager


class DatabaseService:
    """Service providing coordinated repository access and health monitoring."""

    def __init__(
        self,
        backend_type: Optional[str] = None,
        db_path: Optional[str] = None,
        database_url: Optional[str] = None,
        config: Optional[AppConfig] = None,
        auto_init: bool = True,
    ) -> None:
        """Initialize database service with specified backend or system defaults.

        Args:
            backend_type: Explicit 'sqlite' or 'postgres' selection.
            db_path: Explicit path for SQLite database file.
            database_url: Explicit URI for PostgreSQL.
            config: Optional application configuration.
            auto_init: Whether to execute schema migrations on startup.
        """
        self.config = config or get_config()
        self.backend = (
            backend_type
            or os.getenv("DATABASE_BACKEND")
            or "sqlite"
        ).strip().lower()

        if self.backend in ("postgres", "postgresql", "neon"):
            self.backend = "postgres"
            resolved_url = database_url or self.config.neon_database_url
            self.manager = PostgresManager(database_url=resolved_url)
            if auto_init and resolved_url:
                try:
                    if self.manager.test_connection():
                        self.manager.initialize_database()
                except Exception:
                    # Cloud connection not established; gracefully deferred
                    pass
        else:
            self.backend = "sqlite"
            resolved_path = db_path or self.config.sqlite_db_path
            self.manager = SQLiteManager(db_path=resolved_path)
            if auto_init:
                try:
                    self.manager.initialize_database()
                except Exception:
                    pass

        # Instantiate repositories using the active database manager executor
        self.user_repo = UserRepository(self.manager)
        self.scan_repo = ScanRepository(self.manager)
        self.threat_repo = ThreatRepository(self.manager)
        self.file_repo = FileIntegrityRepository(self.manager)
        self.url_repo = URLAnalysisRepository(self.manager)
        self.network_repo = NetworkLogRepository(self.manager)

        # Authentication and Hybrid Cloud Sync engines
        self.auth_service = AuthService(self.user_repo)
        if isinstance(self.manager, SQLiteManager):
            pg_mgr = PostgresManager(self.config.neon_database_url)
            self.cloud_sync_engine = CloudSyncEngine(self.manager, pg_mgr)
        else:
            sq_mgr = SQLiteManager(self.config.sqlite_db_path)
            self.cloud_sync_engine = CloudSyncEngine(sq_mgr, self.manager)

    def check_database_health(self) -> dict[str, Any]:
        """Verify responsiveness of the active database backend.

        Returns:
            dict: Diagnostic status dictionary indicating health and connectivity.
        """
        if self.backend == "postgres":
            target_url = getattr(self.manager, "raw_url", getattr(self.manager, "database_url", ""))
            sanitized = getattr(self.manager, "sanitized_url", sanitize_db_url(target_url) if target_url else "Not configured")
            if not target_url:
                return {
                    "status": "unhealthy",
                    "backend": "postgres",
                    "connected": False,
                    "target": sanitized,
                    "details": "NEON_DATABASE_URL is not configured in environment.",
                }
            try:
                is_connected = self.manager.test_connection()
                if is_connected:
                    return {
                        "status": "healthy",
                        "backend": "postgres",
                        "connected": True,
                        "target": sanitized,
                        "details": "Neon PostgreSQL database is active and responsive.",
                    }
                return {
                    "status": "unhealthy",
                    "backend": "postgres",
                    "connected": False,
                    "target": sanitized,
                    "details": "PostgreSQL test query failed or connection was refused.",
                }
            except Exception as exc:
                return {
                    "status": "unhealthy",
                    "backend": "postgres",
                    "connected": False,
                    "target": sanitized,
                    "details": f"Database connection error: {str(exc)}",
                }

        # SQLite backend health check
        target_path = str(getattr(self.manager, "db_path_str", getattr(self.manager, "db_path", "database/cybershield.db")))
        try:
            row = self.manager.fetch_one("SELECT 1 AS probe;")
            if row and row.get("probe") == 1:
                return {
                    "status": "healthy",
                    "backend": "sqlite",
                    "connected": True,
                    "target": target_path,
                    "details": "Local SQLite database is active and responsive.",
                }
            return {
                "status": "unhealthy",
                "backend": "sqlite",
                "connected": False,
                "target": target_path,
                "details": "SQLite database probe query returned unexpected result.",
            }
        except Exception as exc:
            return {
                "status": "unhealthy",
                "backend": "sqlite",
                "connected": False,
                "target": target_path,
                "details": f"SQLite database unavailable: {str(exc)}",
            }

    @staticmethod
    def paginate(items: list[dict[str, Any]], limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        """Apply pagination slice to a list of records.

        Args:
            items: Full list of records.
            limit: Maximum items to return.
            offset: Zero-based item offset.

        Returns:
            tuple: (paginated_items, total_count)
        """
        total = len(items)
        sliced = items[offset : offset + limit]
        return sliced, total


# Singleton instance placeholder for dependency injection
_service_instance: Optional[DatabaseService] = None


def get_database_service() -> DatabaseService:
    """Retrieve or initialize the global DatabaseService singleton."""
    global _service_instance
    if _service_instance is None:
        _service_instance = DatabaseService()
    return _service_instance


def reset_database_service(service: Optional[DatabaseService] = None) -> None:
    """Reset or override the global DatabaseService singleton (primarily for tests)."""
    global _service_instance
    _service_instance = service
