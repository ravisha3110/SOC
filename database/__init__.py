"""CyberShield Database Package.

Provides hybrid persistence with local offline SQLite and cloud Neon PostgreSQL (Psycopg 3),
including versioned schema migrations, repositories, and exception handling.
"""

from database.exceptions import (
    DatabaseConnectionError,
    DatabaseConstraintError,
    DatabaseError,
    DatabaseMigrationError,
    RecordNotFoundError,
)
from database.postgres_manager import PostgresManager, sanitize_db_url
from database.repositories import (
    FileIntegrityRepository,
    NetworkLogRepository,
    ScanRepository,
    ThreatRepository,
    URLAnalysisRepository,
    UserRepository,
)
from database.schema import (
    ALL_APPLICATION_TABLES,
    TABLE_FILE_INTEGRITY,
    TABLE_MIGRATIONS,
    TABLE_NETWORK_LOGS,
    TABLE_SCAN_HISTORY,
    TABLE_THREATS,
    TABLE_URL_ANALYSIS,
    TABLE_USERS,
)
from database.sqlite_manager import SQLiteManager

__all__ = [
    # Managers
    "SQLiteManager",
    "PostgresManager",
    "sanitize_db_url",
    # Repositories
    "UserRepository",
    "ScanRepository",
    "ThreatRepository",
    "FileIntegrityRepository",
    "URLAnalysisRepository",
    "NetworkLogRepository",
    # Exceptions
    "DatabaseError",
    "DatabaseConnectionError",
    "DatabaseMigrationError",
    "RecordNotFoundError",
    "DatabaseConstraintError",
    # Table names
    "ALL_APPLICATION_TABLES",
    "TABLE_USERS",
    "TABLE_SCAN_HISTORY",
    "TABLE_THREATS",
    "TABLE_FILE_INTEGRITY",
    "TABLE_URL_ANALYSIS",
    "TABLE_NETWORK_LOGS",
    "TABLE_MIGRATIONS",
]
