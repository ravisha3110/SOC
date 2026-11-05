"""CyberShield Database Exceptions.

Provides a unified hierarchy of database exceptions for both local SQLite
and cloud Neon PostgreSQL storage engines.
"""

from __future__ import annotations


class DatabaseError(Exception):
    """Base exception for all CyberShield database failures."""


class DatabaseConnectionError(DatabaseError):
    """Raised when failing to establish or maintain a database connection."""


class DatabaseMigrationError(DatabaseError):
    """Raised when applying database schema migrations fails."""


class RecordNotFoundError(DatabaseError):
    """Raised when an expected record is not found in the database."""


class DatabaseConstraintError(DatabaseError):
    """Raised when a unique or referential integrity constraint is violated."""

