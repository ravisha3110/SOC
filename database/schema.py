"""CyberShield Database Schema Definitions.

Defines the table specifications, column names, and initial migration DDL
for both local SQLite and cloud Neon PostgreSQL.
"""

from __future__ import annotations

# List of managed table names for reference and testing
TABLE_USERS = "users"
TABLE_SCAN_HISTORY = "scan_history"
TABLE_THREATS = "threats"
TABLE_FILE_INTEGRITY = "file_integrity"
TABLE_URL_ANALYSIS = "url_analysis"
TABLE_NETWORK_LOGS = "network_logs"
TABLE_MIGRATIONS = "schema_migrations"

ALL_APPLICATION_TABLES = [
    TABLE_USERS,
    TABLE_SCAN_HISTORY,
    TABLE_THREATS,
    TABLE_FILE_INTEGRITY,
    TABLE_URL_ANALYSIS,
    TABLE_NETWORK_LOGS,
]

# Migration 001 DDL for SQLite
SQLITE_MIGRATION_001 = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_history (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_integrity (
    id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS url_analysis (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_logs (
    id TEXT PRIMARY KEY,
    local_address TEXT NOT NULL,
    remote_address TEXT NOT NULL,
    connection_status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

# Migration 001 DDL for PostgreSQL (Neon)
POSTGRES_MIGRATION_001 = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id VARCHAR(36) PRIMARY KEY,
    scan_type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    result TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS file_integrity (
    id VARCHAR(36) PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS url_analysis (
    id VARCHAR(36) PRIMARY KEY,
    url TEXT NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS network_logs (
    id VARCHAR(36) PRIMARY KEY,
    local_address VARCHAR(100) NOT NULL,
    remote_address VARCHAR(100) NOT NULL,
    connection_status VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
"""

