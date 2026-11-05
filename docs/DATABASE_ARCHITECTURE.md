# CyberShield: Hybrid Database Architecture (SQLite + Neon PostgreSQL)

This document provides a comprehensive architectural guide to CyberShield's hybrid data storage layer, written in clear, academic, and beginner-friendly language suitable for project defense and viva voce evaluation.

---

## 1. Executive Summary & Architecture Overview

CyberShield implements a **Hybrid Database Architecture** combining:
1. **Local Embedded Database (SQLite):** Guarantees full offline functionality, zero-latency local operations, and zero-configuration installation.
2. **Cloud Serverless Database (Neon PostgreSQL):** Provides centralized, scalable relational storage for shared intelligence and enterprise audit logs.

```
+-----------------------------------------------------------------------------------+
|                           CyberShield Application Layer                           |
+-----------------------------------------------------------------------------------+
                                         |
               +-------------------------+-------------------------+
               |                                                   |
               v                                                   v
+-------------------------------+               +-----------------------------------+
|      SQLiteManager (Local)    |               |    PostgresManager (Cloud Neon)   |
|  - Standard library sqlite3   |               |  - Psycopg 3 binary driver        |
|  - Offline persistence        |               |  - Remote serverless PostgreSQL   |
|  - database/cybershield.db    |               |  - NEON_DATABASE_URL / sslmode    |
+-------------------------------+               +-----------------------------------+
               |                                                   |
               v                                                   v
+-----------------------------------------------------------------------------------+
|                       Unified Repositories (Data Access)                          |
|   - UserRepository         - ScanRepository         - ThreatRepository            |
|   - FileIntegrityRepo      - URLAnalysisRepo        - NetworkLogRepo              |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Technologies Explained (Viva Focus)

### What is SQLite?
**SQLite** is a lightweight, embedded SQL database engine. Unlike traditional database servers (like MySQL or Oracle), SQLite does not run as a separate background process. Instead, the database engine is compiled directly into the application, storing the entire database—tables, indexes, and records—inside a single cross-platform disk file (`database/cybershield.db`).
- **Why we use it:** Guarantees that CyberShield works 100% offline without needing internet connectivity, third-party database servers, or complex client installations.

### What is PostgreSQL?
**PostgreSQL** is an advanced, enterprise-grade open-source object-relational database management system known for its strong reliability, feature robustness, and ACID compliance. It supports advanced indexing, complex queries, and enterprise-scale data storage.

### What is Neon?
**Neon** is a modern, serverless cloud hosting platform for PostgreSQL. It decouples compute and storage, allowing the database to automatically scale compute resources up or down, manage cloud backups, and provide secure SSL-encrypted cloud connections over standard PostgreSQL protocol.

### Why Use a Hybrid Storage Model?
In real-world cybersecurity workstations and SOC environments, a security tool cannot afford to fail simply because network connectivity is lost. If an analyst is investigating a compromised network or disconnected host:
1. **Immediate Local Access:** Scans, alerts, and system integrity logs must continue to be recorded locally in SQLite.
2. **Centralized Cloud Intelligence:** When cloud credentials and network access are available, records can be stored and analyzed centrally in Neon PostgreSQL.
3. **Decoupled Architecture:** Using common repository classes ensures our application logic doesn't care whether data resides locally or in the cloud.

---

## 3. Database Schema Specifications

The schema is normalized, beginner-friendly, and utilizes UUID-compatible string keys for cross-database interoperability.

### 1. `users` Table
Stores analyst profiles and credentials.
- **`id`** (`TEXT` / `VARCHAR(36)`): Primary Key (UUID v4 string).
- **`username`** (`TEXT` / `VARCHAR(100)`): Unique analyst identifier.
- **`password_hash`** (`TEXT` / `VARCHAR(255)`): Secure cryptographic hash string (e.g. bcrypt/argon2). *Plaintext passwords are strictly prohibited.*
- **`created_at`** (`TEXT` / `TIMESTAMPTZ`): ISO-8601 UTC creation timestamp.

### 2. `scan_history` Table
Stores high-level records of security inspection events.
- **`id`** (`TEXT` / `VARCHAR(36)`): Primary Key (UUID v4 string).
- **`scan_type`** (`TEXT` / `VARCHAR(50)`): Scan category (`PORT_SCAN`, `FIM`, `URL_CHECK`, `AUTH_LOG`).
- **`target`** (`TEXT` / `VARCHAR(255)`): Target host, IP address, file path, or URL.
- **`result`** (`TEXT`): Serialized JSON summary or technical findings text.
- **`created_at`** (`TEXT` / `TIMESTAMPTZ`): Timestamp of scan execution.

### 3. `threats` Table
Stores specific security vulnerabilities or anomalies discovered during a scan.
- **`id`** (`TEXT` / `VARCHAR(36)`): Primary Key (UUID v4 string).
- **`scan_id`** (`TEXT` / `VARCHAR(36)`): Foreign Key references `scan_history(id)` with `ON DELETE CASCADE`.
- **`threat_type`** (`TEXT` / `VARCHAR(50)`): Threat classifier (e.g., `BRUTE_FORCE`, `WEAK_CIPHER`, `HASH_MISMATCH`).
- **`severity`** (`TEXT` / `VARCHAR(20)`): Severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **`description`** (`TEXT`): Human-readable vulnerability description and mitigation guidance.
- **`created_at`** (`TEXT` / `TIMESTAMPTZ`): Timestamp when threat was detected.

### 4. `file_integrity` Table
Stores baseline cryptographic checksums for File Integrity Monitoring (FIM).
- **`id`** (`TEXT` / `VARCHAR(36)`): Primary Key (UUID v4 string).
- **`file_name`** (`TEXT` / `VARCHAR(255)`): Monitored file path or filename.
- **`file_hash`** (`TEXT` / `VARCHAR(64)`): SHA-256 baseline checksum.
- **`created_at`** (`TEXT` / `TIMESTAMPTZ`): Baseline registration timestamp.

### 5. `url_analysis` Table
Stores domain and URL risk assessments.
- **`id`** (`TEXT` / `VARCHAR(36)`): Primary Key (UUID v4 string).
- **`url`** (`TEXT`): Target analyzed URL.
- **`risk_score`** (`REAL` / `NUMERIC(5,2)`): Numeric risk score from `0.0` (safe) to `100.0` (critical danger).
- **`risk_level`** (`TEXT` / `VARCHAR(20)`): Classification (`SAFE`, `SUSPICIOUS`, `MALICIOUS`).
- **`created_at`** (`TEXT` / `TIMESTAMPTZ`): Timestamp of inspection.

### 6. `network_logs` Table
Stores local network connection snapshots and port telemetry.
- **`id`** (`TEXT` / `VARCHAR(36)`): Primary Key (UUID v4 string).
- **`local_address`** (`TEXT` / `VARCHAR(100)`): Local IP and port (e.g., `127.0.0.1:49152`).
- **`remote_address`** (`TEXT` / `VARCHAR(100)`): Remote destination address.
- **`connection_status`** (`TEXT` / `VARCHAR(50)`): Socket status (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `BLOCKED`).
- **`created_at`** (`TEXT` / `TIMESTAMPTZ`): Observation timestamp.

### 7. `schema_migrations` Table
Tracks applied migration versions to ensure repeatable, safe initialization.
- **`version`** (`INTEGER PRIMARY KEY`): Sequential migration number (e.g. `1`).
- **`applied_at`** (`TEXT` / `TIMESTAMPTZ`): When the migration was executed.
- **`description`** (`TEXT`): Human-readable migration purpose.

---

## 4. Connection Configuration & Data Safety

### Configuration Settings
All database parameters are loaded via environment variables (`.env`) or default configuration:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SQLITE_DB_PATH` | `database/cybershield.db` | Relative or absolute path to local SQLite database file. Supports `:memory:` for testing. |
| `NEON_DATABASE_URL` | *None (empty)* | Cloud connection URI in format: `postgresql://user:pass@ep-host.neon.tech/dbname?sslmode=require` |
| `DATABASE_URL` | *Fallback for NEON_DATABASE_URL* | Standard deployment cloud database URI. |

### Data Security & Privacy Rules
1. **Parameterized Queries Exclusively:** All queries use query placeholders (`?` for SQLite, `%s` for PostgreSQL). String concatenation or formatting into SQL statements is strictly banned, eliminating SQL Injection vulnerabilities.
2. **Credential Sanitization:** The `sanitize_db_url()` utility masks passwords as `***` before URLs can ever be printed to console, logs, or error exceptions.
3. **No Private Files or Plaintext Passwords:** Only hashes and metadata are retained in the database tier.
4. **Idempotent Initialization:** Running `initialize_database()` checks `schema_migrations` before running DDL, preventing destructive resets or table drops.

---

## 5. How to Run Migrations & Automated Tests

### Safe Automatic Migration
Migrations are executed automatically on database initialization. To manually verify or initialize the local database:
```python
from database.sqlite_manager import SQLiteManager

manager = SQLiteManager("database/cybershield.db")
manager.initialize_database()
print("Applied migrations:", manager.get_applied_migrations())
```

### Running Database Test Suite
All database unit, repository, and integration tests execute completely offline without requiring internet access or live cloud credentials:
```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/unit/test_sqlite.py tests/unit/test_postgres.py tests/unit/test_repositories.py tests/integration/test_database_integration.py --cov=database
```

---

## 6. Offline Behavior & Cloud Verification Status

- **Offline Behavior:** Fully verified and operational. The local SQLite database provides 100% functional persistence, foreign key enforcement, transaction rollback, and repository operations.
- **Cloud Verification Status:** **Mocked & Pending Real Neon Credentials.**
  - As per Phase 2 requirements, real live Neon connectivity is not claimed because user credentials have not been provided.
  - The `PostgresManager` implementation has been verified with 100% test coverage using standard `unittest.mock` for connection, queries, transactions, errors, and credential masking.
  - When real credentials are provided in `.env`, the user can verify cloud connectivity using `PostgresManager().test_connection()`.

