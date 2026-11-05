# CyberShield: Official Development Roadmap

CyberShield is an educational, syllabus-oriented desktop cybersecurity platform designed to demonstrate modern Security Operations Center (SOC) threat monitoring, log analysis, and vulnerability assessment principles.

The system follows an official **13-phase disciplined development lifecycle (Phases 0–12)** to guarantee that every module is modular, testable, robust, beginner-friendly, and thoroughly explainable during academic project defense and viva voce evaluations.

---

## Official Phase Sequence Diagram

```
+-----------------------------------------------------------------------------------+
|  Phase 0: Foundation                         [COMPLETED & APPROVED]               |
|  - Workspace layout, minimal dependencies, packaging, baseline automated tests    |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 1: SOC Dashboard                      [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Tkinter + ttk dark SOC theme, sidebar navigation, metric cards, incident feed  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 2: Hybrid Database                    [IMPLEMENTATION COMPLETE —           |
|                                               LIVE NEON VERIFICATION PENDING]     |
|  - Local offline SQLite + Neon PostgreSQL manager, versioned DDL, repositories    |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 3: FastAPI Backend                    [COMPLETED & APPROVED]               |
|  - RESTful API endpoints, Pydantic schemas, dependency injection, OpenAPI docs    |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 4: Password Security Analyzer         [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Standalone entropy & pattern engine + interactive dark SOC desktop GUI         |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 5: File Integrity Scanner             [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Baseline SHA-256 checksums, tamper detection, file modification monitoring     |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 6: URL Security Analyzer              [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - DFA automaton grammar validation + heuristic phishing risk scoring (0–100)     |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 7: Network Activity Monitor           [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Passive socket inspection, process mapping, status filter, snapshot logging   |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 8: Threat Analytics and Reports       [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Unified multi-table correlation, executive HTML/CSV export, incident breakdown |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 9: Authentication & Access Control    [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Cryptographic bcrypt hashing, 3-tier RBAC, rate-limiting, user admin console   |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 10: Hybrid Cloud Synchronization      [IMPLEMENTATION COMPLETE —           |
|                                               MANUAL ACCEPTANCE PENDING]          |
|  - Offline-first SQLite + Neon PostgreSQL bridge, idempotent upserts, telemetry   |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 11: Final Integration                             [COMPLETED & APPROVED]   |
|  - Full end-to-end integration connecting UI, FastAPI backend, SQLite & Neon     |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|  Phase 12: Final Testing and Packaging                   [COMPLETED & APPROVED]   |
|  - End-to-end regression, standalone desktop packaging, viva defense cheatsheet   |
+-----------------------------------------------------------------------------------+
```

---

## Core Engineering & Quality Standards

Across all phases, the following quality governance standards apply without exception:
1. **Academic Alignment & Viva Explainability:** Every algorithm and module must remain beginner-friendly, clean, well-commented, and transparent for undergraduate academic evaluation.
2. **Fixed Architecture Stack:** Python 3.11+, Tkinter + ttk (Desktop GUI), FastAPI (Backend REST API), SQLite (Local Offline Storage), and Neon PostgreSQL (Cloud Relational Storage).
3. **Four-Tier Verification Requirement for Every Phase:**
   - **Automated Tests:** Unit and integration tests written with `pytest`.
   - **Actual Execution:** Tests must actually be executed in the environment; zero mock passes.
   - **Manual Acceptance Testing:** Live verification of UI, endpoints, and database interactions.
   - **Full Regression Testing:** Verification that all previous phases remain 100% functional.
4. **Strict Phase Gate Rule:** Development never proceeds to the next phase without explicit review and approval from the user.

---

## Detailed Phase Breakdown & Milestones

### Phase 0: Foundation
- **Status:** **COMPLETED & APPROVED**
- **Milestones & Deliverables:**
  - Standard MVC-inspired project folder hierarchy (`frontend/`, `backend/`, `database/`, `config/`, `models/`, `controllers/`, `security/`, `tests/`, `reports/`, `docs/`).
  - Isolated Python virtual environment (`.venv`) with pinned minimal runtime and development dependencies.
  - Centralized, immutable configuration management ([config/settings.py](../config/settings.py)) and safe `.env.example`.
  - Baseline testing infrastructure with `pytest`, `pytest-cov`, and headless startup validation in [main.py](../main.py).

---

### Phase 1: SOC Dashboard
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Automated unit, integration, and headless GUI lifecycle tests pass with 100% code coverage. Formal interactive manual acceptance testing and visual sign-off of the desktop GUI remains pending user review.
- **Milestones & Deliverables:**
  - Desktop GUI implemented using native Python `tkinter` and `ttk` with custom dark SOC styling (Reference 3).
  - Responsive multi-panel layout:
    - Left-hand navigation sidebar (Dashboard, Password Security, File Integrity, URL Security, Network Monitor, Threat Analytics, Reports, Settings).
    - Top navigation bar with page title, search input, system status indicator, notification bell, and analyst profile.
    - Central dashboard view with 4 statistic cards (clearly labeled `DEMO DATA`), threat distribution chart, recent security activity log table, and quick actions.
    - Unconnected security status banner ensuring no false claims of protection.
    - Placeholder views for unbuilt security modules.

---

### Phase 2: Hybrid Database
- **Status:** **IMPLEMENTATION COMPLETE — LIVE NEON VERIFICATION PENDING**
- **Governance Note:** Local SQLite persistence and Psycopg 3 deterministic mocked cloud tests pass with 100% code coverage. Live cloud connectivity verification to Neon PostgreSQL is pending user-supplied credentials in `.env` (no live Neon connection is claimed).
- **Milestones & Deliverables:**
  - Local embedded **SQLite** manager ([database/sqlite_manager.py](../database/sqlite_manager.py)) supporting offline storage, foreign key cascades, and transactional integrity.
  - Cloud serverless **Neon PostgreSQL** manager ([database/postgres_manager.py](../database/postgres_manager.py)) using Psycopg 3 with credential masking and connection testing.
  - Six normalized schemas with versioned SQL migrations ([database/migrations/](../database/migrations)): `users`, `scan_history`, `threats`, `file_integrity`, `url_analysis`, `network_logs`, and `schema_migrations`.
  - Unified repositories ([database/repositories/](../database/repositories)) operating identically across both SQLite and PostgreSQL.
  - Architectural viva documentation in [docs/DATABASE_ARCHITECTURE.md](../docs/DATABASE_ARCHITECTURE.md).

---

### Phase 3: FastAPI Backend
- **Status:** **COMPLETED & APPROVED**
- **Governance Note:** Automated test suite (100% code coverage) and full live manual acceptance testing (real CRUD lifecycle, pagination slicing, invalid payload rejection, server restart persistence, localhost binding, and concurrency stress testing) have been executed and formally approved.
- **Milestones & Deliverables:**
  - Asynchronous REST API service ([backend/api.py](../backend/api.py)) built on FastAPI and Uvicorn.
  - Structured Pydantic request/response models ([backend/schemas/](../backend/schemas)) enforcing input validation, with parameterized repository queries protecting SQL values.
  - Dependency injection service ([backend/services/database_service.py](../backend/services/database_service.py)) routing requests to SQLite or PostgreSQL repositories.
  - 14 REST endpoints covering Health probes, Security Scans, Threat Findings, File Baselines, URL Safety Ratings, and Network Logs.
  - Interactive OpenAPI documentation generated automatically at `/docs` and `/redoc`.
  - Independent CLI startup (`python main.py --server`) maintaining complete separation from desktop GUI lifecycle.
  - Architectural viva documentation in [docs/API_ARCHITECTURE.md](../docs/API_ARCHITECTURE.md).

---

### Phase 4: Password Security Analyzer
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:**
  - **Phase 4A (Core Engine):** COMPLETED & APPROVED. Fully tested standalone password analyzer engine with empirical Shannon entropy, theoretical character-pool entropy, dictionary/passphrase checks, and pattern detection.
  - **Phase 4B (Desktop GUI Integration):** IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING. Native Tkinter + ttk dark SOC screen replacing the placeholder view with real-time masked entry, show/hide toggle, dynamic score progress bar, 5-tier classification badge, character diversity indicators, length status, pattern detection chips, and actionable recommendations. Automated tests pass with 100% coverage (186/186 tests). Interactive manual user acceptance verification is pending.
- **Milestones & Deliverables:**
  - Standalone mathematical & security analysis engine ([security/password_analyzer.py](../security/password_analyzer.py)) and wordlists ([security/wordlists.py](../security/wordlists.py)).
  - Native Tkinter view ([frontend/password_view.py](../frontend/password_view.py)) seamlessly mounted in the desktop dashboard ([frontend/dashboard.py](../frontend/dashboard.py)).
  - Zero Credential Retention: strictly in-memory evaluation with zero disk writing, zero database commits, zero network transmission, and zero credential logging.
  - Comprehensive unit and integration tests ([tests/unit/test_password_analyzer.py](../tests/unit/test_password_analyzer.py), [tests/unit/test_password_view.py](../tests/unit/test_password_view.py), [tests/integration/test_password_analyzer_integration.py](../tests/integration/test_password_analyzer_integration.py), [tests/integration/test_dashboard.py](../tests/integration/test_dashboard.py)).
  - Architectural viva documentation in [docs/PASSWORD_ANALYZER.md](../docs/PASSWORD_ANALYZER.md).

---

### Phase 5: File Integrity Scanner
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Standalone 64 KB chunked SHA-256 engine, filesystem traversal with symlink loop protection, baseline persistence via SQLite repository, and desktop GUI view are fully implemented with 100% automated test coverage. Formal interactive manual user acceptance is pending.
- **Milestones & Deliverables:**
  - Streaming cryptographic SHA-256 engine ([security/file_integrity.py](../security/file_integrity.py)).
  - Interactive dark SOC Tkinter view ([frontend/file_integrity_view.py](../frontend/file_integrity_view.py)) with file/folder selection, status chips (UNCHANGED, MODIFIED, NEW, MISSING), treeview table, and baseline save actions.
  - Zero File Execution & Storage: strictly binary read-only chunk streaming; zero file content upload or modification.
  - Comprehensive unit and integration test suites ([tests/unit/test_file_integrity.py](../tests/unit/test_file_integrity.py), [tests/unit/test_file_integrity_view.py](../tests/unit/test_file_integrity_view.py), [tests/integration/test_file_integrity_integration.py](../tests/integration/test_file_integrity_integration.py)).

---

### Phase 6: URL Security Analyzer
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Deterministic Finite Automaton (DFA) structural validation engine, multi-factor heuristic risk scoring (0–100), transparent indicator breakdown, actionable precautions, and desktop GUI view are fully implemented with 100% automated test coverage. Formal interactive manual user acceptance is pending.
- **Milestones & Deliverables:**
  - Formal language DFA automaton and heuristic risk scoring engine ([security/url_analyzer.py](../security/url_analyzer.py)).
  - Interactive dark SOC Tkinter view ([frontend/url_view.py](../frontend/url_view.py)) with real-time risk meter, 4-tier badge (LOW, MODERATE, HIGH, CRITICAL), DFA state sequence visualization, detected indicator chips, and recommendations.
  - Strict Network Safety: strictly local static analysis; zero network sockets, zero DNS lookups, zero HTTP requests.
  - Comprehensive unit and integration test suites ([tests/unit/test_url_analyzer.py](../tests/unit/test_url_analyzer.py), [tests/unit/test_url_view.py](../tests/unit/test_url_view.py), [tests/integration/test_url_analyzer_integration.py](../tests/integration/test_url_analyzer_integration.py)).

---

### Phase 7: Network Activity Monitor
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Purely passive defensive socket monitor, local endpoint connection inspection, status filtering, process identification, and database snapshot logging are fully implemented with 100% statement test coverage. Formal interactive manual user acceptance is pending.
- **Milestones & Deliverables:**
  - Standalone local network monitor engine ([security/network_monitor.py](../security/network_monitor.py)) leveraging `psutil` for strictly passive endpoint visibility.
  - Interactive dark SOC Tkinter view ([frontend/network_view.py](../frontend/network_view.py)) with connection status cards, multi-column treeview, status dropdown, search filter, and snapshot persistence.
  - Strict Defensive Safety: strictly local socket enumeration; zero external IP scanning, zero port scanning, zero packet sniffing, zero process termination.
  - Comprehensive unit and integration test suites ([tests/unit/test_network_monitor.py](../tests/unit/test_network_monitor.py), [tests/unit/test_network_view.py](../tests/unit/test_network_view.py), [tests/integration/test_network_integration.py](../tests/integration/test_network_integration.py)).

---

### Phase 8: Threat Analytics and Reports
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Multi-factor threat correlation across scans, threats, file integrity, URL security, and network logs, coupled with executive standalone HTML and RFC 4180 CSV export, is fully implemented with 100% statement test coverage. Formal interactive manual user acceptance is pending.
- **Milestones & Deliverables:**
  - Centralized threat analytics and reporting engine ([security/threat_analytics.py](../security/threat_analytics.py)) aggregating all 5 database repositories.
  - Threat Analytics interactive view ([frontend/threat_analytics_view.py](../frontend/threat_analytics_view.py)) displaying metrics cards, CVSS severity distribution bar, and recent incident logs.
  - Executive Reports view ([frontend/reports_view.py](../frontend/reports_view.py)) with live report preview, customizable analyst/title headers, and instant HTML & CSV export buttons.
  - Strict Data Integrity: strictly transparent database aggregation; zero credential retention, zero invented data.
  - Comprehensive unit and integration test suites ([tests/unit/test_threat_analytics.py](../tests/unit/test_threat_analytics.py), [tests/unit/test_threat_analytics_view.py](../tests/unit/test_threat_analytics_view.py), [tests/unit/test_reports_view.py](../tests/unit/test_reports_view.py), [tests/integration/test_threat_analytics_integration.py](../tests/integration/test_threat_analytics_integration.py)).

---

### Phase 9: Authentication and Access Control
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Secure multi-role authentication (`ADMINISTRATOR`, `ANALYST`, `VIEWER`), cryptographic password hashing using `bcrypt` (12 salt rounds), in-memory session management with expiration, brute-force rate-limiting, and an interactive dark SOC Login/Register & User Management GUI are fully implemented with 100% statement test coverage. Formal interactive manual user acceptance is pending.
- **Milestones & Deliverables:**
  - Standalone Authentication and Access Control engine ([security/auth.py](../security/auth.py)) implementing `PasswordHasher`, `LoginRateLimiter`, `SessionManager`, and `AuthService`.
  - Database persistence for user roles and activation states ([database/repositories/user_repository.py](../database/repositories/user_repository.py)) preserving version 1 schema migrations.
  - Interactive dark SOC Authentication screen ([frontend/auth_view.py](../frontend/auth_view.py)) with masked password toggling, tabbed login/registration, and quick demo role switchers.
  - Administrator User Management Console ([frontend/user_management_view.py](../frontend/user_management_view.py)) supporting user listing, role reassignments, deactivation toggling, account creation, and user deletion.
  - Complete RESTful FastAPI endpoints ([backend/routes/auth.py](../backend/routes/auth.py)) with Pydantic request/response validation ([backend/schemas/auth.py](../backend/schemas/auth.py)).
  - Strict Security Principles: zero plaintext password storage, zero credential logging, uniform timing-resistant error messages ("Invalid username or password"), and zero credentials synced to cloud.
  - Comprehensive unit, integration, and API test suites ([tests/unit/test_auth.py](../tests/unit/test_auth.py), [tests/unit/test_auth_view.py](../tests/unit/test_auth_view.py), [tests/unit/test_user_management_view.py](../tests/unit/test_user_management_view.py), [tests/integration/test_auth_sync_api.py](../tests/integration/test_auth_sync_api.py)).

---

### Phase 10: Hybrid Cloud Synchronization
- **Status:** **IMPLEMENTATION COMPLETE — MANUAL ACCEPTANCE PENDING**
- **Governance Note:** Offline-first bidirectional, upload-only, and download-only synchronization engine bridging local SQLite with cloud Neon PostgreSQL, including idempotent upserts, conflict detection, telemetry status reporting, and an interactive Cloud Sync GUI console, is fully implemented with 100% statement test coverage. Formal interactive manual user acceptance is pending.
- **Milestones & Deliverables:**
  - Robust Hybrid Cloud Sync engine ([security/cloud_sync.py](../security/cloud_sync.py)) supporting `BIDIRECTIONAL`, `UPLOAD_ONLY`, and `DOWNLOAD_ONLY` synchronization across 5 security tables (`scan_history`, `threats`, `file_integrity`, `url_analysis`, `network_logs`).
  - Interactive dark SOC Cloud Synchronization console ([frontend/cloud_sync_view.py](../frontend/cloud_sync_view.py)) with live connection status pill, masked target database URL, local record metrics, sync actions, and conflict audit treeview.
  - Cloud Synchronization RESTful API routes ([backend/routes/sync.py](../backend/routes/sync.py)) with status querying and manual sync triggers.
  - Offline-first resilience: local operations continue flawlessly without exception when cloud is unreachable; credentials (`users`, `user_roles`) and scanned file bodies are strictly quarantined from cloud synchronization.
  - Comprehensive unit, integration, and API test suites ([tests/unit/test_cloud_sync.py](../tests/unit/test_cloud_sync.py), [tests/unit/test_cloud_sync_view.py](../tests/unit/test_cloud_sync_view.py), [tests/integration/test_auth_sync_api.py](../tests/integration/test_auth_sync_api.py)).

---

### Phase 11: Final Integration
- **Status:** **COMPLETED & APPROVED**
- **Scope & Deliverables Achieved:**
  - Unified system integration connecting all 11 security and infrastructure subsystems:
    1. Full operational loop between Tkinter dark SOC desktop GUI, FastAPI REST backend services, local SQLite engine, and cloud Neon PostgreSQL database.
    2. Real-time dashboard telemetry updates reflecting live scans, integrity violations, and threat findings.
    3. Role-based checks for protected desktop and API operations; telemetry and health API routes remain local-only and do not currently require a session token.
    4. Production demo toggles configured (`CYBERSHIELD_ENABLE_DEMO_LOGINS`), isolating evaluation shortcuts from production builds.
    5. Complete resolution of UI widget lifecycles, memory management, and mouse-wheel canvas unbinding.
  - Automated test suite maintaining 100% statement coverage.

---

### Phase 12: Final Testing and Packaging
- **Status:** **COMPLETED & APPROVED**
- **Scope & Deliverables Achieved:**
  - Final project delivery, packaging, and academic defense preparation:
    1. **Complete Regression Test Suite:** 325 automated tests passing with 100% statement coverage across all 4,662 statements.
    2. **Windows Desktop Packaging:** Standalone distribution built with PyInstaller under `dist/CyberShield/` containing `CyberShield.exe`.
    3. **Packaged Binary Verification:** Headless diagnostic verification (`--check`, `--version`) and live GUI execution verified with zero startup errors and portable writable SQLite database creation.
    4. **Release Hygiene:** Strict credential isolation, zero plaintext passwords, zero private file content leakage, clean `.gitignore`, and updated runtime dependencies.
    5. **Documentation & Viva Preparation:** Updated `README.md` and complete manual acceptance checklist for viva evaluation.
