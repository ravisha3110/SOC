# CyberShield: REST API & Backend Architecture

This document provides a comprehensive, beginner-friendly academic guide explaining the architecture, mechanics, endpoints, and viva voce concepts for the CyberShield FastAPI backend integration.

---

## 1. Core Concepts Explained (Viva Preparation)

### What is an API?
An **API** (Application Programming Interface) is a set of defined rules, protocols, and contracts that allows one software program to talk to another. In CyberShield, the API acts as a secure intermediary between the desktop user interface (Tkinter) or external security monitoring agents, and the underlying database storage layers (SQLite and Neon PostgreSQL). Instead of directly opening SQL files, applications make structured network requests to the API.

### What is REST?
**REST** stands for **Representational State Transfer**. It is a software architectural style for designing networked applications using the standard communication conventions of the World Wide Web.
- **Statelessness:** Every request sent from a client to the server contains all the information needed to understand and process the request. The server does not store client session state between requests.
- **Resource-Based:** Everything in the system (a scan, a threat finding, a monitored file) is treated as a **Resource** identified by a unique URL (e.g. `/api/scans/12345`).
- **Standard HTTP Methods:**
  - `GET`: Retrieve a resource without modifying server state.
  - `POST`: Create a new resource on the server.
  - `DELETE`: Remove an existing resource.

### What is an HTTP Request?
An **HTTP Request** is a formatted message sent from a client (such as a browser, script, or desktop app) to a server over TCP/IP:
1. **Method:** The action to take (`GET`, `POST`, `OPTIONS`).
2. **Path / URL:** The resource endpoint (`/api/scans`).
3. **Headers:** Key-value metadata providing context (e.g. `Content-Type: application/json`, `Origin`).
4. **Query Parameters:** Key-value pairs in the URL used for filtering or pagination (`?limit=50&offset=0`).
5. **Body (Payload):** The data sent with `POST` requests, typically encoded as a JSON object.

### What HTTP Status Codes are Used?
The server replies with standardized 3-digit numeric status codes:
- **`200 OK`:** Request succeeded and returned requested data.
- **`201 Created`:** A new record was successfully created in the database.
- **`400 Bad Request`:** Client provided invalid data (e.g. referencing a nonexistent parent scan).
- **`404 Not Found`:** The requested record ID does not exist in the database.
- **`409 Conflict`:** Duplicate record violation (e.g. duplicate primary key or unique constraint).
- **`422 Unprocessable Entity`:** Pydantic schema validation failure (e.g. risk score > 100 or bad UUID format).
- **`500 Internal Server Error`:** An unexpected server error occurred (sanitized to protect credentials).
- **`503 Service Unavailable`:** Storage backend connection failed or is unreachable.

### What is FastAPI?
**FastAPI** is a modern, high-performance web framework for building REST APIs with Python based on standard Python type hints.
- **Automatic OpenAPI Documentation:** Automatically generates interactive documentation at `/docs` (Swagger UI) and `/redoc`.
- **Fast Execution:** Built on Starlette (ASGI toolkit) and Pydantic (data parsing).
- **Dependency Injection:** Allows database services and repositories to be injected cleanly into route handlers without coupling code.

### What is Pydantic?
**Pydantic** is a data parsing and validation library for Python that uses standard type annotations.
- In CyberShield, Pydantic schemas inspect incoming JSON payloads *before* database execution.
- It rejects invalid types, values, and enum choices with a structured HTTP 422 response. SQL injection protection comes from repository queries using parameterized values; Pydantic is input validation, not a SQL firewall.

---

## 2. API Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                        Client Layer (Desktop Tkinter / Agents)                    |
+-----------------------------------------------------------------------------------+
                                         |
                                HTTP / JSON Requests
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                            FastAPI Application (api.py)                           |
|  - CORS Localhost Restriction   - Global Exception Handlers  - OpenAPI /docs     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                           Pydantic Validation Schemas                             |
|  - ScanCreate / ScanResponse   - ThreatCreate   - FileIntegrity   - URLAnalysis   |
+-----------------------------------------------------------------------------------+
                                         |
                        FastAPI Depends() Dependency Injection
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     DatabaseService & Repository Abstraction Layer                |
|  - ScanRepository  - ThreatRepository  - FileIntegrityRepo  - URLAnalysisRepo    |
+-----------------------------------------------------------------------------------+
                                         |
                 +-----------------------+-----------------------+
                 | (Default)                                     | (Configured)
                 v                                               v
+----------------------------------+            +----------------------------------+
|      SQLiteManager (Local)       |            |    PostgresManager (Cloud Neon)  |
|  - database/cybershield.db       |            |  - Psycopg 3 Binary Driver       |
|  - Parameterized Queries (?)     |            |  - Parameterized Queries (%s)    |
|  - Fully Offline Persistence     |            |  - Serverless Remote Storage     |
+----------------------------------+            +----------------------------------+
```

---

## 3. Communication Mechanics

### How FastAPI Communicates with SQLite
1. When a client performs a `POST /api/scans`, FastAPI validates the JSON payload with `ScanCreate`.
2. FastAPI calls `get_scan_repo`, which retrieves the `ScanRepository` bound to `DatabaseService`.
3. The repository prepares a parameterized SQL statement (`INSERT INTO scan_history VALUES (?, ?, ...)`).
4. `SQLiteManager` executes the query inside a managed connection context. Parameter placeholders (`?`) prevent SQL injection by ensuring data values are treated strictly as literals, never executable code.
5. SQLite commits the record to `database/cybershield.db`, and the created record is returned as a validated `ScanResponse`.

### How FastAPI Communicates with Neon PostgreSQL
1. When `DATABASE_BACKEND=postgres` is set in configuration, `DatabaseService` instantiates `PostgresManager`.
2. Connection credentials are read securely from `NEON_DATABASE_URL` (or `DATABASE_URL`) without hardcoding.
3. The repositories utilize the same execution protocol (`execute`, `fetch_one`, `fetch_all`).
4. Parameter placeholders (`%s`) are dynamically mapped for PostgreSQL compatibility.
5. If the remote database is unreachable or credentials are unverified, health endpoints return `HTTP 503` and gracefully inform the client without leaking connection strings or credentials.

---

## 4. REST API Endpoint Reference

### Authentication & User Administration
Session-protected calls use the token returned by login in an `X-Session-Token: <token>` header.

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Public | Create a user account; the request currently accepts a role value |
| `POST` | `/api/auth/login` | Public | Verify credentials and create a session |
| `POST` | `/api/auth/logout` | Signed-in user | Revoke the current session |
| `GET` | `/api/auth/me` | Signed-in user | Return the current account and role |
| `GET` | `/api/auth/users` | Administrator | List user accounts |
| `PATCH` | `/api/auth/users/{user_id}/role` | Administrator | Change a user's role |
| `PATCH` | `/api/auth/users/{user_id}/status` | Administrator | Activate or deactivate a user |
| `DELETE` | `/api/auth/users/{user_id}` | Administrator | Delete a user account |

### Hybrid Cloud Synchronization
| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/sync/status` | Administrator or Analyst | Read cloud connection and pending-sync status |
| `POST` | `/api/sync/trigger` | Administrator or Analyst | Start a synchronization using the requested direction |

### Health & Diagnostics
| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Application status probe | `200` |
| `GET` | `/api/health/database` | Database backend connectivity probe | `200`, `503` |

### Security Scans
| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/scans` | Record a new historical security scan | `201`, `422`, `500`, `503` |
| `GET` | `/api/scans` | List paginated security scans (`?limit=50&offset=0`) | `200`, `422` |
| `GET` | `/api/scans/{scan_id}` | Fetch full details of single scan | `200`, `404` |

### Threat Findings
| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/threats` | Log a threat finding linked to parent scan | `201`, `400`, `422`, `500` |
| `GET` | `/api/threats` | List threats (`?limit=50&offset=0&scan_id=...`) | `200`, `422` |
| `GET` | `/api/threats/{threat_id}` | Fetch details of single threat finding | `200`, `404` |

### File Integrity Baselines
| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/files` | Register a file checksum baseline | `201`, `409`, `422`, `500` |
| `GET` | `/api/files` | List paginated file integrity baselines | `200`, `422` |

### URL Security Analyses
| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/urls` | Record URL threat evaluation & risk score | `201`, `422`, `500` |
| `GET` | `/api/urls` | List paginated URL inspection records | `200`, `422` |

### Network Telemetry Logs
| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/network` | Record network socket connection event | `201`, `422`, `500` |
| `GET` | `/api/network` | List paginated network telemetry logs | `200`, `422` |

---

## 5. Security & Boundary Enforcement

1. **Local Binding by Default:** The documented and default server address is `127.0.0.1`. Keep it loopback-only; do not bind to a public or untrusted network without first adding and reviewing authentication for every route.
2. **CORS Is Not Authentication:** The application allows its configured local origins. CORS only affects browser cross-origin requests; it does not protect an endpoint from other local programs or network clients.
3. **Route Access Varies:** Login issues a session token in the `X-Session-Token` header. Logout and `/api/auth/me` require a signed-in session; user-management routes require Administrator; sync routes require Administrator or Analyst. Registration, scan, threat, file, URL, network, and health routes currently do not require a session token. Registration also accepts a requested role. Keep the API loopback-only until registration and all open routes have reviewed access policies.
4. **Sensitive Data Masking:** Database connection strings are masked via `sanitize_db_url()`. Connection URLs containing passwords are displayed with the password replaced, for example `postgresql://usr:***@host/db`.
5. **Desktop GUI Boundary:** Launching the Tkinter GUI does not start the web server. The API runs independently through the `--server` option or Uvicorn.

---

## 6. How to Start the API & Run Tests

### Starting the API Independently
You can launch the FastAPI server using either CyberShield's CLI entry-point or Uvicorn directly:

**Method 1: CyberShield CLI**
```powershell
.\.venv\Scripts\python.exe main.py --server
```

**Method 2: Uvicorn Directly**
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```

Once running:
- **Interactive Documentation (Swagger):** Visit [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation:** Visit [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Running Automated API Tests
To execute backend unit and integration tests with coverage:
```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_backend_schemas.py tests/unit/test_backend_services.py tests/integration/test_api_endpoints.py -v --cov=backend --cov-report=term-missing
```

To run the complete application test suite across all development phases:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

