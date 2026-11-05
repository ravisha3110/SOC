# CyberShield — SOC Threat Analytics Desktop Application

CyberShield is an educational, defensive Security Operations Center (SOC) workstation built with Python 3.11, Tkinter/ttk, SQLite, and FastAPI. It brings local security analysis, activity records, role-aware views, and optional Neon PostgreSQL synchronization into one desktop application.

The project is designed for coursework, demonstrations, and learning. The interface and analyzers are explainable and run locally; cloud storage is optional.

## Features

- **SOC dashboard:** Recent activity, status indicators, severity distribution, summary cards, and quick actions.
- **Password analyzer:** Entropy estimates and pattern checks, including common phrases, repeated characters, and predictable suffixes. Analysis is local; it does not query breach-checking services.
- **File integrity monitor:** SHA-256 file and directory baselines, comparison results, and local history.
- **URL analyzer:** Local parsing and heuristic risk scoring. It does not open or fetch the submitted URL.
- **Network activity monitor:** Reads local socket information through `psutil`; it does not scan remote hosts or capture packets.
- **Threat analytics and reports:** Correlates local records and exports HTML and CSV reports.
- **Authentication and user management:** Bcrypt password hashes, expiring sessions, login throttling, and Administrator, Analyst, and Viewer roles.
- **Cloud synchronization:** Optional SQLite-to-Neon PostgreSQL synchronization with bidirectional, upload-only, and download-only modes.
- **REST API:** FastAPI endpoints for health, authentication, and security records, with interactive OpenAPI documentation.

## Technology

| Area | Technology |
| --- | --- |
| Desktop interface | Python 3.11, Tkinter, ttk |
| API | FastAPI, Uvicorn, Pydantic |
| Local storage | SQLite 3 |
| Optional cloud storage | Neon PostgreSQL, Psycopg 3 |
| Authentication | bcrypt, in-memory sessions, role checks |
| Testing | pytest, pytest-cov |
| Windows packaging | PyInstaller one-folder build |

## Quick start on Windows

Use Windows 10 or 11 and Python 3.11. Git is required to clone the repository. Run these commands from PowerShell.

### 1. Clone the repository

```powershell
git clone https://github.com/ravisha3110/SOC.git
cd SOC
```

### 2. Create a virtual environment and install dependencies

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes the runtime requirements, test tools, and PyInstaller. You do not need to activate the virtual environment when using the commands below.

### 3. Create local configuration

```powershell
Copy-Item .env.example .env
notepad .env
```

SQLite works without a cloud account. Leave `NEON_DATABASE_URL` empty to use local storage only. To use Neon, create your own PostgreSQL database and put its connection URI in your local `.env` file. Never put real credentials in `README.md`, `.env.example`, screenshots, or commits.

### 4. Start the desktop application

```powershell
.\.venv\Scripts\python.exe main.py
```

Run the command from the repository root so relative paths and local configuration resolve correctly. In development mode, demo login shortcuts are enabled by default; they are disabled by default when `CYBERSHIELD_ENV=production`.

## Other platforms

Windows is the primary packaged target. For local development on macOS or Linux, install Python 3.11, Git, and the operating system's Tcl/Tk package, then run:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python main.py
```

If Python reports that Tkinter is unavailable, install the Tcl/Tk support package provided by your operating system and recreate the virtual environment with a Python build that includes Tk support.

## Configuration

Settings are loaded from environment variables and, when present, the local `.env` file. Defaults are defined in `config/settings.py`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CYBERSHIELD_ENV` | `development` | Environment name; production disables demo login shortcuts unless explicitly enabled. |
| `CYBERSHIELD_DEBUG` | `True` | Enables development diagnostics. |
| `CYBERSHIELD_APP_TITLE` | `CyberShield - SOC Threat Analytics` | Desktop window title. |
| `CYBERSHIELD_THEME` | `dark` | Theme setting. |
| `CYBERSHIELD_ENABLE_DEMO_LOGINS` | Enabled outside production | Set explicitly to `false` to hide demo login shortcuts. |
| `SQLITE_DB_PATH` | `database/cybershield.db` | Local SQLite database path. |
| `NEON_DATABASE_URL` | Empty | Optional Neon PostgreSQL URI; `DATABASE_URL` is used as a fallback. |
| `API_HOST` | `127.0.0.1` | FastAPI bind address. Keep loopback for local use. |
| `API_PORT` | `8000` | FastAPI port. |

When running the packaged Windows application, the default SQLite database is stored under `%APPDATA%\CyberShield\` so it can be written without administrator permissions. Runtime databases, `.env`, build output, coverage reports, and screenshots are excluded by `.gitignore`.

## Run modes

Run commands from the repository root.

### Desktop GUI

```powershell
.\.venv\Scripts\python.exe main.py
```

### Environment diagnostic

```powershell
.\.venv\Scripts\python.exe main.py --check
```

### FastAPI server

```powershell
.\.venv\Scripts\python.exe main.py --server
```

Open [Swagger UI](http://127.0.0.1:8000/docs) or [ReDoc](http://127.0.0.1:8000/redoc) while the server is running. The server uses `API_HOST` and `API_PORT` from configuration.

## API overview and access model

The main endpoint groups are:

| Group | Example endpoints |
| --- | --- |
| Health | `GET /api/health`, `GET /api/health/database` |
| Authentication | `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me` |
| User administration | `GET/PATCH/DELETE /api/auth/users...` |
| Scans and findings | `/api/scans`, `/api/threats` |
| File, URL, and network records | `/api/files`, `/api/urls`, `/api/network` |
| Cloud synchronization | `GET /api/sync/status`, `POST /api/sync/trigger` |

Login returns a session token. Authenticated endpoints accept it in the `X-Session-Token` header. User-administration endpoints require the Administrator role; cloud-sync endpoints require Administrator or Analyst.

**API limitation:** Registration and the scan, threat, file, URL, network, and health routes currently do not require a session token. The public registration route accepts a requested role, so keep the API on `127.0.0.1` and do not expose it to an untrusted network until those access policies are tightened. CORS settings are not a substitute for authentication.

## Tests and coverage

Run the full unit, integration, and end-to-end suite:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

`pytest.ini` enables terminal and HTML coverage reporting. The HTML report is written to `reports/coverage_html/` and is ignored by Git.

At the time this README was updated, the suite completed with **325 passed**, **100% statement coverage across 4,662 statements**, and one Starlette deprecation warning from its test client dependency.

## Build the Windows application

Build the one-folder distribution locally:

```powershell
.\.venv\Scripts\python.exe -m PyInstaller cybershield.spec --clean --noconfirm
```

The output is created under `dist/CyberShield/`; launch it with:

```powershell
.\dist\CyberShield\CyberShield.exe
```

The generated `dist/` directory is intentionally not committed. Build it with the command above when you need a local executable.

## Project layout

```text
main.py                  Application entry point: GUI, checks, and API server
config/                  Environment and path configuration
frontend/                Tkinter views, shared components, and theme
security/                Analysis, authentication, monitoring, and sync logic
backend/                 FastAPI app, routes, schemas, and services
database/                SQLite/PostgreSQL managers, migrations, and repositories
tests/                   Unit, integration, and end-to-end tests
docs/                    Architecture, analyzer, and development documentation
requirements.txt         Runtime dependencies
requirements-dev.txt     Runtime plus development/test dependencies
cybershield.spec         PyInstaller build specification
```

## Documentation

The `docs/` directory contains the detailed project guides:

| Document | What it covers |
| --- | --- |
| [API architecture](docs/API_ARCHITECTURE.md) | FastAPI structure, endpoint groups, validation, session handling, and local API boundaries. |
| [Database architecture](docs/DATABASE_ARCHITECTURE.md) | SQLite and Neon design, schema, migrations, repositories, and offline behavior. |
| [Password analyzer](docs/PASSWORD_ANALYZER.md) | Entropy measures, pattern checks, limitations, examples, and viva questions. |
| [Development roadmap](docs/DEVELOPMENT_ROADMAP.md) | The original 12-phase project plan and milestone notes. |

## Security and privacy notes

- The `.env` file is local configuration and is ignored by Git. Commit only the placeholder template `.env.example`.
- Passwords are stored as bcrypt hashes; plaintext passwords are not written to the database.
- Password and URL analysis run locally. URL analysis does not make an HTTP request or DNS lookup for the submitted URL.
- Network monitoring reads local socket information; it does not perform packet capture, remote scans, or process termination.
- Cloud synchronization is optional. Do not configure a real Neon URI in a public example or commit.
- The FastAPI service defaults to loopback. Review the API access limitation above before changing its bind address.

## Troubleshooting

- **`No module named tkinter`:** Install Python with Tcl/Tk support (and the OS Tk package on Linux), then recreate `.venv`.
- **`No module named ...`:** Install dependencies again with `python -m pip install -r requirements-dev.txt` inside `.venv`.
- **API port is busy:** Set `API_PORT` in `.env` to an unused local port and use that port in the browser.
- **Cloud status is offline:** The desktop app works with SQLite alone. Check `NEON_DATABASE_URL` only if you intend to use Neon sync.
- **Database path errors:** Start from the repository root or set `SQLITE_DB_PATH` to a writable path.

## License

No `LICENSE` file is included in this repository. Reuse terms have not been specified.
