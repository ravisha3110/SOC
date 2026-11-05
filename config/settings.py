"""CyberShield Application Configuration.

Loads environment variables safely with robust fallback defaults,
ensuring security and explainability for academic project evaluation.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from dotenv import load_dotenv

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent


def init_env(env_path: Path | None = None) -> bool:
    """Load environment variables from .env file if present.

    Args:
        env_path: Optional explicit Path to .env file.

    Returns:
        bool: True if file was found and loaded, False otherwise.
    """
    target = env_path or (BASE_DIR / ".env")
    if target.is_file():
        load_dotenv(dotenv_path=target)
        return True
    return False


# Auto-initialize environment on import if .env exists
init_env()


@dataclass(frozen=True)
class AppConfig:
    """Application configuration container."""

    app_name: str
    app_version: str
    environment: str
    debug: bool
    theme: str
    sqlite_db_path: str
    neon_database_url: str
    api_host: str
    api_port: int
    enable_demo_logins: bool = True


def load_config() -> AppConfig:
    """Load configuration from environment variables or sensible defaults.

    Returns:
        AppConfig: Immutable application configuration instance.
    """
    debug_val = os.getenv("CYBERSHIELD_DEBUG", "True").strip().lower()
    is_debug = debug_val in ("1", "true", "yes", "on")

    raw_port = os.getenv("API_PORT", "8000").strip()
    try:
        api_port = int(raw_port)
    except ValueError:
        api_port = 8000

    env_name = os.getenv("CYBERSHIELD_ENV", "development").strip().lower()

    # In production, demo login shortcuts are disabled by default
    demo_env = os.getenv("CYBERSHIELD_ENABLE_DEMO_LOGINS")
    if demo_env is not None:
        enable_demo = demo_env.strip().lower() in ("1", "true", "yes", "on")
    else:
        enable_demo = (env_name != "production")

    # Detect PyInstaller frozen execution for portable writable storage
    is_frozen = getattr(sys, "frozen", False)
    default_db_path = "database/cybershield.db"
    if is_frozen and "SQLITE_DB_PATH" not in os.environ:
        appdata_dir = os.getenv("APPDATA") or str(Path.home())
        db_dir = Path(appdata_dir) / "CyberShield"
        db_dir.mkdir(parents=True, exist_ok=True)
        default_db_path = str(db_dir / "cybershield.db")

    return AppConfig(
        app_name=os.getenv("CYBERSHIELD_APP_TITLE", "CyberShield - SOC Threat Analytics"),
        app_version="0.1.0",
        environment=env_name,
        debug=is_debug,
        theme=os.getenv("CYBERSHIELD_THEME", "dark"),
        sqlite_db_path=os.getenv("SQLITE_DB_PATH", default_db_path),
        neon_database_url=os.getenv("NEON_DATABASE_URL") or os.getenv("DATABASE_URL") or "",
        api_host=os.getenv("API_HOST", "127.0.0.1"),
        api_port=api_port,
        enable_demo_logins=enable_demo,
    )


# Cached configuration instance for application-wide use
_current_config: AppConfig | None = None


def get_config() -> AppConfig:
    """Retrieve the cached configuration or load a new one if not yet initialized."""
    global _current_config
    if _current_config is None:
        _current_config = load_config()
    return _current_config
