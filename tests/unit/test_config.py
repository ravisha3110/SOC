"""Unit tests for configuration loading and environment variable handling."""

import os
from pathlib import Path
from unittest.mock import patch
from config.settings import AppConfig, get_config, load_config


def test_default_config_loading() -> None:
    """Verify default configuration values when no custom environment is set."""
    with patch.dict(os.environ, {}, clear=True):
        cfg = load_config()
        assert isinstance(cfg, AppConfig)
        assert cfg.app_name == "CyberShield - SOC Threat Analytics"
        assert cfg.app_version == "0.1.0"
        assert cfg.environment == "development"
        assert cfg.debug is True
        assert cfg.theme == "dark"
        assert cfg.sqlite_db_path == "database/cybershield.db"
        assert cfg.neon_database_url == ""
        assert cfg.api_host == "127.0.0.1"
        assert cfg.api_port == 8000
        assert cfg.enable_demo_logins is True


def test_custom_environment_variable_overrides() -> None:
    """Verify that environment variables properly override defaults."""
    custom_env = {
        "CYBERSHIELD_APP_TITLE": "CyberShield Custom Title",
        "CYBERSHIELD_ENV": "production",
        "CYBERSHIELD_DEBUG": "false",
        "CYBERSHIELD_THEME": "cyberpunk-dark",
        "SQLITE_DB_PATH": "custom/path.db",
        "NEON_DATABASE_URL": "postgresql://user:pass@ep-test.neon.tech/cybershield",
        "API_HOST": "0.0.0.0",
        "API_PORT": "9000",
    }
    with patch.dict(os.environ, custom_env, clear=True):
        cfg = load_config()
        assert cfg.app_name == "CyberShield Custom Title"
        assert cfg.environment == "production"
        assert cfg.debug is False
        assert cfg.theme == "cyberpunk-dark"
        assert cfg.sqlite_db_path == "custom/path.db"
        assert cfg.neon_database_url == "postgresql://user:pass@ep-test.neon.tech/cybershield"
        assert cfg.api_host == "0.0.0.0"
        assert cfg.api_port == 9000
        assert cfg.enable_demo_logins is False


def test_demo_logins_explicit_override() -> None:
    """Verify explicit CYBERSHIELD_ENABLE_DEMO_LOGINS overrides environment defaults."""
    with patch.dict(os.environ, {"CYBERSHIELD_ENV": "production", "CYBERSHIELD_ENABLE_DEMO_LOGINS": "true"}, clear=True):
        cfg = load_config()
        assert cfg.enable_demo_logins is True

    with patch.dict(os.environ, {"CYBERSHIELD_ENV": "development", "CYBERSHIELD_ENABLE_DEMO_LOGINS": "0"}, clear=True):
        cfg = load_config()
        assert cfg.enable_demo_logins is False


def test_frozen_packaging_sqlite_path(tmp_path: Path) -> None:
    """Verify that packaged frozen execution resolves sqlite path to user AppData."""
    import sys
    appdata_dir = str(tmp_path / "AppData")
    with patch.dict(os.environ, {"APPDATA": appdata_dir}, clear=True):
        with patch.object(sys, "frozen", True, create=True):
            cfg = load_config()
            expected_db = str(Path(appdata_dir) / "CyberShield" / "cybershield.db")
            assert cfg.sqlite_db_path == expected_db
            assert (Path(appdata_dir) / "CyberShield").is_dir()


def test_invalid_api_port_fallback() -> None:
    """Verify that invalid non-integer API_PORT falls back safely to 8000."""
    with patch.dict(os.environ, {"API_PORT": "invalid-port"}, clear=True):
        cfg = load_config()
        assert cfg.api_port == 8000


def test_get_config_caching() -> None:
    """Verify that get_config returns an AppConfig instance."""
    cfg1 = get_config()
    cfg2 = get_config()
    assert isinstance(cfg1, AppConfig)
    assert cfg1 == cfg2


def test_env_file_loading_when_present(tmp_path: Path) -> None:
    """Verify that .env file is loaded when it exists on disk."""
    from config.settings import init_env

    # Test non-existent path
    assert init_env(tmp_path / "non_existent.env") is False

    # Test existing path
    env_file = tmp_path / ".env"
    env_file.write_text("CYBERSHIELD_ENV=test_env_loaded\n", encoding="utf-8")
    assert init_env(env_file) is True

