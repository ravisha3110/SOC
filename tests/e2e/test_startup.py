"""End-to-End tests for application startup without requiring a visible GUI."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from config.settings import AppConfig
from main import run_desktop_app


def test_subprocess_application_startup_check() -> None:
    """Verify application startup via subprocess in a clean execution context."""
    project_root = Path(__file__).resolve().parent.parent.parent
    cmd = [sys.executable, "main.py", "--check"]

    result = subprocess.run(
        cmd,
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, f"Process failed: {result.stderr}"
    assert "CyberShield" in result.stdout
    assert "Phase 0" in result.stdout
    assert "[SUCCESS] Phase 0 startup self-check passed." in result.stdout


def test_run_desktop_app_lifecycle_headless() -> None:
    """Verify desktop window lifecycle by running CyberShieldApp headlessly."""
    test_config = AppConfig(
        app_name="CyberShield Test",
        app_version="0.1.0",
        environment="testing",
        debug=True,
        theme="dark",
        sqlite_db_path=":memory:",
        neon_database_url="",
        api_host="127.0.0.1",
        api_port=8000,
    )

    with patch("frontend.dashboard.CyberShieldApp") as mock_app_cls:
        mock_app = MagicMock()
        mock_app.run.return_value = 0
        mock_app_cls.return_value = mock_app

        exit_code = run_desktop_app(test_config)

        assert exit_code == 0
        mock_app_cls.assert_called_once_with(config=test_config)
        mock_app.run.assert_called_once()

