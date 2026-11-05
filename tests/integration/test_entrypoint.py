"""Integration tests for main application entry-point and CLI parsing."""

from unittest.mock import MagicMock, patch
import pytest
from config.settings import load_config
from main import main, parse_arguments, verify_environment


def test_cli_argument_parsing() -> None:
    """Verify that CLI flags parse into appropriate namespace values."""
    args_check = parse_arguments(["--check"])
    assert args_check.check is True
    assert args_check.headless is False
    assert args_check.server is False

    args_headless = parse_arguments(["--headless"])
    assert args_headless.headless is True
    assert args_headless.check is False
    assert args_headless.server is False

    args_server = parse_arguments(["--server"])
    assert args_server.server is True
    assert args_server.check is False
    assert args_server.headless is False

    args_default = parse_arguments([])
    assert args_default.check is False
    assert args_default.headless is False
    assert args_default.server is False


def test_verify_environment_diagnostics() -> None:
    """Verify that environment verification returns all expected diagnostic keys."""
    cfg = load_config()
    diagnostics = verify_environment(cfg)

    assert "app_name" in diagnostics
    assert "app_version" in diagnostics
    assert "environment" in diagnostics
    assert "python_version" in diagnostics
    assert "tkinter_available" in diagnostics
    assert "tkinter_version" in diagnostics
    assert "theme" in diagnostics
    assert diagnostics["app_version"] == "0.1.0"


def test_main_with_check_flag() -> None:
    """Verify main entry-point exits with 0 when given --check flag."""
    exit_code = main(["--check"])
    assert exit_code == 0


def test_main_with_headless_flag() -> None:
    """Verify main entry-point exits with 0 when given --headless flag."""
    exit_code = main(["--headless"])
    assert exit_code == 0


def test_main_runs_desktop_app_when_invoked_interactively() -> None:
    """Verify main executes run_desktop_app when no headless flag is passed."""
    with patch("main.run_desktop_app", return_value=0) as mock_run:
        exit_code = main([])
        assert exit_code == 0
        mock_run.assert_called_once()


def test_main_runs_api_server_when_server_flag_passed() -> None:
    """Verify main executes run_api_server when --server flag is passed."""
    with patch("main.run_api_server", return_value=0) as mock_server:
        exit_code = main(["--server"])
        assert exit_code == 0
        mock_server.assert_called_once()


def test_run_api_server_delegates_to_uvicorn() -> None:
    """Verify run_api_server invokes uvicorn.run with expected parameters."""
    from main import run_api_server
    cfg = load_config()
    with patch("uvicorn.run") as mock_uvicorn:
        exit_code = run_api_server(cfg)
        assert exit_code == 0
        mock_uvicorn.assert_called_once_with(
            "backend.api:app",
            host=cfg.api_host,
            port=cfg.api_port,
            reload=False,
        )

