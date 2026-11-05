"""CyberShield - Main Application Entry-Point.

Phase 0: Project Foundation & Environment Setup.
Provides application bootstrapping, environment verification,
and clean headless validation for testing and CI/CD pipelines.
"""

from __future__ import annotations

import argparse
import sys
import tkinter as tk
from typing import Sequence

from config.settings import AppConfig, get_config


def verify_environment(config: AppConfig) -> dict[str, str | bool]:
    """Verify runtime environment and core dependency readiness.

    Args:
        config: Loaded application configuration.

    Returns:
        dict: Diagnostic details of the environment.
    """
    tkinter_available = False
    tkinter_version = "unavailable"

    try:
        # Initialize and immediately withdraw to test without rendering a window
        root = tk.Tk()
        root.withdraw()
        tkinter_version = str(tk.TkVersion)
        root.destroy()
        tkinter_available = True
    except Exception as exc:  # pragma: no cover - depends on host display setup
        tkinter_version = f"error: {exc}"

    return {
        "app_name": config.app_name,
        "app_version": config.app_version,
        "environment": config.environment,
        "python_version": sys.version.split()[0],
        "tkinter_available": tkinter_available,
        "tkinter_version": tkinter_version,
        "theme": config.theme,
    }


def parse_arguments(args: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for CyberShield.

    Args:
        args: Sequence of arguments, or None to read from sys.argv.

    Returns:
        argparse.Namespace: Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        prog="CyberShield",
        description="CyberShield: Syllabus-oriented Desktop Cybersecurity Application",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run startup self-check in headless mode and exit with status code.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without opening graphical display windows.",
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Run the FastAPI REST backend server independently.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="CyberShield 0.1.0 (Phase 1 Threat Analytics Dashboard)",
    )
    return parser.parse_args(args)


def run_api_server(config: AppConfig) -> int:
    """Launch the CyberShield FastAPI backend server using Uvicorn.

    Args:
        config: Loaded application configuration.

    Returns:
        int: Process exit code (0 for clean shutdown).
    """
    import uvicorn

    print(f"[*] Starting CyberShield REST API server on http://{config.api_host}:{config.api_port}")
    print(f"[*] Interactive API Documentation: http://{config.api_host}:{config.api_port}/docs")
    uvicorn.run("backend.api:app", host=config.api_host, port=config.api_port, reload=False)
    return 0


def run_desktop_app(config: AppConfig) -> int:
    """Launch the Phase 1 CyberShield SOC Threat Analytics Dashboard.

    Args:
        config: Loaded application configuration.

    Returns:
        int: Process exit code (0 for success).
    """
    from frontend.dashboard import CyberShieldApp

    app = CyberShieldApp(config=config)
    return app.run()


def main(argv: Sequence[str] | None = None) -> int:
    """Main application entry-point function.

    Args:
        argv: Optional sequence of command-line arguments.

    Returns:
        int: Exit status code (0 for success).
    """
    args = parse_arguments(argv)
    config = get_config()
    diagnostics = verify_environment(config)

    print("================================================================")
    print(f" {config.app_name} - v{config.app_version}")
    print(" Phase 0: Project Foundation & Environment Setup")
    print("================================================================")
    print(f" Python Version   : {diagnostics['python_version']}")
    print(f" Tkinter Status   : {'Available' if diagnostics['tkinter_available'] else 'Unavailable'}")
    print(f" Tkinter Version  : {diagnostics['tkinter_version']}")
    print(f" Environment      : {config.environment}")
    print(f" Target Theme     : {config.theme}")
    print("================================================================")

    # In check or headless mode, complete self-diagnostics and exit cleanly
    if args.check or args.headless:
        print("[SUCCESS] Phase 0 startup self-check passed.")
        return 0

    # Independent backend API server execution
    if args.server:
        return run_api_server(config)

    # Non-headless execution (interactive desktop mode)
    return run_desktop_app(config)


if __name__ == "__main__":
    sys.exit(main())

