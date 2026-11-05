"""Unit tests for validating project package imports and dependencies."""

import importlib
import pytest


@pytest.mark.parametrize(
    "module_name",
    [
        "config",
        "config.settings",
        "frontend",
        "backend",
        "backend.api",
        "backend.dependencies",
        "backend.routes",
        "backend.schemas",
        "backend.services",
        "database",
        "models",
        "controllers",
        "security",
        "main",
    ],
)
def test_internal_module_imports(module_name: str) -> None:
    """Verify that all core internal packages and modules import successfully."""
    module = importlib.import_module(module_name)
    assert module is not None


@pytest.mark.parametrize(
    "external_package",
    [
        "fastapi",
        "uvicorn",
        "pydantic",
        "dotenv",
        "psycopg",
    ],
)
def test_external_dependency_imports(external_package: str) -> None:
    """Verify that core third-party dependencies are installed and importable."""
    module = importlib.import_module(external_package)
    assert module is not None


def test_tkinter_import() -> None:
    """Verify that Tkinter standard library module is available for desktop GUI."""
    import tkinter as tk
    from tkinter import ttk

    assert tk.TkVersion >= 8.0
    assert ttk is not None

