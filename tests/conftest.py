"""Pytest configuration and environment fixtures for CyberShield test suite."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tkinter as tk
import bcrypt
import pytest

# Ensure TCL_LIBRARY and TK_LIBRARY point to base Python installation on Windows
base_tcl = Path(sys.base_prefix) / "tcl" / "tcl8.6"
base_tk = Path(sys.base_prefix) / "tcl" / "tk8.6"

if base_tcl.is_dir() and "TCL_LIBRARY" not in os.environ:
    os.environ["TCL_LIBRARY"] = str(base_tcl)

if base_tk.is_dir() and "TK_LIBRARY" not in os.environ:
    os.environ["TK_LIBRARY"] = str(base_tk)


@pytest.fixture(scope="session")
def session_tk_root():
    """Create a single shared root Tkinter instance for the entire test session.

    Prevents Tcl interpreter corruption caused by repeated Tk() creation and
    destruction in a single process.
    """
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


@pytest.fixture
def tk_root(session_tk_root):
    """Provide a clean, isolated Toplevel window for individual tests."""
    window = tk.Toplevel(session_tk_root)
    window.withdraw()
    yield window
    try:
        window.destroy()
    except Exception:
        pass
