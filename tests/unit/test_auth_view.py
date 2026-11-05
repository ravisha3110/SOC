"""Unit tests for Authentication Desktop GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock
import pytest

from frontend.auth_view import AuthView
from security.auth import AuthService, Role, Session


def test_auth_view_initialization_and_mode_switching(tk_root) -> None:
    """Verify initialization, mode switching between login and register, and password toggle."""
    mock_auth = MagicMock(spec=AuthService)
    login_mock = MagicMock()
    feedback_mock = MagicMock()

    view = AuthView(
        tk_root,
        auth_service=mock_auth,
        on_login_success=login_mock,
        on_feedback=feedback_mock,
    )

    assert view.mode == "login"
    assert view.btn_submit["text"] == "AUTHENTICATE & ENTER SOC"

    # Toggle password mask
    view._toggle_password_mask()
    assert view.entry_password["show"] == ""
    view._toggle_password_mask()
    assert view.entry_password["show"] == "•"

    # Switch to register mode
    view.switch_mode("register")
    assert view.mode == "register"
    assert view.btn_submit["text"] == "CREATE USER ACCOUNT"

    # Switch back to login mode
    view.switch_mode("login")
    assert view.mode == "login"


def test_auth_view_login_success_and_failure(tk_root) -> None:
    """Verify login submission handling on success and failure."""
    mock_auth = MagicMock(spec=AuthService)
    login_mock = MagicMock()
    feedback_mock = MagicMock()

    view = AuthView(
        tk_root,
        auth_service=mock_auth,
        on_login_success=login_mock,
        on_feedback=feedback_mock,
    )

    # 1. Login Failure
    mock_auth.authenticate_user.return_value = (False, "Invalid username or password.", None)
    view.entry_username.insert(0, "bad_user")
    view.entry_password.insert(0, "bad_pass")
    view._handle_submit()

    assert "Invalid username or password" in view.lbl_alert["text"]
    login_mock.assert_not_called()

    # 2. Login Success
    dummy_session = MagicMock(spec=Session)
    dummy_session.username = "good_user"
    dummy_session.role = Role.ANALYST
    mock_auth.authenticate_user.return_value = (True, "Success", dummy_session)

    view._handle_submit()
    login_mock.assert_called_with(dummy_session)
    feedback_mock.assert_called_with("Welcome good_user (ANALYST)")


def test_auth_view_registration_flow(tk_root) -> None:
    """Verify registration submission and auto-login."""
    mock_auth = MagicMock(spec=AuthService)
    login_mock = MagicMock()

    view = AuthView(
        tk_root,
        auth_service=mock_auth,
        on_login_success=login_mock,
    )
    view.switch_mode("register")

    # 1. Registration Failure
    mock_auth.register_user.return_value = (False, "Password too short", None)
    view.entry_username.insert(0, "new_user")
    view.entry_password.insert(0, "123")
    view._handle_submit()
    assert "Password too short" in view.lbl_alert["text"]

    # 2. Registration Success
    dummy_session = MagicMock(spec=Session)
    mock_auth.register_user.return_value = (True, "Created", {"id": "1", "username": "new_user"})
    mock_auth.authenticate_user.return_value = (True, "Logged in", dummy_session)

    view._handle_submit()
    login_mock.assert_called_with(dummy_session)


def test_auth_view_quick_demo_login(tk_root) -> None:
    """Verify rapid viva demo login shortcuts."""
    mock_auth = MagicMock(spec=AuthService)
    login_mock = MagicMock()
    feedback_mock = MagicMock()

    view = AuthView(
        tk_root,
        auth_service=mock_auth,
        on_login_success=login_mock,
        on_feedback=feedback_mock,
    )

    dummy_session = MagicMock(spec=Session)
    dummy_session.username = "admin_demo"
    dummy_session.role = Role.ADMINISTRATOR
    mock_auth.authenticate_user.return_value = (True, "Logged in", dummy_session)

    view._quick_demo_login("admin_demo", Role.ADMINISTRATOR)
    login_mock.assert_called_with(dummy_session)
    feedback_mock.assert_called_with("Demo login successful as ADMINISTRATOR")


def test_auth_view_demo_logins_disabled_in_production(tk_root) -> None:
    """Verify demo login buttons are omitted when enable_demo_logins is False."""
    mock_auth = MagicMock(spec=AuthService)
    view = AuthView(
        tk_root,
        auth_service=mock_auth,
        on_login_success=MagicMock(),
        enable_demo_logins=False,
    )
    assert view.enable_demo_logins is False
    card_children = [c.cget("text") for c in view.card.winfo_children() if hasattr(c, "cget") and "text" in c.keys()]
    assert not any("QUICK DEMO ROLES" in str(t) for t in card_children)

