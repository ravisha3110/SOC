"""Unit tests for User Management Desktop GUI View."""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock
import pytest

from frontend.user_management_view import UserManagementView
from security.auth import AuthService, Role, Session


def test_user_management_view_initialization_and_selection(tk_root) -> None:
    """Verify initialization, table population, and row selection."""
    mock_auth = MagicMock(spec=AuthService)
    mock_auth.list_users.return_value = [
        {"id": "u-1", "username": "alice", "role": "analyst", "is_active": 1, "created_at": "2026-11-05T00:00:00Z"},
        {"id": "u-2", "username": "bob", "role": "viewer", "is_active": 0, "created_at": "2026-11-05T00:00:00Z"},
    ]
    admin_session = MagicMock(spec=Session)
    admin_session.role = Role.ADMINISTRATOR
    feedback_mock = MagicMock()

    view = UserManagementView(
        tk_root,
        auth_service=mock_auth,
        current_session=admin_session,
        on_feedback=feedback_mock,
    )

    children = view.tree.get_children()
    assert len(children) == 2
    feedback_mock.assert_called_with("User management loaded 2 registered accounts.")

    # Select first user (Active)
    view.tree.selection_set(children[0])
    view._on_user_selected(None)
    assert "Selected User: alice" in view.lbl_selected_user["text"]
    assert "Deactivate 'alice'" in view.btn_toggle_status["text"]

    # Select second user (Disabled)
    view.tree.selection_set(children[1])
    view._on_user_selected(None)
    assert "Activate 'bob'" in view.btn_toggle_status["text"]


def test_user_management_view_actions(tk_root) -> None:
    """Verify role change, status toggle, delete, and user creation actions."""
    mock_auth = MagicMock(spec=AuthService)
    mock_auth.list_users.return_value = [
        {"id": "u-target", "username": "charlie", "role": "viewer", "is_active": 1, "created_at": "2026-11-05T00:00:00Z"},
    ]
    admin_session = MagicMock(spec=Session)
    feedback_mock = MagicMock()

    view = UserManagementView(
        tk_root,
        auth_service=mock_auth,
        current_session=admin_session,
        on_feedback=feedback_mock,
    )

    children = view.tree.get_children()
    view.tree.selection_set(children[0])

    # 1. Change Role
    mock_auth.update_user_role.return_value = (True, "User role updated to administrator.")
    view.target_role_var.set("administrator")
    view._handle_change_role()
    mock_auth.update_user_role.assert_called_with("u-target", "administrator", admin_session)

    # 2. Toggle Status
    mock_auth.set_user_active_status.return_value = (True, "User account successfully deactivated.")
    view._handle_toggle_status()
    mock_auth.set_user_active_status.assert_called_with("u-target", False, admin_session)

    # 3. Delete User
    mock_auth.delete_user.return_value = (True, "User deleted successfully.")
    view._handle_delete_user()
    mock_auth.delete_user.assert_called_with("u-target", admin_session)

    # 4. Create User
    mock_auth.register_user.return_value = (True, "User registered successfully.", {"id": "new-1"})
    view.entry_new_user.delete(0, tk.END)
    view.entry_new_user.insert(0, "new_member")
    view.entry_new_pass.delete(0, tk.END)
    view.entry_new_pass.insert(0, "TempPass2026!")
    view.new_user_role_var.set("analyst")
    view._handle_create_user()
    mock_auth.register_user.assert_called_with("new_member", "TempPass2026!", role="analyst")


def test_user_management_view_actions_without_selection(tk_root) -> None:
    """Verify action handlers handle unselected states gracefully."""
    mock_auth = MagicMock(spec=AuthService)
    mock_auth.list_users.return_value = []
    admin_session = MagicMock(spec=Session)
    feedback_mock = MagicMock()

    view = UserManagementView(
        tk_root,
        auth_service=mock_auth,
        current_session=admin_session,
        on_feedback=feedback_mock,
    )

    # Call actions without selecting any row
    view._on_user_selected(None)
    view._handle_change_role()
    feedback_mock.assert_called_with("Please select a user from the table first.")

    view._handle_toggle_status()
    feedback_mock.assert_called_with("Please select a user from the table first.")

    view._handle_delete_user()
    feedback_mock.assert_called_with("Please select a user from the table first.")

