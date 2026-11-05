"""CyberShield Authentication and User Management Schemas."""

from __future__ import annotations

from typing import Annotated
from pydantic import BaseModel, ConfigDict, Field


class UserRegisterRequest(BaseModel):
    """Payload for registering a new user account."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username: Annotated[str, Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-\.]+$")]
    password: Annotated[str, Field(min_length=8, max_length=128)]
    role: Annotated[str, Field(default="analyst", max_length=20)]


class UserLoginRequest(BaseModel):
    """Payload for user authentication."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username: Annotated[str, Field(min_length=1, max_length=50)]
    password: Annotated[str, Field(min_length=1, max_length=128)]


class UserResponse(BaseModel):
    """Safe public user profile representation (never includes password hashes)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    is_active: bool
    created_at: str


class LoginResponse(BaseModel):
    """Response payload containing authentication session token."""

    token: str
    user: UserResponse
    expires_at: str


class UpdateRoleRequest(BaseModel):
    """Payload for updating a user's access control role."""

    role: Annotated[str, Field(min_length=3, max_length=20)]


class UpdateStatusRequest(BaseModel):
    """Payload for enabling or disabling a user account."""

    is_active: bool


class UserListResponse(BaseModel):
    """Paginated collection of user profiles."""

    items: list[UserResponse]
    total: int

