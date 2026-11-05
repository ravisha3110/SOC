"""Authentication, Session Management, and RBAC API Endpoints."""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from backend.dependencies import (
    get_auth_service,
    get_current_session,
    require_role,
)
from backend.schemas.auth import (
    LoginResponse,
    UpdateRoleRequest,
    UpdateStatusRequest,
    UserListResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from security.auth import AuthService, Role, Session

router = APIRouter(prefix="/api/auth", tags=["Authentication & Access Control"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new SOC analyst user",
)
def register(
    payload: UserRegisterRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserResponse:
    """Register a new user account with secure password hashing."""
    success, message, created_user = auth_service.register_user(
        username=payload.username,
        password=payload.password,
        role=payload.role,
    )
    if not success or not created_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return UserResponse(
        id=created_user["id"],
        username=created_user["username"],
        role=created_user["role"],
        is_active=bool(created_user.get("is_active", 1)),
        created_at=created_user["created_at"],
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and obtain session token",
)
def login(
    payload: UserLoginRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    """Verify credentials and issue an active session token."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    success, message, session = auth_service.authenticate_user(
        username=payload.username,
        password=payload.password,
        ip_address=client_ip,
    )
    if not success or not session:
        # Check if error is due to lockout (HTTP 429) vs invalid credentials (HTTP 401)
        if "locked" in message.lower():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=message,
        )

    return LoginResponse(
        token=session.token,
        user=UserResponse(
            id=session.user_id,
            username=session.username,
            role=session.role.value,
            is_active=True,
            created_at=session.created_at.isoformat(),
        ),
        expires_at=session.expires_at.isoformat(),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke current user session",
)
def logout(
    current_session: Annotated[Session, Depends(get_current_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict[str, str]:
    """Revoke active session token."""
    auth_service.logout_user(current_session.token)
    return {"message": "Session successfully revoked."}


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get currently authenticated user context",
)
def get_current_user_profile(
    current_session: Annotated[Session, Depends(get_current_session)],
) -> UserResponse:
    """Return the profile and role of the currently authenticated session."""
    return UserResponse(
        id=current_session.user_id,
        username=current_session.username,
        role=current_session.role.value,
        is_active=True,
        created_at=current_session.created_at.isoformat(),
    )


# -----------------------------------------------------------------------------
# Administrator Management Endpoints
# -----------------------------------------------------------------------------

@router.get(
    "/users",
    response_model=UserListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all user accounts (Administrator only)",
)
def list_users(
    admin_session: Annotated[Session, Depends(require_role([Role.ADMINISTRATOR]))],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserListResponse:
    """Retrieve all user accounts without exposing credential hashes."""
    users = auth_service.list_users(admin_session)
    items = [UserResponse(**u) for u in users]
    return UserListResponse(items=items, total=len(items))


@router.patch(
    "/users/{user_id}/role",
    status_code=status.HTTP_200_OK,
    summary="Update user role (Administrator only)",
)
def update_user_role(
    user_id: str,
    payload: UpdateRoleRequest,
    admin_session: Annotated[Session, Depends(require_role([Role.ADMINISTRATOR]))],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict[str, str]:
    """Modify role assignment for an existing user account."""
    success, message = auth_service.update_user_role(user_id, payload.role, admin_session)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return {"message": message}


@router.patch(
    "/users/{user_id}/status",
    status_code=status.HTTP_200_OK,
    summary="Enable or disable user account (Administrator only)",
)
def update_user_status(
    user_id: str,
    payload: UpdateStatusRequest,
    admin_session: Annotated[Session, Depends(require_role([Role.ADMINISTRATOR]))],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict[str, str]:
    """Activate or deactivate a user account."""
    success, message = auth_service.set_user_active_status(user_id, payload.is_active, admin_session)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return {"message": message}


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete user account (Administrator only)",
)
def delete_user(
    user_id: str,
    admin_session: Annotated[Session, Depends(require_role([Role.ADMINISTRATOR]))],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> dict[str, str]:
    """Delete a user account."""
    success, message = auth_service.delete_user(user_id, admin_session)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return {"message": message}

