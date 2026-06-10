"""Authentication router — login + token + current user + admin management."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

import redis_keys as rk
from auth.dependencies import get_current_user, require_admin
from auth.service import (
    authenticate,
    create_token,
    create_user,
    delete_user,
    get_user,
    list_users,
    revoke_token,
    update_user,
    verify_password,
)
from license.gate import check_user_limit

from config import get_redis as _get_redis


def _check_login_rate_limit(request: Request) -> None:
    """Block IPs that exceed 10 login attempts per 60 seconds."""
    client_ip = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown"
    )
    key = rk.login_ratelimit(client_ip)
    try:
        redis = _get_redis()
        count = redis.incr(key)
        if count == 1:
            redis.expire(key, 60)
        if count > 10:
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Try again in a minute.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Rate-limit check failed (Redis unavailable?): %s", exc)


router = APIRouter(prefix="/auth", tags=["auth"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str


class UserInfo(BaseModel):
    username: str
    role: str


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    role: str = Field("analyst", description="User role: admin, analyst, developer, or guest")
    companies: list[str] = Field(
        default_factory=list, description="Companies this user can access (empty = all)"
    )


class UpdateUserRequest(BaseModel):
    role: str | None = Field(None, description="New role: admin, analyst, developer, or guest")
    password: str | None = Field(None, min_length=8, description="New password (min 8 chars)")
    companies: list[str] | None = Field(
        None, description="Companies this user can access (empty list = all)"
    )


class UpdateCompaniesRequest(BaseModel):
    companies: list[str] = Field(
        default_factory=list, description="Companies this user can access (empty = all)"
    )


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/login", response_model=TokenResponse, summary="Login (JSON)")
async def login(request: Request, body: LoginRequest):
    """Primary login endpoint used by the frontend."""
    _check_login_rate_limit(request)
    user = authenticate(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_token(user["username"], user["role"])
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        username=user["username"],
        role=user["role"],
    )


@router.post("/token", response_model=TokenResponse, summary="Login (OAuth2 form)")
async def token(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    """OAuth2-compatible endpoint for tooling (Swagger UI, curl, etc.)."""
    _check_login_rate_limit(request)
    user = authenticate(form.username, form.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    tok = create_token(user["username"], user["role"])
    return TokenResponse(
        access_token=tok,
        token_type="bearer",
        username=user["username"],
        role=user["role"],
    )


@router.post("/logout", summary="Revoke current token")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Revoke the calling token. The token becomes invalid immediately."""
    auth_header = request.headers.get("Authorization", "")
    token_str = (
        auth_header[7:]
        if auth_header.startswith("Bearer ")
        else request.query_params.get("_token", "")
    )
    if token_str:
        revoke_token(token_str)
    return {"detail": "Logged out successfully"}


@router.get("/me", response_model=UserInfo, summary="Current user info")
async def me(current_user: dict = Depends(get_current_user)):
    return UserInfo(username=current_user["username"], role=current_user["role"])


# ── Self-service: change own password ────────────────────────────────────────


@router.put("/me/password", summary="Change own password")
async def change_own_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    """Any authenticated user can change their own password."""
    from config import settings as _settings

    username = current_user["username"]
    # When AUTH_ENABLED=False the synthetic "local" user maps to the configured admin
    if username == "local":
        username = _settings.ADMIN_USERNAME
    user = get_user(username)
    if not user or not verify_password(body.old_password, user.get("hashed_password", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    update_user(username, password=body.new_password)
    return {"detail": "Password updated successfully"}


# ── Admin: user management ───────────────────────────────────────────────────


@router.get("/users", summary="List all users (admin only)")
async def admin_list_users(admin: dict = Depends(require_admin)):
    """Return all users with their roles."""
    return {"users": list_users()}


@router.post(
    "/users",
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user (admin only)",
)
async def admin_create_user(
    body: CreateUserRequest,
    admin: dict = Depends(require_admin),
):
    check_user_limit()
    try:
        user = create_user(body.username, body.password, body.role, body.companies)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    return user


@router.put("/users/{username}", summary="Update a user (admin only)")
async def admin_update_user(
    username: str,
    body: UpdateUserRequest,
    admin: dict = Depends(require_admin),
):
    """Update a user's role and/or reset their password."""
    if body.role is None and body.password is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nothing to update — provide 'role' and/or 'password'",
        )
    try:
        user = update_user(
            username, role=body.role, password=body.password, companies=body.companies
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    return user


@router.put(
    "/users/{username}/companies", summary="Set company restrictions for a user (admin only)"
)
async def admin_set_user_companies(
    username: str,
    body: UpdateCompaniesRequest,
    admin: dict = Depends(require_admin),
):
    """Set which companies a user can access. Empty list = unrestricted."""
    try:
        user = update_user(username, companies=body.companies)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return user


@router.delete("/users/{username}", summary="Delete a user (admin only)")
async def admin_delete_user(
    username: str,
    admin: dict = Depends(require_admin),
):
    """Delete a user. Admins cannot delete themselves."""
    if username == admin["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    if not delete_user(username):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )
    return {"detail": f"User '{username}' deleted"}
