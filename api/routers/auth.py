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
    backup_codes_remaining,
    confirm_totp_enrollment,
    create_mfa_challenge,
    create_token,
    create_user,
    decode_mfa_challenge,
    delete_user,
    disable_totp,
    get_user,
    is_totp_enabled,
    list_users,
    revoke_token,
    start_totp_enrollment,
    update_user,
    verify_password,
    verify_totp,
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


class LoginResponse(BaseModel):
    """Either a full token (no MFA / MFA passed) or an MFA challenge."""
    access_token: str | None = None
    token_type: str | None = None
    username: str | None = None
    role: str | None = None
    mfa_required: bool = False
    mfa_token: str | None = None


class TotpLoginRequest(BaseModel):
    mfa_token: str
    code: str


class TotpEnableRequest(BaseModel):
    code: str = Field(..., min_length=4, max_length=16)


class TotpDisableRequest(BaseModel):
    password: str


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


@router.post("/login", response_model=LoginResponse, summary="Login (JSON)")
async def login(request: Request, body: LoginRequest):
    """Primary login endpoint. Returns a token, or an MFA challenge if the
    account has TOTP enabled (complete via /auth/login/totp)."""
    _check_login_rate_limit(request)
    user = authenticate(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if is_totp_enabled(user["username"]):
        return LoginResponse(
            mfa_required=True,
            mfa_token=create_mfa_challenge(user["username"]),
        )
    token = create_token(user["username"], user["role"])
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        username=user["username"],
        role=user["role"],
    )


@router.post("/login/totp", response_model=TokenResponse, summary="Complete MFA login")
async def login_totp(request: Request, body: TotpLoginRequest):
    """Second login step: verify the TOTP (or backup) code against the challenge."""
    _check_login_rate_limit(request)
    username = decode_mfa_challenge(body.mfa_token)
    if not username:
        raise HTTPException(status_code=401, detail="MFA session expired — sign in again")
    if not verify_totp(username, body.code):
        raise HTTPException(status_code=401, detail="Invalid authentication code")
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    token = create_token(username, user["role"])
    return TokenResponse(
        access_token=token, token_type="bearer", username=username, role=user["role"],
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
    if is_totp_enabled(user["username"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA is enabled for this account — use the web login (/auth/login).",
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


# ── Self-service: multi-factor authentication (TOTP) ─────────────────────────


def _resolve_username(current_user: dict) -> str:
    """Map the synthetic 'local' user (AUTH_ENABLED=false) to the admin account."""
    from config import settings as _settings

    username = current_user["username"]
    return _settings.ADMIN_USERNAME if username == "local" else username


@router.get("/me/totp", summary="MFA status for the current user")
async def totp_status(current_user: dict = Depends(get_current_user)):
    username = _resolve_username(current_user)
    enabled = is_totp_enabled(username)
    return {"enabled": enabled, "backup_codes_remaining": backup_codes_remaining(username) if enabled else 0}


@router.post("/me/totp/setup", summary="Begin TOTP enrollment (returns QR)")
async def totp_setup(current_user: dict = Depends(get_current_user)):
    """Generate a pending secret + an otpauth URI and a scannable QR PNG."""
    username = _resolve_username(current_user)
    enroll = start_totp_enrollment(username)
    qr_data_uri = _qr_png_data_uri(enroll["otpauth_uri"])
    return {
        "secret": enroll["secret"],
        "otpauth_uri": enroll["otpauth_uri"],
        "qr": qr_data_uri,
    }


@router.post("/me/totp/enable", summary="Confirm + activate TOTP")
async def totp_enable(
    body: TotpEnableRequest,
    current_user: dict = Depends(get_current_user),
):
    username = _resolve_username(current_user)
    codes = confirm_totp_enrollment(username, body.code.strip())
    if codes is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code — make sure your authenticator clock is in sync and try again.",
        )
    return {"detail": "Two-factor authentication enabled", "backup_codes": codes}


@router.post("/me/totp/disable", summary="Disable TOTP (requires password)")
async def totp_disable(
    body: TotpDisableRequest,
    current_user: dict = Depends(get_current_user),
):
    username = _resolve_username(current_user)
    user = get_user(username)
    if not user or not verify_password(body.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is incorrect")
    disable_totp(username)
    return {"detail": "Two-factor authentication disabled"}


def _qr_png_data_uri(payload: str) -> str:
    """Render ``payload`` as a base64 PNG data URI (server-side, no frontend dep)."""
    import base64
    import io

    import qrcode

    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


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
