"""FastAPI auth dependencies — inject into routers via Depends()."""

from __future__ import annotations

import redis_keys as rk
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from auth.service import decode_token, get_user, is_token_revoked
from config import settings

_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)

# Short-TTL identity cache. get_current_user runs on the event loop (async dep)
# yet the revoke-check + user lookup are SYNCHRONOUS Redis round-trips — two per
# protected request. Over Tailscale RTT that blocks the loop and serializes every
# request ("every page slow"). Caching the resolved user by token for a few
# seconds removes both Redis hits for the common case (a client polling many
# endpoints with the same token). Trade-off: a revoked/edited account keeps
# working up to _USER_CACHE_TTL seconds — acceptable for a short window.
_USER_CACHE: dict[str, tuple[float, dict]] = {}
_USER_CACHE_TTL = 15.0
_USER_CACHE_MAX = 2048


def _cache_get(token: str) -> dict | None:
    import time

    hit = _USER_CACHE.get(token)
    if hit and (time.monotonic() - hit[0]) < _USER_CACHE_TTL:
        return hit[1]
    return None


def _cache_put(token: str, user: dict) -> None:
    import time

    if len(_USER_CACHE) > _USER_CACHE_MAX:
        _USER_CACHE.clear()  # cheap bound; entries are short-lived anyway
    _USER_CACHE[token] = (time.monotonic(), user)


async def get_current_user(
    request: Request,
    token: str | None = Depends(_oauth2),
) -> dict:
    """
    Validate the JWT and return the user dict.

    Accepts the token from:
      1. Authorization: Bearer <token>  header  (normal API calls)
      2. ?_token=<token>                query param  (browser downloads — CSV export,
                                                      collector script — where headers
                                                      cannot be set by the browser)

    If AUTH_ENABLED=false the dependency is a no-op and returns a synthetic
    admin user so all existing code keeps working in dev/trusted-LAN mode.
    """
    if not settings.AUTH_ENABLED:
        return {"username": "local", "role": "admin", "companies": []}

    # Fall back to ?_token query param for browser-initiated downloads
    effective_token = token or request.query_params.get("_token")

    if not effective_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    cached = _cache_get(effective_token)
    if cached is not None:
        # Still enforce revocation on a cache hit so logout/revoke takes effect
        # immediately (one cheap Redis EXISTS; the user lookup stays cached).
        try:
            if is_token_revoked(decode_token(effective_token)):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except JWTError:
            pass
        return cached
    try:
        payload = decode_token(effective_token)
        if is_token_revoked(payload):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        username: str | None = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        # Defensive: backfill role for pre-RBAC accounts still in Redis.
        # The startup migration normally handles this; this guard covers edge cases.
        if not user.get("role"):
            try:
                from config import get_redis as _get_redis

                r = _get_redis()
                r.hset(rk.user_key(username), "role", "admin")
                user["role"] = "admin"
            except Exception:
                user["role"] = "admin"  # best-effort in memory
        _cache_put(effective_token, user)
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Only allow users with the 'admin' role."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


async def require_analyst_or_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Allow admin, analyst, developer, and guest roles. Guest write-blocking is handled by middleware."""
    if current_user.get("role") not in ("admin", "analyst", "developer", "guest"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    return current_user


async def require_developer_or_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Allow only admin and developer roles (Studio access)."""
    if current_user.get("role") not in ("admin", "developer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Developer or admin access required",
        )
    return current_user


async def require_analyst_plus(current_user: dict = Depends(get_current_user)) -> dict:
    """Allow admin, analyst, developer — excludes guest."""
    if current_user.get("role") not in ("admin", "analyst", "developer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst access required",
        )
    return current_user


async def require_case_access(
    case_id: str, current_user: dict = Depends(get_current_user)
) -> dict:
    """Load a case and enforce the caller's company restriction. Inject into any
    case-scoped data route (timeline/search/aggregate/events/export/...) so a
    company-restricted analyst cannot read or mutate another company's case.
    Returns the case dict."""
    from services.cases import get_case as _get_case

    case = _get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    flt = get_company_filter(current_user)
    if flt is not None and case.get("company", "") not in flt:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: case belongs to a different company",
        )
    return case


def get_company_filter(user: dict) -> list[str] | None:
    """
    Return the list of companies this user is restricted to, or None (unrestricted).

    Admins are always unrestricted. Analysts with an empty companies list are also
    unrestricted. Only analysts with a non-empty companies list are filtered.
    """
    if user.get("role") == "admin":
        return None
    import json

    companies = user.get("companies", [])
    if isinstance(companies, str):
        try:
            companies = json.loads(companies)
        except (json.JSONDecodeError, TypeError):
            companies = []
    return companies if companies else None
