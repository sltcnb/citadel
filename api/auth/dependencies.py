"""FastAPI auth dependencies — inject into routers via Depends()."""

from __future__ import annotations

import redis_keys as rk
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from auth import rbac
from auth.service import decode_token, get_user, groups_index, is_token_revoked
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


# ── Effective permission/company resolution ─────────────────────────────────────


def _as_list(value) -> list[str]:
    """Coerce a raw hash field (JSON string or list) into a list of strings."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        try:
            import json as _json

            parsed = _json.loads(value)
            return [str(v) for v in parsed] if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            return []
    return []


def resolve_effective(user: dict) -> dict:
    """Resolve and cache the user's effective permissions + company scope onto the
    user dict (idempotent). Reads the groups index from Redis once; cheap enough
    for per-request use and memoized via the ``_effective_perms`` marker key.

    Returns the same user dict (mutated in place) for convenience.
    """
    if user.get("_effective_perms") is not None:
        return user
    # Normalize the raw hash fields into real lists so the pure rbac functions
    # (which expect lists) work whether the dict came from get_user (JSON strings)
    # or from _public (already parsed).
    norm = dict(user)
    norm["groups"] = _as_list(user.get("groups"))
    norm["companies"] = _as_list(user.get("companies"))
    norm["extra_permissions"] = _as_list(user.get("extra_permissions"))
    try:
        gidx = groups_index()
    except Exception:
        gidx = {}
    user["_effective_perms"] = rbac.effective_permissions(norm, gidx)
    user["_effective_companies"] = rbac.effective_companies(norm, gidx)
    return user


def has_permission(user: dict, perm: str) -> bool:
    """True if the user holds ``perm`` (admins always pass)."""
    if user.get("role") == "admin":
        return True
    return perm in resolve_effective(user)["_effective_perms"]


def require_permission(perm: str):
    """Dependency factory: 403 unless the current user has ``perm``. Admins pass.

    Usage:  Depends(require_permission("cases.write"))
    """

    async def _dep(current_user: dict = Depends(get_current_user)) -> dict:
        if not has_permission(current_user, perm):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {perm}",
            )
        return current_user

    return _dep


async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Only allow users with the 'admin' role (or the settings.admin permission)."""
    if current_user.get("role") != "admin" and not has_permission(
        current_user, rbac.SETTINGS_ADMIN
    ):
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


def require_case_access(
    case_id: str, current_user: dict = Depends(get_current_user)
) -> dict:
    """Load a case and enforce the caller's company restriction. Inject into any
    case-scoped data route (timeline/search/aggregate/events/export/...) so a
    company-restricted analyst cannot read or mutate another company's case.
    Returns the case dict.

    SYNC on purpose: it does a blocking Redis read (get_case). As an `async def`
    it ran on the event loop and — on the heavily-polled timeline/search routes —
    starved the loop until even /health timed out and the pod was SIGKILLed
    (CrashLoop). As a plain `def`, FastAPI runs it in the threadpool, off-loop."""
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

    Now group-aware: the scope is the UNION of the user's own companies and the
    company scopes of every group they belong to (via rbac.effective_companies).
    Admins (and anyone with no scope anywhere) are unrestricted (None).
    """
    if user.get("role") == "admin":
        return None
    return resolve_effective(user)["_effective_companies"]
