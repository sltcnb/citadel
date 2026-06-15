"""
Platform runtime settings — admin-configurable knobs that used to be env-only
module constants.

Mirrors the Redis-backed admin-config pattern in ``routers/llm_config.py``:
the effective configuration is a Redis-over-default merge stored as a single
JSON document at ``fo:config:platform``. Admins read/write it through
``GET/PUT /admin/platform-config``; other modules read the effective values via
the pure :func:`get_platform_config` resolver so that admin changes actually
take effect at runtime.

No secrets live here, so GET returns the values verbatim (no redaction).

All readers fail open to the env/const defaults on any Redis error — a flaky
Redis must never break auth, ingest, or agent runs.
"""

from __future__ import annotations

import json
import logging

from auth.dependencies import require_admin
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from config import get_redis as _redis
from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["platform"])

_admin_dep = [Depends(require_admin)]

_PLATFORM_CONFIG_KEY = "fo:config:platform"

# Languages offered for default report generation. Keep small + explicit.
LANGUAGE_ALLOWLIST = ("en", "fr", "es", "de", "it", "pt", "nl", "ja", "zh")


def _defaults() -> dict:
    """Default effective config — pulled from the current env/const sources."""
    try:
        jwt_hours = int(settings.JWT_EXPIRE_HOURS)
    except Exception:
        jwt_hours = 8
    return {
        "jwt_expire_hours": jwt_hours,
        "login_rate_limit": 10,
        "login_rate_window_seconds": 60,
        "agent_max_steps": 50,
        "default_report_language": "en",
        "max_upload_gib": 2,
        "session_idle_minutes": 0,  # 0 = disabled (advisory)
    }


def _stored(r) -> dict:
    raw = r.get(_PLATFORM_CONFIG_KEY)
    return json.loads(raw) if raw else {}


def get_platform_config() -> dict:
    """Pure resolver other modules import to read the effective values.

    Returns the Redis-over-default merge. Fails open to the env/const defaults
    on any Redis/parse error so callers never break on a Redis hiccup.
    """
    base = _defaults()
    try:
        stored = _stored(_redis())
    except Exception:
        return base
    # Only let known keys override, and keep the default's type.
    for k, v in (stored or {}).items():
        if k in base:
            base[k] = v
    return base


# ── Pydantic models ─────────────────────────────────────────────────────────


class PlatformConfigIn(BaseModel):
    jwt_expire_hours: int
    login_rate_limit: int
    login_rate_window_seconds: int
    agent_max_steps: int
    default_report_language: str
    max_upload_gib: int
    session_idle_minutes: int


def _validate(body: PlatformConfigIn) -> dict:
    """Validate types/ranges. Raises HTTPException(422) on bad values."""
    errors: list[str] = []

    # Positive ints (>= 1)
    for field in (
        "jwt_expire_hours",
        "login_rate_limit",
        "login_rate_window_seconds",
        "agent_max_steps",
        "max_upload_gib",
    ):
        val = getattr(body, field)
        if not isinstance(val, int) or isinstance(val, bool) or val < 1:
            errors.append(f"{field} must be a positive integer")

    # session_idle_minutes: 0 (disabled) or positive
    if (
        not isinstance(body.session_idle_minutes, int)
        or isinstance(body.session_idle_minutes, bool)
        or body.session_idle_minutes < 0
    ):
        errors.append("session_idle_minutes must be >= 0 (0 disables)")

    lang = (body.default_report_language or "").lower()
    if lang not in LANGUAGE_ALLOWLIST:
        errors.append(
            "default_report_language must be one of: " + ", ".join(LANGUAGE_ALLOWLIST)
        )

    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))

    return {
        "jwt_expire_hours": body.jwt_expire_hours,
        "login_rate_limit": body.login_rate_limit,
        "login_rate_window_seconds": body.login_rate_window_seconds,
        "agent_max_steps": body.agent_max_steps,
        "default_report_language": lang,
        "max_upload_gib": body.max_upload_gib,
        "session_idle_minutes": body.session_idle_minutes,
    }


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get("/admin/platform-config", dependencies=_admin_dep)
def get_platform_config_endpoint():
    """Return the effective platform configuration (Redis-over-default merge)."""
    return get_platform_config()


@router.put("/admin/platform-config", dependencies=_admin_dep)
def update_platform_config(body: PlatformConfigIn):
    """Validate types/ranges and persist the platform configuration."""
    cfg = _validate(body)
    _redis().set(_PLATFORM_CONFIG_KEY, json.dumps(cfg))
    return get_platform_config()
