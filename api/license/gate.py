"""FastAPI feature-gate dependencies.

There is no longer a "hard gate" middleware — the license is always valid
(falls back to Community when the key is absent / expired / invalid).
Premium features are protected per-endpoint via `require_feature(...)`.

To release as open source: keep this code, just don't issue paid keys.
To strip licensing entirely: delete `api/license/` + the LicenseProvider in
the frontend; remove every `Depends(require_feature(...))` reference.
"""

from __future__ import annotations

import contextlib
import logging
import secrets
import time

from fastapi import HTTPException

from .client import get_license
from .models import PLAN_LABELS

logger = logging.getLogger(__name__)

# ── Limit serialisation ───────────────────────────────────────────────────────
#
# check_*_limit() counts the existing resources and compares against the plan
# cap, then the caller creates the resource. Two concurrent creates therefore
# both counted N, both saw N < cap, and both created — landing at cap+1.
#
# The fix is to make count-check-create one critical section. This is a short
# spin-lock in Redis (same shape as the per-case seal lock in
# services/evidence_seal.py) rather than a database constraint, because the
# counted resources live in Redis, not in a relational table.
_LIMIT_LOCK_KEY = "fo:license:limit:lock"
_LIMIT_LOCK_TTL_MS = 5000

# Take the lock only if free, with a TTL so a crashed holder cannot wedge
# resource creation for the whole installation.
_LOCK_LUA = """
if redis.call('set', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then
  return 1
end
return 0
"""


@contextlib.contextmanager
def limit_lock(name: str = "global"):
    """Serialise a count-check-create sequence across workers.

    Best-effort: if Redis is unreachable the body still runs. Losing the lock
    degrades to the old racy behaviour (one extra resource over the cap), which
    is strictly better than refusing to create anything because Redis blipped.
    """
    key = f"{_LIMIT_LOCK_KEY}:{name}"
    token = secrets.token_hex(8)
    held = False
    r = None
    try:
        from config import get_redis

        r = get_redis()
        script = r.register_script(_LOCK_LUA)
        # ~1s of patience: these are sub-millisecond critical sections.
        for _ in range(100):
            if script(keys=[key], args=[token, _LIMIT_LOCK_TTL_MS]):
                held = True
                break
            time.sleep(0.01)
        if not held:
            logger.warning(
                "Could not acquire the license limit lock (%s) — proceeding "
                "without serialisation; a concurrent create may exceed the cap.",
                key,
            )
    except Exception as exc:  # noqa: BLE001 — never block creation on Redis
        logger.warning("License limit lock unavailable (%s): %s", key, exc)
    try:
        yield
    finally:
        if held and r is not None:
            try:
                if r.get(key) == token:
                    r.delete(key)
            except Exception:  # noqa: BLE001 — the TTL cleans up regardless
                pass


def _upgrade_hint(plan: str) -> str:
    from .models import UPGRADE_PATHS

    upgrade = UPGRADE_PATHS.get(plan)
    if upgrade:
        return f" Upgrade to {PLAN_LABELS[upgrade]} to unlock this feature."
    return ""


def require_feature(feature: str):
    """FastAPI dependency that raises 402 if the feature is not in the active plan."""

    def _check():
        info = get_license()
        if not info.is_feature_enabled(feature):
            hint = _upgrade_hint(info.plan)
            raise HTTPException(
                status_code=402,
                detail=f"Feature '{feature}' is not available on the {info.plan_label} plan.{hint}",
            )

    return _check


def check_case_limit() -> None:
    """Call before creating a case. Raises 402 if the plan's case limit is reached."""
    from services import cases as case_svc

    info = get_license()
    max_cases = info.get_limit("max_cases")
    if max_cases is None:
        return
    active = [c for c in case_svc.list_cases() if c.get("status") != "archived"]
    if len(active) >= max_cases:
        hint = _upgrade_hint(info.plan)
        raise HTTPException(
            status_code=402,
            detail=f"Active case limit ({max_cases}) reached on the {info.plan_label} plan.{hint}",
        )


def check_company_limit() -> None:
    """Refuse to register a new company if the plan caps it."""
    info = get_license()
    max_companies = info.get_limit("max_companies")
    if max_companies is None:
        return
    try:
        import json as _json

        import redis_keys as _rk

        from config import get_redis as _get_redis

        raw = _get_redis().get(_rk.COMPANIES)
        n = len(_json.loads(raw)) if raw else 0
    except Exception:
        n = 0
    if n >= max_companies:
        hint = _upgrade_hint(info.plan)
        raise HTTPException(
            status_code=402,
            detail=f"Company limit ({max_companies}) reached on the {info.plan_label} plan.{hint}",
        )


def check_user_limit() -> None:
    """Call before creating a user. Raises 402 if the plan's seat limit is reached."""
    from auth.service import user_count

    info = get_license()
    max_users = info.get_limit("max_users")
    if max_users is None:
        return
    if user_count() >= max_users:
        hint = _upgrade_hint(info.plan)
        raise HTTPException(
            status_code=402,
            detail=f"User seat limit ({max_users}) reached on the {info.plan_label} plan.{hint}",
        )
