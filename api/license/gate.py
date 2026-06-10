"""FastAPI feature-gate dependencies.

There is no longer a "hard gate" middleware — the license is always valid
(falls back to Community when the key is absent / expired / invalid).
Premium features are protected per-endpoint via `require_feature(...)`.

To release as open source: keep this code, just don't issue paid keys.
To strip licensing entirely: delete `api/license/` + the LicenseProvider in
the frontend; remove every `Depends(require_feature(...))` reference.
"""

from __future__ import annotations

from fastapi import HTTPException

from .client import get_license
from .models import PLAN_LABELS


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
        import redis_keys as _rk

        from config import get_redis as _get_redis

        n = _get_redis().scard(_rk.COMPANIES_SET) if hasattr(_rk, "COMPANIES_SET") else 0
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
