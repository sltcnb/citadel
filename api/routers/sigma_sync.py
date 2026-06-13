"""Sigma HQ synchronization endpoints."""

from __future__ import annotations

import json

import redis_keys as rk
from auth.dependencies import get_current_user, require_admin
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from services.sigma_settings import get_global_sigma_enabled, set_global_sigma_enabled
from services.sigma_sync import SigmaSyncService

from config import get_redis

router = APIRouter(tags=["sigma-sync"])


class SigmaSettings(BaseModel):
    enabled: bool


@router.get("/sigma/settings")
def get_sigma_settings(current_user: dict = Depends(get_current_user)):
    """Effective global Sigma opt-out state. Readable by any authenticated user
    so the UI can hide Sigma controls when disabled."""
    return {"sigma_enabled": get_global_sigma_enabled()}


@router.put("/sigma/settings")
def update_sigma_settings(body: SigmaSettings, current_user: dict = Depends(require_admin)):
    """Enable/disable Sigma detection rules platform-wide (admin only).

    Disabling stops Sigma rules from running against cases and returns 503 from
    the Sigma sync/parse/import endpoints. Native + custom rules are unaffected.
    Per-case overrides still take precedence over this global default.
    """
    set_global_sigma_enabled(body.enabled)
    return {"sigma_enabled": body.enabled}


class SigmaSyncRequest(BaseModel):
    categories: list[str] | None = None
    tags: list[str] | None = None
    levels: list[str] | None = None


class SigmaSyncResponse(BaseModel):
    imported: int
    skipped: int
    errors: int
    total_rules: int


@router.get("/sigma/status")
def get_sigma_status(current_user: dict = Depends(require_admin)):
    """Get Sigma HQ sync status."""
    service = SigmaSyncService()
    return service.get_sync_status()


@router.post("/sigma/sync", response_model=SigmaSyncResponse)
def sync_sigma_rules(request: SigmaSyncRequest, current_user: dict = Depends(require_admin)):
    """
    Sync rules from Sigma HQ.

    This downloads the latest Sigma rules from GitHub and converts them
    to Elasticsearch queries. May take 2-5 minutes depending on filters.

    Recommended for production:
    - levels: ["critical"] (only critical severity rules)
    - levels: ["high", "critical"] (high and critical)
    """
    if not get_global_sigma_enabled():
        raise HTTPException(status_code=503, detail="Sigma integration is disabled on this instance.")
    service = SigmaSyncService()

    # Default to critical only if no filters specified
    if not request.levels and not request.categories and not request.tags:
        request.levels = ["critical"]

    try:
        result = service.sync_sigma_rules(
            categories=request.categories, tags=request.tags, levels=request.levels
        )
        return SigmaSyncResponse(**result)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")


@router.delete("/sigma/clear")
def clear_sigma_rules(current_user: dict = Depends(require_admin)):
    """Clear all synced Sigma HQ rules."""
    service = SigmaSyncService()
    result = service.clear_sigma_rules()
    return result


@router.get("/sigma/rules")
def list_sigma_rules(skip: int = 0, limit: int = 50, current_user: dict = Depends(require_admin)):
    """List synced Sigma HQ rules."""
    redis_client = get_redis()
    rules = json.loads(redis_client.get(rk.GLOBAL_SIGMA_RULES) or "[]")

    return {"rules": rules[skip : skip + limit], "total": len(rules), "skip": skip, "limit": limit}
