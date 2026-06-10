"""License info + install endpoints."""

from __future__ import annotations

import logging

import jwt
from auth.dependencies import get_current_user, require_admin
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .client import _client, invalidate_license_cache

logger = logging.getLogger(__name__)

router = APIRouter(tags=["license"])


class LicenseInstallBody(BaseModel):
    key: str = Field(..., min_length=10, description="Signed JWT license key")
    signing_key: str | None = Field(
        None, description="Optional HS256 secret. If omitted, current signing key is reused."
    )


@router.get("/license/info")
def license_info(_: dict = Depends(get_current_user)):
    """Return the active license — plan, features, expiry, label.

    No secrets — neither the JWT nor the signing key ever leave the server.
    """
    return _client.info


@router.post("/license/refresh", dependencies=[Depends(require_admin)])
def refresh_license():
    """Force re-validation of the current key (admin only)."""
    invalidate_license_cache()
    return _client.info


@router.post("/license/install", dependencies=[Depends(require_admin)])
def install_license(body: LicenseInstallBody):
    """Validate + persist a license key. Admin only.

    Verification happens before the file is written; a bad key never replaces
    the running one. The key is stored under CITADEL_LICENSE_FILE (default
    /app/uploads/.citadel-license.json) so it survives pod restarts."""
    try:
        info = _client.set_license(body.key, body.signing_key)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="License key has expired.")
    except jwt.InvalidSignatureError:
        raise HTTPException(status_code=400, detail="Signature mismatch — wrong signing key.")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JWT: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    logger.info("License installed via API — plan=%s org=%s", info.plan, info.org_name)
    return _client.info


@router.delete("/license/install", dependencies=[Depends(require_admin)])
def uninstall_license():
    """Remove any installed key file — revert to env / community. Admin only."""
    _client.clear_license()
    logger.info("License override cleared via API — reverted to env/community.")
    return _client.info
