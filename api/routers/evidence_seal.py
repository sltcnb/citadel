"""Court-ready signed evidence chain — HTTP surface.

Exposes the per-case, hash-chained evidence custody log built in
``services/evidence_seal.py``:

    POST /cases/{case_id}/evidence/seal     — seal an artifact (append to chain)
    GET  /cases/{case_id}/evidence/seals    — list seals + verification summary
    GET  /cases/{case_id}/evidence/verify   — recompute + report chain integrity
    GET  /cases/{case_id}/evidence/manifest — court-ready signed custody manifest

All routes require case access. Follows conventions in ``routers/anomaly.py``.
"""

from __future__ import annotations

import logging

from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

import services.evidence_seal as seal_svc

logger = logging.getLogger(__name__)
router = APIRouter(tags=["evidence"])


class SealRequest(BaseModel):
    artifact_id: str = Field(..., min_length=1, description="Stable id of the artifact (e.g. job_id)")
    sha256: str = Field(..., min_length=1, description="SHA-256 of the artifact bytes")
    meta: dict | None = Field(default=None, description="Optional descriptive metadata")


@router.post("/cases/{case_id}/evidence/seal")
def create_seal(
    case_id: str,
    body: SealRequest,
    case: dict = Depends(require_case_access),
):
    """Record an immutable, hash-chained evidence seal for an artifact."""
    sealed_by = (case or {}).get("username", "") if isinstance(case, dict) else ""
    record = seal_svc.seal_artifact(
        case_id=case_id,
        artifact_id=body.artifact_id,
        sha256=body.sha256,
        meta=body.meta,
        sealed_by=sealed_by,
    )
    return {"sealed": True, "seal": record}


@router.get("/cases/{case_id}/evidence/seals")
def get_seals(case_id: str, _case: dict = Depends(require_case_access)):
    """List the per-case seal chain (newest-first) with a verification summary."""
    seals = seal_svc.list_seals(case_id)
    verify = seal_svc.verify_seals(case_id)
    return {"seals": seals, "count": len(seals), "verify": verify}


@router.get("/cases/{case_id}/evidence/verify")
def verify(case_id: str, _case: dict = Depends(require_case_access)):
    """Recompute the chain and report whether it is intact."""
    return seal_svc.verify_seals(case_id)


@router.get("/cases/{case_id}/evidence/manifest")
def manifest(case_id: str, _case: dict = Depends(require_case_access)):
    """Return the court-ready, (optionally HMAC-signed) custody manifest."""
    return seal_svc.custody_manifest(case_id)
