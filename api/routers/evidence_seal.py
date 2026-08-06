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

import services.evidence_seal as seal_svc
import services.jobs as jobs_svc
from auth.dependencies import get_current_user, require_case_access
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(tags=["evidence"])


class SealRequest(BaseModel):
    artifact_id: str = Field(..., min_length=1, description="Stable id of the artifact (e.g. job_id)")
    sha256: str = Field(
        ...,
        pattern=r"^[0-9a-fA-F]{64}$",
        description="SHA-256 of the artifact bytes (64 hex chars)",
    )
    meta: dict | None = Field(default=None, description="Optional descriptive metadata")


@router.post("/cases/{case_id}/evidence/seal")
def create_seal(
    case_id: str,
    body: SealRequest,
    case: dict = Depends(require_case_access),
    user: dict = Depends(get_current_user),
):
    """Record an immutable, hash-chained evidence seal for an artifact."""
    # Cross-check: when artifact_id is an ingest job of this case, the pipeline
    # recorded the true sha256 at ingest (routers/ingest.py sets job.sha256) —
    # a disagreeing client-supplied hash is a typo that would be sealed
    # permanently, so reject it. Non-job artifacts keep the explicit-hash flow
    # (there is no server-side record to compare against).
    try:
        job = jobs_svc.get_job(body.artifact_id)
    except Exception:  # noqa: BLE001 - don't block sealing when Redis is down
        logger.warning("Job hash cross-check unavailable for %s", body.artifact_id, exc_info=True)
        job = None
    if job and job.get("case_id") == case_id:
        recorded = (job.get("sha256") or "").strip().lower()
        if recorded and recorded != body.sha256.lower():
            raise HTTPException(
                status_code=422,
                detail=(
                    "sha256 does not match the hash recorded at ingest for job "
                    f"{body.artifact_id} ({recorded}) — refusing to seal a mismatched hash."
                ),
            )
    sealed_by = (user or {}).get("username") or (case or {}).get("analyst", "")
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
