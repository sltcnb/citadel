"""Findings router — one API for every analysis output.

Any surface (IOC panel, anomaly scan, MITRE, kill-chain, entity graph, process
tree, a module, the co-pilot, or the analyst by hand) saves its output here as
standardized :class:`citadel_contracts.Finding` records. Once saved they are
uniformly:

  * **queryable**  — they are ``artifact_type:finding`` events in the timeline;
  * **exportable** — the CSV / ``.citadel`` archive already scrolls ``fo-case-*``;
  * **reportable** — the Scribe report pulls a Findings section;
  * **reingestable** — ``POST …/findings/promote`` writes a subset (or all) back
    into the pipeline as a fresh ingest job.

Endpoints (all under ``/api/v1``):
  GET    /cases/{case_id}/findings           list (filter by kind / severity)
  GET    /cases/{case_id}/findings/summary   counts by kind & severity
  POST   /cases/{case_id}/findings           save one or many
  DELETE /cases/{case_id}/findings           delete by id list or kind
  POST   /cases/{case_id}/findings/promote   re-ingest a subset (or all) back in
"""

from __future__ import annotations

import json
import logging
import uuid

from auth.dependencies import require_case_access
from citadel_contracts import Finding
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from services import findings as fnd
from services.cases import get_case

logger = logging.getLogger(__name__)
router = APIRouter(tags=["findings"])


class FindingIn(BaseModel):
    kind: str | None = None  # falls back to the batch kind
    title: str
    severity: str = "informational"
    description: str = ""
    source_feature: str = ""
    timestamp: str | None = None
    timestamp_desc: str = "Finding"
    host: dict = {}
    user: dict = {}
    process: dict = {}
    network: dict = {}
    techniques: list[str] = []
    evidence: list[str] = []
    tags: list[str] = []
    payload: dict = {}
    provenance: dict = {}
    dedup_key: str | None = None


class SaveFindingsIn(BaseModel):
    """Save a batch of findings produced by one feature.

    ``kind`` / ``source_feature`` are batch defaults applied to any item that
    does not set its own. ``replace_kind=True`` makes this batch overwrite the
    case's existing findings of this kind (use for idempotent re-runs of a
    feature, e.g. re-running the IOC extraction).
    """

    kind: str
    source_feature: str = ""
    replace_kind: bool = False
    items: list[FindingIn]


class PromoteIn(BaseModel):
    finding_ids: list[str] | None = None  # subset; None + kind → whole kind
    kind: str | None = None
    filename: str | None = None


class DeleteIn(BaseModel):
    finding_ids: list[str] | None = None
    kind: str | None = None


@router.get("/cases/{case_id}/findings")
def list_case_findings(
    case_id: str,
    _acl: dict = Depends(require_case_access),
    kind: str | None = Query(None),
    severity: str | None = Query(None),
    size: int = Query(500, le=2000),
):
    return fnd.list_findings(case_id, kind=kind, severity=severity, size=size)


@router.get("/cases/{case_id}/findings/summary")
def findings_summary(case_id: str, _acl: dict = Depends(require_case_access)):
    return fnd.findings_summary(case_id)


@router.post("/cases/{case_id}/findings")
def save_findings(
    case_id: str, body: SaveFindingsIn, _acl: dict = Depends(require_case_access)
):
    """Persist a batch of findings into the unified store."""
    findings: list[Finding] = []
    for item in body.items:
        findings.append(
            Finding(
                kind=item.kind or body.kind,
                title=item.title,
                severity=item.severity,
                description=item.description,
                source_feature=item.source_feature or body.source_feature or body.kind,
                timestamp=item.timestamp,
                timestamp_desc=item.timestamp_desc,
                host=item.host,
                user=item.user,
                process=item.process,
                network=item.network,
                techniques=item.techniques,
                evidence=item.evidence,
                tags=item.tags,
                payload=item.payload,
                provenance=item.provenance,
                dedup_key=item.dedup_key,
            )
        )
    res = fnd.index_findings(
        case_id, findings, replace_kind=body.kind if body.replace_kind else None
    )
    if res.get("error") and not res.get("indexed"):
        raise HTTPException(status_code=500, detail=f"Save failed: {res['error']}")
    return {"saved": res["indexed"], "failed": res["failed"], "kind": body.kind}


@router.delete("/cases/{case_id}/findings")
def delete_case_findings(
    case_id: str, body: DeleteIn, _acl: dict = Depends(require_case_access)
):
    deleted = fnd.delete_findings(case_id, finding_ids=body.finding_ids, kind=body.kind)
    return {"deleted": deleted}


@router.post("/cases/{case_id}/findings/promote")
def promote_findings(
    case_id: str, body: PromoteIn, _acl: dict = Depends(require_case_access)
):
    """Re-ingest a subset (or a whole kind) of findings back into the pipeline.

    The selected finding documents are written as a JSONL artifact to MinIO and
    dispatched as a normal ingest job — reusing the exact machinery that
    re-ingests module artifacts. "Part or total" is just which ids you pass.
    """
    from services import jobs as job_svc
    from services import storage
    from services.celery_dispatch import dispatch_ingest

    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    listing = fnd.list_findings(case_id, kind=body.kind, size=2000)
    rows = listing.get("findings", [])
    if body.finding_ids:
        wanted = set(body.finding_ids)
        rows = [r for r in rows if r.get("finding_id") in wanted or r.get("_id") in wanted]
    if not rows:
        raise HTTPException(status_code=400, detail="No matching findings to re-ingest")

    # Strip ES bookkeeping; ship the raw finding docs as JSONL.
    payload = "\n".join(
        json.dumps({k: v for k, v in r.items() if k != "_id"}) for r in rows
    ).encode("utf-8")

    job_id = uuid.uuid4().hex
    filename = body.filename or f"findings-{body.kind or 'selection'}-{job_id[:8]}.jsonl"
    minio_key = f"cases/{case_id}/findings/{job_id}/{filename}"

    import io

    try:
        storage.upload_fileobj(minio_key, io.BytesIO(payload), len(payload))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not stage findings: {exc}") from exc

    job_svc.create_job(job_id, case_id, filename, "")
    job_svc.update_job(job_id, minio_object_key=minio_key, status="PENDING")
    try:
        dispatch_ingest(job_id, case_id, minio_key, filename)
    except Exception as exc:
        job_svc.update_job(job_id, status="FAILED", error=str(exc))
        raise HTTPException(
            status_code=500, detail=f"Failed to dispatch re-ingest: {exc}"
        ) from exc

    return {"job_id": job_id, "filename": filename, "count": len(rows), "status": "PENDING"}
