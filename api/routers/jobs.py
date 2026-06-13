"""Job status endpoints."""

import logging

from auth.dependencies import (
    get_company_filter,
    get_current_user,
    require_case_access,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from services import elasticsearch as es
from services import jobs as job_svc
from services import storage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["jobs"])


def _check_job_case_access(job: dict, current_user: dict) -> None:
    """Enforce the caller's company restriction for a job that has no case_id path
    param. Mirrors require_case_access / cases._check_company_access: 404 if the
    job's case is missing, 403 if it belongs to another company."""
    from services.cases import get_case as _get_case

    job_case_id = job.get("case_id")
    case = _get_case(job_case_id) if job_case_id else None
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    flt = get_company_filter(current_user)
    if flt is not None and case.get("company", "") not in flt:
        raise HTTPException(
            status_code=403,
            detail="Access denied: case belongs to a different company",
        )


@router.get("/jobs/{job_id}")
def get_job(job_id: str):
    """Poll a single job's status and progress."""
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/cases/{case_id}/jobs")
def list_case_jobs(
    case_id: str,
    limit: int = Query(500, ge=1, le=2000),
    page: int = Query(0, ge=0),
    _case: dict = Depends(require_case_access),
):
    """List jobs for a case — paginated to avoid loading all records at once."""
    total = job_svc.count_case_jobs(case_id)
    jobs = job_svc.list_case_jobs(case_id, limit=limit, page=page)
    status_counts = job_svc.status_counts_for_case(case_id)
    return {
        "case_id": case_id,
        "jobs": jobs,
        "total": total,
        "status_counts": status_counts,
        "page": page,
        "limit": limit,
    }


@router.post("/jobs/batch")
def get_jobs_batch(body: dict):
    """
    Return status for up to 500 job IDs in a single request.

    Accepts: {"job_ids": ["id1", "id2", ...]}
    Returns: array of job objects (missing IDs are silently omitted).

    Used by the Ingest UI to replace N individual polling calls with one,
    preventing ERR_INSUFFICIENT_RESOURCES when a ZIP produces hundreds of jobs.
    """
    job_ids = body.get("job_ids", [])[:500]
    results = []
    for jid in job_ids:
        job = job_svc.get_job(jid)
        if job:
            results.append(job)
    return results


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: str):
    """
    Retry a failed ingest job.

    Re-dispatches the Celery task with the original arguments and resets the
    job status to PENDING.  Only jobs whose current status is FAILED can be
    retried.
    """
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("status") not in ("FAILED", "PENDING"):
        raise HTTPException(
            status_code=409,
            detail=f"Only FAILED or PENDING jobs can be retried (current status: {job.get('status')})",
        )

    case_id = job.get("case_id")
    original_filename = job.get("original_filename", "")
    minio_object_key = job.get("minio_object_key", "")
    s3_config_key = job.get("s3_config_key", "")
    s3_source_key = job.get("s3_source_key", "")

    if not case_id:
        raise HTTPException(status_code=422, detail="Job is missing a case_id and cannot be retried")
    # An S3-only job restarts from the transfer phase; a MinIO-backed job needs
    # its object key. Require at least one valid dispatch path.
    if not ((s3_source_key and s3_config_key) or minio_object_key):
        raise HTTPException(
            status_code=422,
            detail="Job has no source object key and cannot be retried",
        )

    # Reset job state in Redis
    job_svc.reset_job_for_retry(job_id)

    # Re-dispatch — S3-originated jobs restart from the transfer phase so
    # the full S3 → MinIO → ingest pipeline runs again (handles partial
    # transfers, overwritten objects, etc.).
    try:
        if s3_source_key and s3_config_key:
            from services.celery_dispatch import dispatch_s3_transfer

            dispatch_s3_transfer(job_id, case_id, s3_config_key, s3_source_key, original_filename)
        else:
            from services.celery_dispatch import dispatch_ingest

            dispatch_ingest(job_id, case_id, minio_object_key, original_filename)
    except Exception as exc:
        logger.exception("Failed to re-dispatch Celery task for job %s", job_id)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to dispatch retry task: {exc}",
        )

    return {
        "job_id": job_id,
        "status": "PENDING",
        "message": "Job has been re-queued for processing",
    }


@router.delete("/jobs/{job_id}")
def delete_job(job_id: str, current_user: dict = Depends(get_current_user)):
    """
    Permanently delete an ingestion job and all its data:
      - Job metadata from Redis (and child job records if this was a ZIP)
      - Source file from MinIO
      - All indexed events from Elasticsearch

    Active jobs (RUNNING, UPLOADING) are rejected — wait for them to finish.
    """
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # IDOR guard: this route has no case_id path param, so enforce the company
    # restriction against the job's own case before any destructive action.
    _check_job_case_access(job, current_user)

    if job.get("status") in ("RUNNING", "UPLOADING"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete an active job (status: {job.get('status')}). Wait for it to finish.",
        )

    case_id = job.get("case_id")

    # Collect this job + any child jobs created from a ZIP expansion.
    # Use a pipeline HGET on just source_zip (one round-trip) to avoid
    # loading the full job hash for every job in a potentially huge case.
    jobs_to_delete = [job]
    if job.get("plugin_used", "").startswith("archive"):
        original_zip = job.get("original_filename", "")
        from config import get_redis as _get_redis

        r = _get_redis()
        child_ids = [cid for cid in job_svc.list_case_job_ids(case_id) if cid != job_id]
        pipe = r.pipeline(transaction=False)
        for cid in child_ids:
            pipe.hget(f"job:{cid}", "source_zip")
        source_zips = pipe.execute()
        matching_ids = [cid for cid, sz in zip(child_ids, source_zips) if sz == original_zip]
        for cid in matching_ids:
            child = job_svc.get_job(cid)
            if child:
                jobs_to_delete.append(child)

    deleted_ids = []
    for j in jobs_to_delete:
        jid = j["job_id"]
        minio_key = j.get("minio_object_key", "")

        # Remove source file from MinIO
        if minio_key:
            try:
                storage.delete_object(minio_key)
            except Exception as exc:
                logger.warning("MinIO delete skipped for %s: %s", minio_key, exc)

        # Remove indexed events from Elasticsearch
        try:
            es._request(
                "POST",
                f"/fo-case-{case_id}-*/_delete_by_query?conflicts=proceed",
                {"query": {"term": {"ingest_job_id": jid}}},
            )
        except Exception as exc:
            logger.warning("ES delete_by_query skipped for job %s: %s", jid, exc)

        job_svc.delete_job(jid, case_id)
        deleted_ids.append(jid)

    logger.info(
        "Deleted job %s and %d child(ren) for case %s", job_id, len(deleted_ids) - 1, case_id
    )
    return {"job_id": job_id, "deleted": True, "children_deleted": len(deleted_ids) - 1}


@router.delete("/cases/{case_id}/jobs")
def delete_all_case_jobs(case_id: str, _case: dict = Depends(require_case_access)):
    """
    Delete all non-active jobs for a case (COMPLETED, FAILED, SKIPPED, PENDING).
    Active jobs (RUNNING, UPLOADING) are skipped.
    Deletes source files from MinIO and indexed events from Elasticsearch.
    """
    all_ids = job_svc.list_case_job_ids(case_id)
    deleted, skipped = [], []

    for jid in all_ids:
        job = job_svc.get_job(jid)
        if not job:
            continue
        if job.get("status") in ("RUNNING", "UPLOADING"):
            skipped.append(jid)
            continue

        minio_key = job.get("minio_object_key", "")
        if minio_key:
            try:
                storage.delete_object(minio_key)
            except Exception as exc:
                logger.warning("MinIO delete skipped for %s: %s", jid, exc)

        try:
            es._request(
                "POST",
                f"/fo-case-{case_id}-*/_delete_by_query?conflicts=proceed",
                {"query": {"term": {"ingest_job_id": jid}}},
            )
        except Exception as exc:
            logger.warning("ES delete_by_query skipped for job %s: %s", jid, exc)

        job_svc.delete_job(jid, case_id)
        deleted.append(jid)

    logger.info(
        "Bulk delete: %d jobs deleted, %d skipped (active) for case %s",
        len(deleted),
        len(skipped),
        case_id,
    )
    return {"deleted": len(deleted), "skipped_active": len(skipped)}
