"""Job state management in Redis."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

from config import get_redis

logger = logging.getLogger(__name__)
JOB_TTL = 604800  # 7 days


def create_job(
    job_id: str,
    case_id: str,
    filename: str,
    minio_key: str,
    source_zip: str = "",
    keep_raw: bool = False,
    plugin_hint: str = "",
) -> dict:
    r = get_redis()
    job = {
        "job_id": job_id,
        "case_id": case_id,
        "status": "PENDING",
        "original_filename": filename,
        "minio_object_key": minio_key,
        "events_indexed": "0",
        "events_failed": "0",
        "error": "",
        "plugin_used": "",
        "plugin_stats": "{}",
        "created_at": datetime.now(UTC).isoformat(),
        "started_at": "",
        "completed_at": "",
        "task_id": "",
        "source_zip": source_zip,
        "keep_raw": "1" if keep_raw else "0",
        "plugin_hint": plugin_hint,
    }
    r.hset(f"job:{job_id}", mapping=job)
    r.expire(f"job:{job_id}", JOB_TTL)

    # Add to case job set (unordered, kept for backward compat)
    r.sadd(f"case:{case_id}:jobs", job_id)
    r.expire(f"case:{case_id}:jobs", JOB_TTL)
    # Add to sorted set (score = creation timestamp) for O(log N) recent lookups
    r.zadd(f"case:{case_id}:jobs:zs", {job_id: time.time()})
    r.expire(f"case:{case_id}:jobs:zs", JOB_TTL)
    return job


def get_job(job_id: str) -> dict | None:
    r = get_redis()
    data = r.hgetall(f"job:{job_id}")
    if not data:
        return None
    # Deserialize JSON fields
    for field in ("plugin_stats",):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except (json.JSONDecodeError, TypeError):
                data[field] = {}
    for field in ("events_indexed", "events_failed"):
        if field in data:
            try:
                data[field] = int(data[field])
            except (ValueError, TypeError):
                data[field] = 0
    return data


def update_job(job_id: str, **fields) -> None:
    """Patch arbitrary fields on an existing job hash."""
    r = get_redis()
    key = f"job:{job_id}"
    r.hset(key, mapping={k: str(v) for k, v in fields.items()})
    r.expire(key, JOB_TTL)


def reset_job_for_retry(job_id: str, plugin_hint: str | None = None) -> None:
    """Reset a FAILED/SKIPPED job back to PENDING so it can be re-dispatched."""
    r = get_redis()
    key = f"job:{job_id}"
    fields: dict[str, str] = {
        "status": "PENDING",
        "error": "",
        "events_indexed": "0",
        "plugin_used": "",
        "plugin_stats": "{}",
        "started_at": "",
        "completed_at": "",
        "task_id": "",
    }
    if plugin_hint is not None:
        fields["plugin_hint"] = plugin_hint
    r.hset(key, mapping=fields)
    r.expire(key, JOB_TTL)


def delete_job(job_id: str, case_id: str) -> None:
    """Remove a job record from Redis and from the case's job set."""
    r = get_redis()
    r.delete(f"job:{job_id}")
    r.srem(f"case:{case_id}:jobs", job_id)
    r.zrem(f"case:{case_id}:jobs:zs", job_id)


def count_case_jobs(case_id: str) -> int:
    """Return total job count for a case without loading job data."""
    return get_redis().scard(f"case:{case_id}:jobs")


def status_counts_for_case(case_id: str) -> dict[str, int]:
    """Tally jobs per status using a single Redis pipeline (HGET status).
    Cheap enough for 10k+ jobs: one round-trip, no full hash loads."""
    r = get_redis()
    ids = list(r.smembers(f"case:{case_id}:jobs"))
    if not ids:
        return {}
    pipe = r.pipeline(transaction=False)
    for jid in ids:
        pipe.hget(f"job:{jid}", "status")
    statuses = pipe.execute()
    counts: dict[str, int] = {}
    for s in statuses:
        if s:
            counts[s] = counts.get(s, 0) + 1
    return counts


def list_case_job_ids(case_id: str) -> list[str]:
    """Return all job IDs for a case — lightweight, no hgetall."""
    return list(get_redis().smembers(f"case:{case_id}:jobs"))


def list_case_job_ids_recent(case_id: str, n: int = 5000) -> list[str]:
    """Return up to N most-recently-created job IDs, newest first (sorted-set backed)."""
    r = get_redis()
    ids = r.zrevrange(f"case:{case_id}:jobs:zs", 0, n - 1)
    if ids:
        return list(ids)
    # Fallback to unordered set for cases created before the sorted set was added
    return list(r.smembers(f"case:{case_id}:jobs"))


def list_case_jobs(case_id: str, limit: int = 500, page: int = 0) -> list[dict]:
    """Return paginated job records, newest first.

    Pages over the per-case sorted set (score = creation time) so pagination is
    STABLE — `smembers` returns an unordered set, which duplicated/skipped jobs
    across pages. Falls back to the unordered set for cases created before the
    sorted set existed.
    """
    r = get_redis()
    start = page * limit
    end = start + limit - 1
    page_ids = list(r.zrevrange(f"case:{case_id}:jobs:zs", start, end))
    if not page_ids and page == 0:
        # Legacy case with no sorted set: fall back to unordered membership.
        all_ids = list(r.smembers(f"case:{case_id}:jobs"))
        page_ids = all_ids[start : start + limit]
    jobs = []
    for jid in page_ids:
        job = get_job(jid)
        if job:
            jobs.append(job)
    # zrevrange already orders newest-first; re-sort defensively for the fallback.
    return sorted(jobs, key=lambda j: j.get("created_at", ""), reverse=True)
