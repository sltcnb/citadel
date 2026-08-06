"""Background AI report generation job state (Redis).

Generating the AI narrative report takes minutes — long enough that analysts
close the report drawer mid-run. The old flow fired the request from the panel
and aborted it on unmount, killing the report with it. Generation now runs
server-side in a daemon thread (see routers/reports.py); this module tracks the
lifecycle (pending → running → done/error) in Redis so the UI can poll — and
resume polling after a drawer close/reopen or a page navigation. Entries expire
after 24h.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime

from config import get_redis

logger = logging.getLogger(__name__)

JOB_TTL_SECONDS = 24 * 60 * 60  # keep status/result for a day
_ACTIVE_STATUSES = ("pending", "running")


def _key(case_id: str) -> str:
    return f"case:{case_id}:ai:report_job"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def get_job(case_id: str) -> dict | None:
    try:
        raw = get_redis().get(_key(case_id))
    except Exception:
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _store(case_id: str, **fields) -> None:
    job = get_job(case_id) or {"case_id": case_id}
    job.update(fields)
    try:
        get_redis().setex(_key(case_id), JOB_TTL_SECONDS, json.dumps(job))
    except Exception:
        logger.warning("report job store failed for case %s", case_id, exc_info=True)


def start_job(case_id: str, fn, *args) -> bool:
    """Mark the job pending and run fn(*args) in a daemon thread.

    Returns False (and starts nothing) when a job is already in flight for the
    case — a second Generate click must not double the LLM spend.
    """
    existing = get_job(case_id)
    if existing and existing.get("status") in _ACTIVE_STATUSES:
        return False

    _store(
        case_id,
        status="pending",
        started_at=_now_iso(),
        finished_at=None,
        result=None,
        error=None,
    )

    def _runner() -> None:
        _store(case_id, status="running")
        try:
            result = fn(*args)
        except Exception as exc:  # stored, never raised — the UI polls for it
            detail = getattr(exc, "detail", None) or str(exc)
            logger.warning("AI report job failed for case %s: %s", case_id, detail)
            _store(case_id, status="error", error=str(detail), finished_at=_now_iso())
            return
        _store(case_id, status="done", result=result, finished_at=_now_iso())

    t = threading.Thread(target=_runner, name=f"ai-report-{case_id}", daemon=True)
    t.start()
    return True
