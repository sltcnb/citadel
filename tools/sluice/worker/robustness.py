"""Queue robustness helpers for the Sluice ingest worker.

Three concerns, all Redis-backed so they work across every Celery worker
process and replica (prefork gives each task its own process; a per-process
lock would not bound anything globally):

1. **Idempotency** — a task re-delivered for a job/object that already reached a
   terminal *successful* state must be a no-op. Celery runs with ``acks_late`` +
   ``task_reject_on_worker_lost``, so a task can legitimately be redelivered after
   a crash; without a guard it would re-index the artifact twice.

2. **Dead-letter path** — a poison task that keeps failing is retried a bounded
   number of times, then parked on a capped Redis list with its error captured,
   instead of retrying forever or vanishing.

3. **Backpressure** — heavy work (plugin parse + bulk index) is gated by a
   Redis counter so a burst of dispatches can't run more heavy tasks at once
   than the worker fleet can hold in memory.

Pure stdlib + a duck-typed redis client, so it is unit-testable with a tiny
fake redis (see tests/test_robustness.py) — nothing here imports Celery.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

try:  # pragma: no cover - observability is always present in-tree
    import observability as _obs
except Exception:  # noqa: BLE001 - metrics must never block dead-lettering
    _obs = None

logger = logging.getLogger(__name__)

# ── Config (env, safe defaults) ────────────────────────────────────────────────
# Bounded retries before a task is dead-lettered.
TASK_MAX_RETRIES = int(os.getenv("WORKER_TASK_MAX_RETRIES", "3"))
# Base retry backoff (seconds); grows exponentially, capped by RETRY_BACKOFF_MAX.
TASK_RETRY_BACKOFF = int(os.getenv("WORKER_TASK_RETRY_BACKOFF", "30"))
TASK_RETRY_BACKOFF_MAX = int(os.getenv("WORKER_TASK_RETRY_BACKOFF_MAX", "600"))
# Keep at most this many dead-letter entries (newest first).
DEAD_LETTER_MAXLEN = int(os.getenv("WORKER_DEAD_LETTER_MAXLEN", "1000"))
# Max concurrent in-flight *heavy* tasks across the whole fleet. 0 = unbounded.
MAX_IN_FLIGHT = int(os.getenv("WORKER_MAX_IN_FLIGHT", "0"))
# Self-heal TTL on the in-flight counter so a missed release can't wedge the
# gate forever (matches the Celery hard time limit).
INFLIGHT_TTL = int(os.getenv("WORKER_INFLIGHT_TTL", "7200"))

# ── Redis keys ──────────────────────────────────────────────────────────────────
DEAD_LETTER_KEY = "fo:worker:dead_letter"
_INFLIGHT_KEY = "fo:worker:inflight"

# Job statuses that mean "already successfully handled" — re-processing is a
# no-op. FAILED and CANCELLED are intentionally excluded: FAILED may legitimately
# be retried, and CANCELLED is handled explicitly by the task itself.
TERMINAL_STATUSES = frozenset({"COMPLETED", "SKIPPED"})


def _decode(v: Any) -> Any:
    return v.decode() if isinstance(v, bytes) else v


# ── 1. Idempotency ───────────────────────────────────────────────────────────────


def job_already_processed(r, job_id: str) -> bool:
    """True when *job_id* already reached a terminal successful state.

    Callers use this at task entry to make a redelivered task a no-op. Any Redis
    hiccup returns False (fail open — better to risk a rare re-process than to
    silently drop a job).
    """
    if not job_id:
        return False
    try:
        status = _decode(r.hget(f"job:{job_id}", "status"))
    except Exception:  # pragma: no cover - bookkeeping must never break a task
        return False
    return status in TERMINAL_STATUSES


# ── 2. Dead-letter path ──────────────────────────────────────────────────────────


def retry_countdown(retries: int) -> int:
    """Exponential backoff (seconds) for the *next* retry, capped."""
    return min(TASK_RETRY_BACKOFF * (2**max(0, retries)), TASK_RETRY_BACKOFF_MAX)


def retries_exhausted(retries: int) -> bool:
    """True when a task has used up its retry budget and must be dead-lettered."""
    return retries >= TASK_MAX_RETRIES


def to_dead_letter(
    r,
    *,
    task_name: str,
    task_id: str | None,
    args: list | tuple | None,
    error: Any,
    retries: int,
) -> dict:
    """Park a poison task on the capped dead-letter list with its error captured.

    Returns the stored entry. Never raises — a failed dead-letter write is logged
    but must not mask the original task failure.
    """
    entry = {
        "task": task_name,
        "task_id": task_id,
        "args": list(args) if args else [],
        "error": str(error)[:2000],
        "retries": retries,
        "failed_at": datetime.now(UTC).isoformat(),
    }
    try:
        r.lpush(DEAD_LETTER_KEY, json.dumps(entry, default=str))
        r.ltrim(DEAD_LETTER_KEY, 0, DEAD_LETTER_MAXLEN - 1)
        logger.error(
            "dead-letter: task %s (%s) parked after %d retries: %s",
            task_name,
            task_id,
            retries,
            entry["error"],
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("could not write dead-letter entry for %s: %s", task_name, exc)
    if _obs is not None:
        try:
            _obs.record_dead_letter(task_name)
        except Exception:  # pragma: no cover - metrics must never break dead-lettering
            pass
    return entry


def dead_letter_size(r) -> int:
    try:
        return int(r.llen(DEAD_LETTER_KEY))
    except Exception:  # pragma: no cover
        return 0


# ── 3. Backpressure ──────────────────────────────────────────────────────────────


def acquire_slot(r) -> bool:
    """Reserve one heavy-work slot. True if capacity is available (or unbounded).

    Uses an atomic INCR so the gate holds across worker processes and replicas.
    Never blocks heavy work on a bookkeeping failure (fails open).
    """
    if MAX_IN_FLIGHT <= 0:
        return True
    try:
        n = int(r.incr(_INFLIGHT_KEY))
        r.expire(_INFLIGHT_KEY, INFLIGHT_TTL)
    except Exception:  # pragma: no cover
        return True
    if n > MAX_IN_FLIGHT:
        try:
            r.decr(_INFLIGHT_KEY)
        except Exception:  # pragma: no cover
            pass
        return False
    return True


def release_slot(r) -> None:
    """Release a slot reserved by :func:`acquire_slot`. Clamps at zero."""
    if MAX_IN_FLIGHT <= 0:
        return
    try:
        n = int(r.decr(_INFLIGHT_KEY))
        if n < 0:
            r.set(_INFLIGHT_KEY, 0)
    except Exception:  # pragma: no cover
        pass
