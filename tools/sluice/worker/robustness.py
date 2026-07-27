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

# ── Scratch-disk guard ──────────────────────────────────────────────────────────
# The worker stages downloads + tool output under /tmp, which in k8s is an
# emptyDir with a hard sizeLimit. Exceeding it gets the whole pod EVICTED by the
# kubelet — killing every concurrent task and, historically, wedging the ingest
# Deployment in an eviction/crash loop that piled up 100+ dead pods. So refuse to
# stage an artifact that would blow the budget and fail *that* task cleanly.
# NB: the emptyDir quota is enforced by the kubelet, and shutil.disk_usage()
# reports the *node* filesystem free space (not the quota) — so the guard budgets
# against MEASURED /tmp usage, not fs-free.
SCRATCH_PATH = os.getenv("WORKER_SCRATCH_PATH", "/tmp")
# Default kept safely under the current 20Gi emptyDir sizeLimit even if the
# deployment doesn't override it; the manifest sets a larger budget to match a
# larger sizeLimit.
SCRATCH_BUDGET_BYTES = int(os.getenv("WORKER_SCRATCH_BUDGET_BYTES", str(18 * 1024**3)))
# Multiply an artifact's declared size to cover decompression + tool scratch.
SCRATCH_MARGIN = float(os.getenv("WORKER_SCRATCH_MARGIN", "1.3"))


class InsufficientScratchSpace(RuntimeError):
    """Staging an artifact would exceed the scratch-disk budget. Raised so the
    task fails cleanly instead of overflowing the emptyDir and getting the pod
    evicted (which kills every concurrent task)."""

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


def scratch_used_bytes(path: str = SCRATCH_PATH) -> int:
    """Total bytes currently staged under `path` (the emptyDir scratch area).

    Walks the tree because the kubelet enforces the emptyDir quota by summing
    file sizes the same way — fs-free-space APIs report the node disk, not the
    per-volume quota."""
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def require_scratch(need_bytes: int, path: str = SCRATCH_PATH) -> None:
    """Refuse to stage ``need_bytes`` if it would exceed the scratch budget.

    Budgets against *measured* usage of ``path`` (see the module note): raises
    :class:`InsufficientScratchSpace` when projected usage would exceed
    ``SCRATCH_BUDGET_BYTES``. A no-op when the size is unknown/zero."""
    if need_bytes <= 0:
        return
    need = int(need_bytes * SCRATCH_MARGIN)
    used = scratch_used_bytes(path)
    if used + need > SCRATCH_BUDGET_BYTES:
        raise InsufficientScratchSpace(
            f"scratch budget would be exceeded on {path}: {used // 1024 // 1024} MB used "
            f"+ ~{need // 1024 // 1024} MB needed > {SCRATCH_BUDGET_BYTES // 1024 // 1024} MB "
            f"budget — refusing to stage so the pod is not evicted"
        )
