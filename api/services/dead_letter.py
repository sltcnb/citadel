"""Dead-letter queue admin operations — list + replay.

Reads/writes the same capped Redis list the Sluice worker's
``tools/sluice/worker/robustness.py`` writes poison tasks to
(``fo:worker:dead_letter``, newest entry at index 0 via LPUSH). The API and the
processor are separate deployable containers, so the key name is duplicated
here rather than imported — treat it as a shared contract between the two.

Replay re-enqueues a dead-lettered task through the same direct-to-redis path
the API already uses for normal dispatch (services/celery_dispatch.py), and is
idempotent: if the job/run this task belonged to already reached a terminal
*successful* state (see robustness.TERMINAL_STATUSES), replay is a no-op that
just clears the stale entry instead of re-doing already-succeeded work.
"""

from __future__ import annotations

import json
import logging

from config import get_redis

logger = logging.getLogger(__name__)

# Mirrors tools/sluice/worker/robustness.DEAD_LETTER_KEY.
DEAD_LETTER_KEY = "fo:worker:dead_letter"

# Statuses that mean "already handled" — mirrors robustness.TERMINAL_STATUSES.
_TERMINAL_STATUSES = frozenset({"COMPLETED", "SKIPPED"})

# task name -> base queue it belongs to. Mirrors the queues
# services/celery_dispatch.py's dispatch_* helpers push onto. Every task
# currently dead-lettered by the worker carries its job/run id as args[0].
_TASK_QUEUE = {
    "ingest.process_artifact": "ingest",
    "ingest.s3_transfer": "ingest",
    "module.run": "modules",
    "harvest.run_harvest": "modules",
}


def _decode(v):
    return v.decode() if isinstance(v, bytes) else v


def list_dead_letters(limit: int = 200) -> list[dict]:
    """Newest-first list of dead-letter entries, each tagged with its list
    index (stable as long as nothing else mutates the list concurrently —
    used by replay_entry to target a specific entry)."""
    r = get_redis()
    limit = max(1, min(limit, 1000))
    raw = r.lrange(DEAD_LETTER_KEY, 0, limit - 1)
    out = []
    for i, item in enumerate(raw):
        try:
            entry = json.loads(_decode(item))
        except Exception:
            logger.warning("dead_letter: skipping unparseable entry at index %d", i)
            continue
        entry["index"] = i
        out.append(entry)
    return out


def dead_letter_count() -> int:
    try:
        return int(get_redis().llen(DEAD_LETTER_KEY))
    except Exception:
        return 0


def _job_already_done(r, job_id: str | None) -> bool:
    if not job_id:
        return False
    try:
        status = _decode(r.hget(f"job:{job_id}", "status"))
    except Exception:
        return False
    return status in _TERMINAL_STATUSES


def _replay_raw_entry(r, raw_value) -> dict:
    """Replay one raw (still-JSON-encoded) dead-letter entry and remove it.

    Removal always happens (whether replayed or skipped as already-done) so a
    replay never leaves a duplicate/stale entry behind. Uses LREM with count=1
    so only the first exact match is dropped, never the whole list.
    """
    entry = json.loads(_decode(raw_value))
    task_name = entry.get("task")
    args = entry.get("args") or []
    job_id = args[0] if args else None

    r.lrem(DEAD_LETTER_KEY, 1, raw_value)

    if _job_already_done(r, job_id):
        logger.info(
            "dead_letter: skipping replay of %s (%s) — job %s already terminal",
            task_name,
            entry.get("task_id"),
            job_id,
        )
        return {
            "status": "skipped_already_processed",
            "task": task_name,
            "task_id": entry.get("task_id"),
            "job_id": job_id,
        }

    queue = _TASK_QUEUE.get(task_name)
    if not queue:
        raise ValueError(f"Unknown dead-letter task {task_name!r}; cannot replay")

    from services.celery_dispatch import PRIORITY_HIGH, _push

    # Replays are analyst-initiated and explicit — send them at high priority
    # so they don't sit behind a backlog of routine bulk ingest.
    _push(
        queue, task_name, job_id or entry.get("task_id") or "", list(args), priority=PRIORITY_HIGH
    )
    logger.info("dead_letter: replayed %s (%s) → queue '%s'", task_name, job_id, queue)
    return {
        "status": "requeued",
        "task": task_name,
        "task_id": entry.get("task_id"),
        "job_id": job_id,
        "queue": queue,
    }


def replay_entry(index: int) -> dict:
    """Replay the dead-letter entry currently at *index* (0 = newest)."""
    r = get_redis()
    raw = r.lrange(DEAD_LETTER_KEY, index, index)
    if not raw:
        raise KeyError(f"No dead-letter entry at index {index}")
    return _replay_raw_entry(r, raw[0])


def replay_all() -> list[dict]:
    """Replay every dead-lettered entry, oldest bookkeeping-safe loop.

    Always re-reads index 0 (LREM shifts the list after each replay) and is
    bounded by the list's size at call time so a fresh failure landing mid-run
    can't turn this into an infinite loop.
    """
    r = get_redis()
    results: list[dict] = []
    remaining = int(r.llen(DEAD_LETTER_KEY))
    for _ in range(remaining):
        raw = r.lrange(DEAD_LETTER_KEY, 0, 0)
        if not raw:
            break
        try:
            results.append(_replay_raw_entry(r, raw[0]))
        except Exception as exc:  # noqa: BLE001 — one bad entry must not abort the batch
            logger.warning("dead_letter: replay_all skipping an entry: %s", exc)
            # Drop it so replay_all makes forward progress instead of looping.
            r.lrem(DEAD_LETTER_KEY, 1, raw[0])
    return results
