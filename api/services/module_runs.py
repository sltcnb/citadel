"""Module run state management in Redis."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

import redis_keys as rk

from config import get_redis

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()
MODULE_RUN_TTL = 604800  # 7 days
MALWARE_RUNS_MAX = 200  # keep last 200 standalone runs

# A RUNNING run whose started_at is older than this can no longer have a live
# worker behind it: the Celery hard time limit (~3h) would have killed the task
# long ago. Same threshold for a PENDING run whose queue message was lost.
STALE_RUN_SECONDS = 4 * 3600
STALE_RUN_ERROR = "worker lost — run never completed; safe to retry"

# Sentinel case_id used for runs that are not tied to a specific case
MALWARE_CASE_ID = "__malware__"


def create_module_run(
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
    params: dict | None = None,
) -> dict:
    r = get_redis()
    run = {
        "run_id": run_id,
        "case_id": case_id,
        "module_id": module_id,
        "status": "PENDING",
        "source_files": json.dumps(source_files),
        # Persisted so a retry can re-dispatch the run exactly as launched —
        # params used to live only in the (possibly lost) queue message.
        "params": json.dumps(params or {}),
        # created_at is set here and never reset (retries only clear started_at/
        # completed_at), so the list stays in launch order even for runs that
        # failed at dispatch and therefore never got a started_at.
        "created_at": _now_iso(),
        "started_at": "",
        "completed_at": "",
        "total_hits": "0",
        "hits_by_level": "{}",
        "results_preview": "[]",
        "output_minio_key": "",
        "error": "",
        "tool_stdout": "",
        "tool_stderr": "",
        "tool_log": "",
    }
    r.hset(rk.module_run(run_id), mapping=run)
    r.expire(rk.module_run(run_id), MODULE_RUN_TTL)
    r.sadd(rk.case_module_runs(case_id), run_id)
    r.expire(rk.case_module_runs(case_id), MODULE_RUN_TTL)
    # Global standalone malware analysis index
    if case_id == MALWARE_CASE_ID:
        r.zadd(rk.MALWARE_RUNS, {run_id: time.time()})
        r.expire(rk.MALWARE_RUNS, MODULE_RUN_TTL)
        # Trim to most recent MALWARE_RUNS_MAX entries
        r.zremrangebyrank(rk.MALWARE_RUNS, 0, -(MALWARE_RUNS_MAX + 1))
    return run


def get_module_run(run_id: str) -> dict | None:
    r = get_redis()
    data = r.hgetall(rk.module_run(run_id))
    if not data:
        return None
    return _reap_stale_run(_deserialize(data))


def list_case_module_runs(case_id: str) -> list[dict]:
    r = get_redis()
    run_ids = r.smembers(rk.case_module_runs(case_id))
    runs = []
    for rid in run_ids:
        run = get_module_run(rid)  # get_module_run reaps zombie runs
        if run:
            runs.append(run)
    return sorted(runs, key=_run_sort_key, reverse=True)


def _reap_stale_run(run: dict) -> dict:
    """Fail a zombie run left behind by a dead worker.

    A worker dying mid-run leaves the record RUNNING forever; a lost queue
    message leaves it PENDING forever. Neither is ever touched again — cancel
    only sets a flag nothing reads and bulk-delete skips "active" runs — so
    the record would stick in the UI indefinitely. Past STALE_RUN_SECONDS no
    live worker can still own the run (the Celery hard limit kills tasks at
    ~3h), so mark it FAILED with a retry-safe error. Cheap: the Redis write
    only happens for runs that qualify; update_module_run preserves the TTL.
    """
    status = run.get("status")
    stamp = run.get("started_at") if status == "RUNNING" else (
        run.get("created_at") if status == "PENDING" else None
    )
    if not stamp:
        return run
    try:
        ts = datetime.fromisoformat(stamp)
    except (ValueError, TypeError):
        return run
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    if (datetime.now(UTC) - ts).total_seconds() <= STALE_RUN_SECONDS:
        return run

    completed_at = _now_iso()
    update_module_run(
        run["run_id"], status="FAILED", error=STALE_RUN_ERROR, completed_at=completed_at
    )
    logger.warning(
        "Reaped stale module run %s (%s, %s since %s)",
        run["run_id"],
        run.get("module_id"),
        status,
        stamp,
    )
    return {**run, "status": "FAILED", "error": STALE_RUN_ERROR, "completed_at": completed_at}


def _run_sort_key(run: dict) -> tuple[str, str]:
    """Newest-first ordering key. created_at is the launch instant and survives
    retries; started_at covers records written before created_at existed. The
    run_id breaks ties so runs launched in the same batch keep a stable order
    instead of shuffling between polls."""
    return (run.get("created_at") or run.get("started_at") or "", run.get("run_id", ""))


def update_module_run(run_id: str, **fields) -> None:
    r = get_redis()
    key = rk.module_run(run_id)
    r.hset(
        key,
        mapping={
            k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in fields.items()
        },
    )
    r.expire(key, MODULE_RUN_TTL)


def reset_module_run_for_retry(run_id: str) -> None:
    """Reset a FAILED or stuck PENDING module run so it can be re-dispatched."""
    r = get_redis()
    key = rk.module_run(run_id)
    r.hset(
        key,
        mapping={
            "status": "PENDING",
            "error": "",
            "total_hits": "0",
            "hits_by_level": "{}",
            "results_preview": "[]",
            "output_minio_key": "",
            "tool_stdout": "",
            "tool_stderr": "",
            "tool_log": "",
            "started_at": "",
            "completed_at": "",
        },
    )
    r.expire(key, MODULE_RUN_TTL)


def delete_module_run(run_id: str, case_id: str = "") -> None:
    """Remove a module run's Redis state: the run hash, its buffered log stream,
    any leftover cancel flag, and its membership in the case (and standalone
    malware) indexes. Object-store output and indexed hits are purged by the
    caller — see routers/modules.py::_purge_module_run."""
    r = get_redis()
    r.delete(rk.module_run(run_id), rk.module_log(run_id), rk.module_cancel(run_id))
    if case_id:
        r.srem(rk.case_module_runs(case_id), run_id)
    # Cheap unconditionally: a case run was never in the malware index anyway.
    r.zrem(rk.MALWARE_RUNS, run_id)


def list_malware_runs() -> list[dict]:
    """Return all standalone malware analysis runs, newest first."""
    r = get_redis()
    run_ids = r.zrevrange(rk.MALWARE_RUNS, 0, 99)
    runs = []
    for rid in run_ids:
        run = get_module_run(rid)
        if run:
            runs.append(run)
    return runs


def _deserialize(data: dict) -> dict:
    for field in ("source_files", "results_preview"):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except (json.JSONDecodeError, TypeError):
                data[field] = []
    for field in ("hits_by_level", "llm_analysis"):
        if field in data and isinstance(data[field], str):
            try:
                data[field] = json.loads(data[field])
            except (json.JSONDecodeError, TypeError):
                data[field] = {} if field == "hits_by_level" else None
    if "params" in data and isinstance(data["params"], str):
        try:
            data["params"] = json.loads(data["params"])
        except (json.JSONDecodeError, TypeError):
            data["params"] = {}
    data.setdefault("params", {})  # records written before params was stored
    for field in ("total_hits", "indexed_count"):
        if field in data:
            try:
                data[field] = int(data[field])
            except (ValueError, TypeError):
                data[field] = 0
    return data
