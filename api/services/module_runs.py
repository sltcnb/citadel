"""Module run state management in Redis."""

from __future__ import annotations

import json
import logging
import time

import redis_keys as rk

from config import get_redis

logger = logging.getLogger(__name__)
MODULE_RUN_TTL = 604800  # 7 days
MALWARE_RUNS_MAX = 200  # keep last 200 standalone runs

# Sentinel case_id used for runs that are not tied to a specific case
MALWARE_CASE_ID = "__malware__"


def create_module_run(
    run_id: str,
    case_id: str,
    module_id: str,
    source_files: list,
) -> dict:
    r = get_redis()
    run = {
        "run_id": run_id,
        "case_id": case_id,
        "module_id": module_id,
        "status": "PENDING",
        "source_files": json.dumps(source_files),
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
    return _deserialize(data)


def list_case_module_runs(case_id: str) -> list[dict]:
    r = get_redis()
    run_ids = r.smembers(rk.case_module_runs(case_id))
    runs = []
    for rid in run_ids:
        run = get_module_run(rid)
        if run:
            runs.append(run)
    return sorted(
        runs,
        key=lambda x: x.get("started_at") or x.get("run_id", ""),
        reverse=True,
    )


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
    for field in ("total_hits",):
        if field in data:
            try:
                data[field] = int(data[field])
            except (ValueError, TypeError):
                data[field] = 0
    return data
