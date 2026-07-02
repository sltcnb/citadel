"""Case management — cases are stored in Redis as JSON hashes."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime

import redis_keys as rk

from config import get_redis

logger = logging.getLogger(__name__)
CASE_TTL = 0  # Cases don't expire by default


def create_case(name: str, description: str = "", analyst: str = "", company: str = "") -> dict:
    r = get_redis()
    case_id = uuid.uuid4().hex[:12]
    case = {
        "case_id": case_id,
        "name": name,
        "description": description,
        "analyst": analyst,
        "company": company,
        "status": "active",
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
        "tags": json.dumps([]),
    }
    r.hset(f"case:{case_id}", mapping=case)
    r.sadd("cases:all", case_id)
    return case


def get_case(case_id: str) -> dict | None:
    r = get_redis()
    data = r.hgetall(f"case:{case_id}")
    if not data:
        return None
    for field in ("tags",):
        if field in data:
            try:
                data[field] = json.loads(data[field])
            except Exception:
                data[field] = []
    return data


_AUTO_RUN_STAGES = ("auto_detections", "auto_ioc_match", "auto_modules", "auto_ai")


def get_auto_run(case_id: str) -> dict:
    """Per-case auto-run stage flags. Detections / IOC match / modules default ON;
    the LLM (`auto_ai`) is OPT-IN (default OFF) — the analyst arms it explicitly."""
    r = get_redis()
    h = r.hgetall(f"case:{case_id}") or {}
    return {s: h.get(s, "0" if s == "auto_ai" else "1") != "0" for s in _AUTO_RUN_STAGES}


def set_auto_run(case_id: str, flags: dict) -> dict:
    r = get_redis()
    key = f"case:{case_id}"
    for s in _AUTO_RUN_STAGES:
        if s in flags and flags[s] is not None:
            r.hset(key, s, "1" if flags[s] else "0")
    return get_auto_run(case_id)


def auto_run_enabled(case_id: str, stage: str) -> bool:
    """True if `stage` should auto-run for this case (default True)."""
    try:
        return get_redis().hget(f"case:{case_id}", stage) != "0"
    except Exception:
        return True


def list_cases() -> list[dict]:
    r = get_redis()
    case_ids = list(r.smembers("cases:all"))
    if not case_ids:
        return []
    pipe = r.pipeline(transaction=False)
    for cid in case_ids:
        pipe.hgetall(f"case:{cid}")
    results = pipe.execute()
    cases = []
    for data in results:
        if not data:
            continue
        for field in ("tags",):
            if field in data:
                try:
                    data[field] = json.loads(data[field])
                except Exception:
                    data[field] = []
        cases.append(data)
    return sorted(cases, key=lambda c: c.get("created_at", ""), reverse=True)


def update_case(case_id: str, **fields) -> dict | None:
    r = get_redis()
    if not r.exists(f"case:{case_id}"):
        return None
    fields["updated_at"] = datetime.now(UTC).isoformat()
    if "tags" in fields:
        fields["tags"] = json.dumps(fields["tags"])
    r.hset(f"case:{case_id}", mapping=fields)
    return get_case(case_id)


def delete_case(case_id: str, background: bool = True) -> bool:
    """
    Delete a case and all its data.

    background=True (default): Redis metadata is removed immediately (so GET
    returns 404 at once), then MinIO objects and ES indices are deleted in a
    daemon thread so the HTTP response is not blocked.
    """
    import threading

    r = get_redis()
    if not r.exists(f"case:{case_id}"):
        return False

    from services import storage
    from services.jobs import list_case_job_ids
    from services.module_runs import list_case_module_runs

    # ── Module runs: delete output MinIO objects + Redis records ──────────────────
    module_runs = list_case_module_runs(case_id)
    for run in module_runs:
        output_key = run.get("output_minio_key", "")
        if output_key:
            try:
                storage.delete_object(output_key)
            except Exception:
                pass
        run_id = run.get("run_id", "")
        if run_id:
            r.delete(rk.module_run(run_id), rk.module_log(run_id))
    r.delete(rk.case_module_runs(case_id))

    # ── Redis job records: cancel pending/running then batch-delete ───────────────
    job_ids = list_case_job_ids(case_id)
    BATCH = 1000
    for i in range(0, len(job_ids), BATCH):
        batch = job_ids[i : i + BATCH]
        # Mark any still-queued jobs as CANCELLED so processors skip them
        pipe = r.pipeline(transaction=False)
        for jid in batch:
            pipe.hset(f"job:{jid}", "status", "CANCELLED")
        pipe.execute()
        r.delete(*[f"job:{jid}" for jid in batch])
    r.delete(f"case:{case_id}:jobs", f"case:{case_id}:jobs:zs")

    # ── Harvest runs: scan and delete (no case index exists; few keys in practice) ─
    cursor = 0
    while True:
        cursor, keys = r.scan(cursor, match="harvest_run:*", count=100)
        for key in keys:
            if r.hget(key, "case_id") == case_id:
                r.delete(key)
        if cursor == 0:
            break

    # ── Per-case Redis keys (notes, saved searches, alert rules) ──────────────────
    r.delete(
        f"case:{case_id}",
        rk.case_notes(case_id),
        rk.case_saved_searches(case_id),
        rk.case_alert_rules(case_id),
        rk.case_alert_run(case_id),
        rk.case_alert_rule_run(case_id),
        rk.case_alert_run_lock(case_id),
    )
    r.srem("cases:all", case_id)

    def _cleanup_bulk():
        try:
            storage.delete_case_objects(case_id)
        except Exception as exc:
            logger.warning("MinIO cleanup failed for case %s: %s", case_id, exc)
        try:
            from services.elasticsearch import delete_case_indices

            delete_case_indices(case_id)
        except Exception as exc:
            logger.warning("ES cleanup failed for case %s: %s", case_id, exc)
        logger.info("Background cleanup complete for case %s", case_id)

    if background:
        threading.Thread(target=_cleanup_bulk, daemon=True).start()
        logger.info("Case %s deleted from Redis; bulk data cleanup started in background", case_id)
    else:
        _cleanup_bulk()

    return True
