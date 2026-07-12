"""Admin utility endpoints — system maintenance operations."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services import elasticsearch as es
from services import storage
from services import storage_reconcile

from config import get_redis, settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])


@router.get("/admin/storage-reconcile/report")
def get_storage_reconcile_report():
    """Return the latest persisted storage-reconcile report (report-only).

    The scheduled sweep (when enabled) stores its result; this surfaces it for
    the admin UI. Returns ``{"status": "none"}`` when no report exists yet.
    """
    report = storage_reconcile.latest_report()
    if report is None:
        return {"status": "none"}
    return {"status": "ok", "report": report}


@router.post("/admin/storage-reconcile/run")
def run_storage_reconcile_now():
    """Run an on-demand REPORT-ONLY reconcile sweep and persist the result.

    Never deletes anything — it only classifies orphan objects vs dangling DB
    references, independent of whether the periodic schedule is enabled.
    """
    try:
        report = storage_reconcile.find_orphans()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Reconcile failed: {exc}") from exc
    payload = report.as_dict()
    payload["mode"] = "report-only"
    try:
        get_redis().set(
            storage_reconcile.LATEST_REPORT_KEY, json.dumps(payload, default=str)
        )
    except Exception as exc:  # noqa: BLE001 — persistence best-effort
        logger.warning("storage_reconcile: could not persist on-demand report: %s", exc)
    return {"status": "ok", "report": payload}


@router.post("/admin/purge-orphaned-data")
def purge_orphaned_data():
    """
    Delete all MinIO objects, ES indices, and Redis job records for cases
    that no longer exist in Redis (orphaned from deleted or expired cases).

    Safe to run at any time — active cases (present in cases:all) are never touched.
    """
    r = get_redis()
    # Normalize to str so comparisons hold whether or not the client decodes.
    active_cases: set[str] = {
        (c.decode() if isinstance(c, bytes) else c) for c in (r.smembers("cases:all") or set())
    }

    result = {
        "minio_cases_purged": [],
        "es_cases_purged": [],
        "redis_job_keys_deleted": 0,
        "redis_case_keys_deleted": 0,
    }

    # ── 1. MinIO: find case prefixes with no matching Redis record ────────────
    try:
        client = storage.get_minio()
        prefixes = client.list_objects(settings.MINIO_BUCKET, prefix="cases/", delimiter="/")
        for obj in prefixes:
            if not obj.is_dir:
                continue
            case_id = obj.object_name.rstrip("/").split("/")[-1]
            if case_id not in active_cases:
                deleted = storage.delete_case_objects(case_id)
                result["minio_cases_purged"].append(
                    {"case_id": case_id, "objects_deleted": deleted}
                )
                logger.info("Purged orphaned MinIO case %s (%d objects)", case_id, deleted)
    except Exception as exc:
        logger.warning("MinIO purge error: %s", exc)

    # ── 2. ES: drop indices for non-active cases ──────────────────────────────
    try:
        indices_raw = es._request("GET", "/_cat/indices/fo-case-*?h=index&format=json")
        # Group indices by case_id; delete as explicit list (wildcard DELETE is blocked)
        orphan_indices: dict[str, list[str]] = {}
        for item in indices_raw:
            idx = item.get("index", "")
            after_prefix = idx[len("fo-case-") :]  # e.g. "cfaeedc9fc03-evtx"
            case_id = after_prefix[:12]
            if case_id not in active_cases:
                orphan_indices.setdefault(case_id, []).append(idx)
        for case_id, idx_list in orphan_indices.items():
            try:
                es._request("DELETE", f"/{','.join(idx_list)}")
                result["es_cases_purged"].append(case_id)
                logger.info("Purged orphaned ES indices for case %s (%d)", case_id, len(idx_list))
            except Exception as exc:
                logger.warning("ES purge failed for %s: %s", case_id, exc)
    except Exception as exc:
        logger.warning("ES index list error: %s", exc)

    # ── 3. Redis: orphaned job hashes + stale case job sets ───────────────────
    # Strategy A: scan case:*:jobs sets for cases no longer in cases:all
    # Strategy B: scan job:* hashes directly — catches orphans whose parent set
    #             already expired or was cleaned up without deleting job hashes
    try:
        cursor = 0
        deleted_keys = 0

        # A — parent sets
        while True:
            cursor, keys = r.scan(cursor, match="case:*:jobs", count=1000)
            for key in keys:
                parts = key.split(":")
                # skip case:{id}:jobs:zs — handled separately
                if len(parts) != 3:
                    continue
                case_id = parts[1]
                if case_id not in active_cases:
                    job_ids = list(r.smembers(key))
                    for i in range(0, len(job_ids), 1000):
                        batch = [f"job:{j}" for j in job_ids[i : i + 1000]]
                        r.delete(*batch)
                        deleted_keys += len(batch)
                    r.delete(key, f"case:{case_id}:jobs:zs")
            if cursor == 0:
                break

        # B — direct job hash scan (catches parentless orphans)
        pipe = r.pipeline(transaction=False)
        batch_keys: list[str] = []
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="job:*", count=1000)
            for key in keys:
                pipe.hget(key, "case_id")
                batch_keys.append(key)
                if len(batch_keys) >= 2000:
                    case_ids_batch = pipe.execute()
                    to_delete = [
                        k
                        for k, cid in zip(batch_keys, case_ids_batch)
                        if cid and cid not in active_cases
                    ]
                    if to_delete:
                        r.delete(*to_delete)
                        deleted_keys += len(to_delete)
                    batch_keys = []
                    pipe = r.pipeline(transaction=False)
            if cursor == 0:
                break
        # flush remaining
        if batch_keys:
            case_ids_batch = pipe.execute()
            to_delete = [
                k for k, cid in zip(batch_keys, case_ids_batch) if cid and cid not in active_cases
            ]
            if to_delete:
                r.delete(*to_delete)
                deleted_keys += len(to_delete)

        result["redis_job_keys_deleted"] = deleted_keys
        if deleted_keys:
            logger.info("Purged %d orphaned Redis job keys", deleted_keys)
    except Exception as exc:
        logger.warning("Redis job purge error: %s", exc)

    # ── 4. Redis: other case-scoped keys keyed by case_id as the LAST segment ──
    # These were left behind by deletes during ingestion: collab lists, the
    # per-case dedup set, alert-run results, and the bare case:{id} hash.
    try:
        aux_deleted = 0
        # pattern → function(key_str) -> case_id
        last_seg_patterns = [
            "fo:collab:list:*",
            "fo:ingest:seen_sha256:*",
            "fo:alert_run:*",
        ]
        for pat in last_seg_patterns:
            cursor = 0
            while True:
                cursor, keys = r.scan(cursor, match=pat, count=1000)
                for key in keys:
                    ks = key.decode() if isinstance(key, bytes) else key
                    case_id = ks.rsplit(":", 1)[-1]
                    if case_id not in active_cases:
                        r.delete(key)
                        aux_deleted += 1
                if cursor == 0:
                    break
        # Bare case:{id} hash (NOT case:{id}:jobs* — those are handled above).
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="case:*", count=1000)
            for key in keys:
                ks = key.decode() if isinstance(key, bytes) else key
                parts = ks.split(":")
                if len(parts) != 2:  # only "case:{id}", skip "case:{id}:jobs" etc.
                    continue
                if parts[1] not in active_cases:
                    r.delete(key)
                    aux_deleted += 1
            if cursor == 0:
                break
        result["redis_case_keys_deleted"] = aux_deleted
        if aux_deleted:
            logger.info("Purged %d orphaned Redis case-scoped keys", aux_deleted)
    except Exception as exc:
        logger.warning("Redis case-key purge error: %s", exc)

    return result


class WipeConfirm(BaseModel):
    confirm: str


@router.post("/admin/wipe-all-data")
def wipe_all_data(body: WipeConfirm):
    """
    DESTRUCTIVE — delete ALL case data: every ES index, every MinIO case object,
    every Redis case/job key. Requires {"confirm": "WIPE"} in the request body.
    """
    if body.confirm != "WIPE":
        raise HTTPException(status_code=400, detail='Body must be {"confirm": "WIPE"}')

    r = get_redis()
    result = {"es_indices_deleted": [], "minio_objects_deleted": 0, "redis_keys_deleted": 0}

    # 1. Delete all fo-case-* ES indices
    try:
        indices_raw = es._request("GET", "/_cat/indices/fo-case-*?h=index&format=json")
        for item in indices_raw:
            idx = item.get("index", "")
            if idx:
                try:
                    es._request("DELETE", f"/{idx}")
                    result["es_indices_deleted"].append(idx)
                except Exception as exc:
                    logger.warning("ES delete failed for %s: %s", idx, exc)
    except Exception as exc:
        logger.warning("ES index list error: %s", exc)

    # 2. Delete all MinIO case objects
    try:
        client = storage.get_minio()
        prefixes = client.list_objects(settings.MINIO_BUCKET, prefix="cases/", delimiter="/")
        for obj in prefixes:
            if not obj.is_dir:
                continue
            case_id = obj.object_name.rstrip("/").split("/")[-1]
            deleted = storage.delete_case_objects(case_id)
            result["minio_objects_deleted"] += deleted
    except Exception as exc:
        logger.warning("MinIO wipe error: %s", exc)

    # 3. Delete all case + job Redis keys
    try:
        deleted = 0
        for pattern in ("case:*", "fo:case:*", "cases:*"):
            cursor = 0
            while True:
                cursor, keys = r.scan(cursor, match=pattern, count=500)
                if keys:
                    r.delete(*keys)
                    deleted += len(keys)
                if cursor == 0:
                    break
        result["redis_keys_deleted"] = deleted
        logger.warning(
            "Wipe-all-data executed: %d ES indices, %d MinIO objects, %d Redis keys",
            len(result["es_indices_deleted"]),
            result["minio_objects_deleted"],
            deleted,
        )
    except Exception as exc:
        logger.warning("Redis wipe error: %s", exc)

    return result
