"""Case retention lifecycle — auto-archive idle cases, auto-purge old archives.

Disk pressure from long-forgotten cases (multi-hundred-GB uploads PVC + ES
indices) is a real operational pain. This module runs a periodic sweep:

  1. ARCHIVE — cases still ``active`` whose ``updated_at`` is older than
     ``retention_archive_after_days`` get a full .citadel archive built and
     uploaded to the configured archive bucket (same machinery as
     ``POST /cases/{id}/upload-archive``), then their status flips to
     ``archived``. Local data is kept at this stage.
  2. PURGE — cases already ``archived`` for longer than
     ``retention_purge_after_days`` go through the existing purge path
     (``POST /cases/{id}/purge-archive``): the archive is rebuilt + re-uploaded
     (so a restorable copy is guaranteed to exist), then local ES indices and
     MinIO objects are deleted and the case is marked ``local_purged``.

Both thresholds live in the platform config (``fo:config:platform``, Settings →
System). ``retention_archive_after_days = 0`` disables the whole scheduler.

Safety rules:
  * the ``__malware__`` sentinel case is never touched;
  * a case with active ingestion jobs (PENDING/QUEUED/RUNNING/PROCESSING/
    UPLOADING) is never archived or purged — if the job status check itself
    fails we fail CLOSED and skip the case;
  * retention applies per case regardless of company/tenant;
  * both actions require the archive S3 bucket to be configured — without it
    there is nowhere to put the restorable copy, so the sweep skips;
  * every action (and every failed action) writes a tamper-evident audit
    record (services.audit) and a log line.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta

import redis_keys as rk

from config import get_redis, settings
from services import audit as audit_svc
from services import cases as case_svc
from services import jobs as job_svc
from services.module_runs import MALWARE_CASE_ID

logger = logging.getLogger(__name__)

# Redis single-flight lock — only one uvicorn worker / replica runs the sweep.
_LOCK_KEY = "fo:retention:lock"

# Job statuses that mean "ingest is still in flight" — never archive/purge.
_ACTIVE_JOB_STATUSES = frozenset({"PENDING", "QUEUED", "RUNNING", "PROCESSING", "UPLOADING"})


def _retention_config() -> tuple[int, int]:
    """Effective (archive_after_days, purge_after_days) from the platform config.

    Fails closed to (0, 30) — disabled — when the config store is unreadable.
    """
    from routers.platform_settings import get_platform_config

    try:
        cfg = get_platform_config() or {}
    except Exception:  # noqa: BLE001 — a Redis hiccup must not crash the sweep
        cfg = {}
    try:
        archive_after = int(cfg.get("retention_archive_after_days") or 0)
    except (TypeError, ValueError):
        archive_after = 0
    try:
        purge_after = int(cfg.get("retention_purge_after_days") or 30)
    except (TypeError, ValueError):
        purge_after = 30
    return max(0, archive_after), max(1, purge_after)


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _archive_s3_configured() -> bool:
    """True when the archive bucket (Settings → Archiving) is configured."""
    try:
        raw = get_redis().get(rk.ARCHIVE_SETTINGS)
        cfg = json.loads(raw) if raw else {}
        return bool(cfg.get("s3_endpoint") and cfg.get("s3_bucket"))
    except Exception:  # noqa: BLE001 — fail closed
        return False


def _has_active_jobs(case_id: str) -> bool:
    """True when the case has ingestion jobs in flight.

    Fails CLOSED (returns True) when the check itself errors — skipping a
    retention cycle is cheap, destroying in-flight ingest data is not.
    """
    try:
        counts = job_svc.status_counts_for_case(case_id) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Retention: job status check failed for case %s (%s) — skipping", case_id, exc
        )
        return True
    return any(str(s).upper() in _ACTIVE_JOB_STATUSES and int(n) > 0 for s, n in counts.items())


def _archive_case(case_id: str) -> dict:
    """Build the .citadel archive and upload it to the archive bucket, keeping
    local data — the same machinery as POST /cases/{id}/upload-archive."""
    from routers import export as export_router

    return export_router.upload_archive_case(case_id, None)


def _purge_case(case_id: str) -> dict:
    """Rebuild + re-upload the archive, then delete local ES/MinIO data — the
    same machinery as POST /cases/{id}/purge-archive."""
    from routers import export as export_router

    return export_router.purge_archive_case(case_id, None)


def _audit(case_id: str, action: str, status: int) -> None:
    """Tamper-evident audit record for a retention action. Never raises."""
    try:
        audit_svc.record_event(
            actor="system:retention",
            role="system",
            method="POST",
            path=f"/internal/retention/{action}/{case_id}",
            case_id=case_id,
            status=status,
            ip="",
        )
    except Exception as exc:  # noqa: BLE001 — auditing must never break the sweep
        logger.warning("Retention: audit record failed (%s case %s): %s", action, case_id, exc)


def run_retention_cycle(now: datetime | None = None) -> dict:
    """One archive/purge sweep over all cases. Synchronous — run off the event
    loop. Returns a summary dict (lists of case_ids per outcome)."""
    now = now or datetime.now(UTC)
    archive_after, purge_after = _retention_config()
    result: dict[str, list[str]] = {"archived": [], "purged": [], "skipped_busy": [], "errors": []}

    if archive_after <= 0:
        return result  # scheduler disabled

    if not _archive_s3_configured():
        logger.warning(
            "Retention: archive S3 bucket not configured (Settings → Archiving) — sweep skipped"
        )
        result["errors"].append("archive S3 not configured")
        return result

    archive_cutoff = now - timedelta(days=archive_after)
    purge_cutoff = now - timedelta(days=purge_after)

    r = get_redis()
    for cid in sorted(r.smembers("cases:all") or []):
        if cid == MALWARE_CASE_ID:
            continue
        action = ""
        try:
            case = r.hgetall(f"case:{cid}") or {}
            if not case:
                continue
            status = case.get("status", "active")

            if status == "active":
                ts = _parse_ts(case.get("updated_at") or case.get("created_at"))
                if ts is None or ts >= archive_cutoff:
                    continue
                if _has_active_jobs(cid):
                    result["skipped_busy"].append(cid)
                    continue
                action = "archive"
                info = _archive_case(cid)
                case_svc.update_case(cid, status="archived", archived_at=now.isoformat())
                _audit(cid, action, 200)
                logger.info(
                    "Retention: archived case %s (%s events, idle > %dd)",
                    cid, info.get("event_count", "?"), archive_after,
                )
                result["archived"].append(cid)

            elif status == "archived":
                if str(case.get("local_purged", "")).lower() == "true":
                    continue  # already purged — nothing local left to delete
                ts = _parse_ts(case.get("archived_at") or case.get("updated_at"))
                if ts is None or ts >= purge_cutoff:
                    continue
                if _has_active_jobs(cid):
                    result["skipped_busy"].append(cid)
                    continue
                action = "purge"
                _purge_case(cid)
                _audit(cid, action, 200)
                logger.info(
                    "Retention: purged local data for case %s (archived > %dd)",
                    cid, purge_after,
                )
                result["purged"].append(cid)

        except Exception as exc:  # noqa: BLE001 — one bad case must not stop the sweep
            logger.warning("Retention: %s failed for case %s: %s", action or "sweep", cid, exc)
            if action:
                _audit(cid, action, 500)
            result["errors"].append(cid)

    if result["archived"] or result["purged"] or result["errors"]:
        logger.info(
            "Retention sweep: %d archived, %d purged, %d busy-skipped, %d error(s)",
            len(result["archived"]), len(result["purged"]),
            len(result["skipped_busy"]), len(result["errors"]),
        )
    return result


async def start_retention_scheduler() -> None:
    """Background coroutine — started at API startup next to the CTI scheduler.

    Wakes on a fixed interval (default hourly) and runs one retention sweep in
    a worker thread. Disabled deployments (retention_archive_after_days = 0)
    cost one cheap config read per tick.
    """
    interval = max(60, int(settings.RETENTION_CHECK_INTERVAL_SECONDS))
    logger.info("Retention scheduler started (interval %ds)", interval)
    # Let Redis/ES/MinIO settle before the first sweep.
    await asyncio.sleep(120)
    while True:
        try:
            archive_after, _ = _retention_config()
            if archive_after > 0:
                # Single-flight across uvicorn workers / replicas: only the
                # lock holder runs the sweep this cycle.
                if get_redis().set(_LOCK_KEY, "1", nx=True, ex=max(60, interval - 60)):
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, run_retention_cycle)
        except Exception as exc:  # noqa: BLE001 — the loop must never die
            logger.warning("Retention scheduler tick error: %s", exc)
        await asyncio.sleep(interval)
