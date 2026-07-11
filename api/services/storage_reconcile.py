"""Reconcile MinIO objects against the object keys recorded in the database.

Two classes of drift are detected under the ``cases/`` prefix:

* **orphan objects** — present in MinIO but referenced by no DB record. These
  waste storage and can be swept (only with an explicit confirmation).
* **missing objects** ("dangling references") — a DB record points at an
  object key that no longer exists in MinIO. These are reported for human
  review and are NEVER auto-fixed: deleting a record is a chain-of-custody
  decision, not an automated one.

``reconcile`` is REPORT-ONLY by default. Actual object deletion happens only
when ``dry_run=False`` AND ``confirm=True``. A configurable grace period
(``STORAGE_RECONCILE_GRACE_HOURS``) protects objects newer than the window so an
in-flight upload whose DB record hasn't been written yet is never swept.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from config import settings
from services import storage

logger = logging.getLogger(__name__)

_CASE_PREFIX = "cases/"


# ── Known-key collection (the "DB" side) ───────────────────────────────────────


def known_object_keys() -> set[str]:
    """Return every object key currently referenced by a DB record.

    The authoritative references live on job hashes (``minio_object_key``),
    which cover ingest sources, re-ingested findings artifacts and module
    outputs. Missing/unreachable Redis raises so callers don't misread an
    outage as "everything is an orphan".
    """
    from config import get_redis
    from services import jobs as job_svc

    r = get_redis()
    keys: set[str] = set()
    case_ids = r.smembers("cases:all") or set()
    for case_id in case_ids:
        for job_id in job_svc.list_case_job_ids(case_id):
            job = job_svc.get_job(job_id)
            if not job:
                continue
            k = job.get("minio_object_key")
            if k:
                keys.add(k)
    return keys


# ── Report structures ──────────────────────────────────────────────────────────


@dataclass
class OrphanReport:
    orphan_objects: list[str] = field(default_factory=list)  # in MinIO, no DB record
    missing_objects: list[str] = field(default_factory=list)  # DB record, no object
    skipped_recent: list[str] = field(default_factory=list)  # within grace period
    scanned_objects: int = 0
    known_keys: int = 0
    truncated: bool = False

    def as_dict(self) -> dict:
        return {
            "orphan_objects": self.orphan_objects,
            "missing_objects": self.missing_objects,
            "skipped_recent": self.skipped_recent,
            "counts": {
                "orphan_objects": len(self.orphan_objects),
                "missing_objects": len(self.missing_objects),
                "skipped_recent": len(self.skipped_recent),
                "scanned_objects": self.scanned_objects,
                "known_keys": self.known_keys,
            },
            "truncated": self.truncated,
        }


def _grace_cutoff(grace_hours: int | None) -> datetime:
    hours = settings.STORAGE_RECONCILE_GRACE_HOURS if grace_hours is None else grace_hours
    return datetime.now(UTC) - timedelta(hours=hours)


def _last_modified(obj) -> datetime | None:
    lm = getattr(obj, "last_modified", None)
    if lm is None:
        return None
    if lm.tzinfo is None:
        lm = lm.replace(tzinfo=UTC)
    return lm


def find_orphans(
    case_id: str | None = None,
    grace_hours: int | None = None,
    max_objects: int | None = None,
) -> OrphanReport:
    """Classify objects under ``cases/`` against the DB's known keys.

    Scope to a single case with *case_id*. Objects modified inside the grace
    window are recorded under ``skipped_recent`` and excluded from the orphan
    list. Listing is capped at *max_objects* (``STORAGE_RECONCILE_MAX_OBJECTS``).
    """
    cap = settings.STORAGE_RECONCILE_MAX_OBJECTS if max_objects is None else max_objects
    cutoff = _grace_cutoff(grace_hours)
    known = known_object_keys()
    prefix = f"{_CASE_PREFIX}{case_id}/" if case_id else _CASE_PREFIX

    report = OrphanReport(known_keys=len(known))
    seen_objects: set[str] = set()

    for obj in storage.list_objects(prefix=prefix, recursive=True):
        if report.scanned_objects >= cap:
            report.truncated = True
            logger.warning(
                "storage_reconcile: object listing hit cap of %d — report truncated", cap
            )
            break
        key = obj.object_name
        report.scanned_objects += 1
        seen_objects.add(key)
        if key in known:
            continue  # accounted for
        lm = _last_modified(obj)
        if lm is not None and lm >= cutoff:
            report.skipped_recent.append(key)  # too new to judge — in-flight upload
            continue
        report.orphan_objects.append(key)

    # Dangling references: known keys with no object. When scanning a single
    # case, only judge keys under that case's prefix.
    relevant_known = {k for k in known if k.startswith(prefix)} if case_id else known
    report.missing_objects = sorted(relevant_known - seen_objects)
    report.orphan_objects.sort()
    report.skipped_recent.sort()

    logger.info(
        "storage_reconcile scan: scanned=%d known=%d orphan=%d missing=%d skipped_recent=%d%s",
        report.scanned_objects,
        report.known_keys,
        len(report.orphan_objects),
        len(report.missing_objects),
        len(report.skipped_recent),
        " (truncated)" if report.truncated else "",
    )
    return report


def reconcile(
    dry_run: bool = True,
    confirm: bool = False,
    case_id: str | None = None,
    grace_hours: int | None = None,
    max_objects: int | None = None,
) -> dict:
    """Report drift and, only when explicitly told, sweep orphan objects.

    Report-only unless ``dry_run=False`` AND ``confirm=True``. Dangling DB
    references are never auto-fixed. Every deletion is logged precisely.
    """
    report = find_orphans(case_id=case_id, grace_hours=grace_hours, max_objects=max_objects)
    result = report.as_dict()

    would_delete = report.orphan_objects
    if dry_run or not confirm:
        result["action"] = "report-only"
        result["deleted"] = []
        result["would_delete"] = would_delete
        if would_delete and not dry_run and not confirm:
            logger.warning(
                "storage_reconcile: %d orphan object(s) NOT deleted — confirm flag not set",
                len(would_delete),
            )
        else:
            logger.info(
                "storage_reconcile dry-run: %d orphan object(s) would be deleted",
                len(would_delete),
            )
        return result

    # Live deletion — orphan objects only, never DB records.
    deleted: list[str] = []
    for key in would_delete:
        try:
            storage.delete_object(key)
            logger.info("storage_reconcile: deleted orphan object %s", key)
            deleted.append(key)
        except storage.StorageError as exc:
            logger.error("storage_reconcile: failed to delete orphan %s: %s", key, exc)
    result["action"] = "deleted"
    result["deleted"] = deleted
    result["would_delete"] = []
    logger.info(
        "storage_reconcile: swept %d/%d orphan object(s)%s",
        len(deleted),
        len(would_delete),
        f" for case {case_id}" if case_id else "",
    )
    return result
