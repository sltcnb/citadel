"""
Core ingest task: download artifact from MinIO, detect type, run plugin, index to ES.
"""

from __future__ import annotations

import hashlib
import io as _io
import json
import logging
import os
import shutil
import tarfile as _tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile as _zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis
import redis_keys as rk


def _put_with_retry(minio_client, bucket: str, key: str, data: bytes, attempts: int = 3) -> None:
    """PUT bytes to MinIO with retries — handles transient SignatureDoesNotMatch / network blips."""
    for attempt in range(1, attempts + 1):
        try:
            minio_client.put_object(bucket, key, _io.BytesIO(data), len(data))
            return
        except Exception as exc:
            if attempt == attempts:
                raise
            wait = 2**attempt
            logger.warning(
                "MinIO put attempt %d/%d failed (%s) — retry in %ds", attempt, attempts, exc, wait
            )
            time.sleep(wait)


import bus_emit
from celery_app import app
from plugin_loader import PluginLoader
from utils.es_bulk import ESBulkIndexer
from utils.file_type import detect_mime

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio-service:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forensics-cases")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch-service:9200")
BULK_SIZE = int(os.getenv("BULK_SIZE", "500"))

# Shared plugin loader instance (reused across tasks in the same worker)
_plugin_loader = PluginLoader(Path("/app/babel"))

# Shared pool — prevents each task from creating its own pool (which exhausts Redis connections)
_redis_pool = redis.ConnectionPool.from_url(
    REDIS_URL,
    max_connections=20,
    decode_responses=True,
    socket_timeout=10,
    socket_connect_timeout=5,
)


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=_redis_pool)


def get_minio():
    from minio import Minio

    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )


def _strip_surrogates(s: str) -> str:
    """Replace lone unicode surrogates so subsequent json.dumps / redis writes
    don't raise UnicodeEncodeError. Filenames extracted from tar/zip archives
    can carry \\udcXX bytes when the source path wasn't valid UTF-8."""
    return s.encode("utf-8", errors="replace").decode("utf-8")


def _safe_relative_path(name: str) -> str | None:
    """Sanitize an archive entry name for safe use as a filesystem path.

    Returns the cleaned relative path, or None if the entry should be rejected
    (path traversal, absolute path, drive letter, embedded NUL, …).

    SECURITY: archive entries control the local path written under work_dir.
    Without this guard, a malicious .zip / .tar can write outside the work_dir
    (CVE-style zip-slip / tar-slip) — e.g. `../../etc/cron.d/evil`.
    """
    if not name:
        return None
    s = _strip_surrogates(name).replace("\\", "/").strip()
    if not s or "\x00" in s:
        return None
    # Reject absolute paths and Windows drive letters
    if s.startswith("/") or (len(s) >= 2 and s[1] == ":"):
        return None
    parts = []
    for p in s.split("/"):
        if not p or p == ".":
            continue
        if p == "..":
            return None  # path traversal — reject the whole entry
        parts.append(p)
    return "/".join(parts) or None


def update_job_status(r: redis.Redis, job_id: str, **fields) -> None:
    key = f"job:{job_id}"
    safe = {}
    for k, v in fields.items():
        if isinstance(v, str):
            safe[k] = _strip_surrogates(v)
        else:
            try:
                safe[k] = json.dumps(v, ensure_ascii=False)
            except (TypeError, ValueError, UnicodeEncodeError):
                safe[k] = json.dumps(v, ensure_ascii=True)
    r.hset(key, mapping=safe)
    r.expire(key, 604800)  # 7 days TTL


def _es_search(index: str, body: dict) -> dict:
    """Fire a single ES search query from the processor."""
    url = f"{ELASTICSEARCH_URL}/{index}/_search"
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


_NON_TERMINAL = {"PENDING", "RUNNING", "UPLOADING"}


def _case_has_active_jobs(r: redis.Redis, case_id: str) -> bool:
    """True if any RUNNING/PENDING/UPLOADING job remains for this case."""
    job_ids = list(r.smembers(f"case:{case_id}:jobs") or [])
    if not job_ids:
        return False
    pipe = r.pipeline(transaction=False)
    for jid in job_ids:
        jid_str = jid.decode() if isinstance(jid, bytes) else jid
        pipe.hget(f"job:{jid_str}", "status")
    for s in pipe.execute():
        if not s:
            continue
        status = s.decode() if isinstance(s, bytes) else s
        if status in _NON_TERMINAL:
            return True
    return False


def _run_library_rules(r: redis.Redis, case_id: str) -> None:
    """Execute every applicable library rule against a case. Persists the run
    record at case_alert_run(case_id) so the UI 'Last Run' section finds it."""
    data = r.get(rk.GLOBAL_ALERT_RULES)
    rules = json.loads(data) if data else []
    # Company filter
    raw_co = r.hget(f"case:{case_id}", "company")
    case_company = (raw_co.decode() if isinstance(raw_co, bytes) else raw_co) or ""

    def _applies(rule):
        cos = rule.get("companies") or []
        return not cos or case_company in cos or "*" in cos

    rules = [rl for rl in rules if _applies(rl)]
    if not rules:
        logger.info("[detections] case %s — no library rules to run", case_id)
        return
    matches = []
    for rule in rules:
        idx = (
            f"fo-case-{case_id}-{rule['artifact_type']}"
            if rule.get("artifact_type")
            else f"fo-case-{case_id}-*"
        )
        body = {
            "query": {"query_string": {"query": rule.get("query", ""), "default_operator": "AND"}},
            "size": 5,
            "_source": ["timestamp", "message", "host", "user", "fo_id", "artifact_type"],
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        try:
            resp = _es_search(idx, body)
            count = resp["hits"]["total"]["value"]
            if count >= int(rule.get("threshold", 1)):
                matches.append(
                    {
                        "rule": rule,
                        "match_count": count,
                        "sample_events": [h["_source"] for h in resp["hits"]["hits"]],
                    }
                )
        except Exception as exc:
            logger.debug("[detections] rule %s skipped: %s", rule.get("name"), exc)
    run = {
        "ran_at": datetime.now(UTC).isoformat(),
        "rules_checked": len(rules),
        "matches": matches,
        "analyses": {},
        "auto": True,
    }
    r.set(rk.case_alert_run(case_id), json.dumps(run))
    r.expire(rk.case_alert_run(case_id), 7 * 86400)
    logger.info(
        "[detections] case %s — auto-ran %d rules, %d matches", case_id, len(rules), len(matches)
    )
    if matches:
        _fire_alert_webhooks(r, case_id, matches, run["ran_at"])


def _fire_alert_webhooks(r: redis.Redis, case_id: str, matches: list, ran_at: str) -> None:
    """Notify subscribed webhooks that detection rules fired on a case."""
    from tasks._webhooks import fire_webhooks

    raw_name = r.hget(f"case:{case_id}", "name")
    case_name = (raw_name.decode() if isinstance(raw_name, bytes) else raw_name) or case_id
    summary = [
        {
            "rule_name": (m.get("rule") or {}).get("name", "?"),
            "level": (m.get("rule") or {}).get("level", ""),
            "match_count": m.get("match_count", 0),
        }
        for m in matches[:20]
    ]
    lines = "\n".join(
        f"• {s['rule_name']}: {s['match_count']} match(es)"
        + (f" [{s['level']}]" if s["level"] else "")
        for s in summary
    )
    fire_webhooks(
        r,
        "alert_rules",
        {
            "event": "alert_rules",
            "text": f"Citadel: {len(matches)} detection rule(s) fired on case {case_name}\n{lines}",
            "case_id": case_id,
            "case_name": case_name,
            "matches": summary,
            "ran_at": ran_at,
        },
    )


def _auto_run_alert_rules(r: redis.Redis, case_id: str) -> None:
    """Schedule a deferred detection-rules run for a case.

    The actual run waits for the case to be idle (no RUNNING/PENDING jobs).
    Triggered by every job completion; chains itself forward until quiet,
    so detections fire ONCE after the last job finishes — not per-job.
    """
    # Debounce — only the first completion within a window schedules a chain.
    if not r.set(rk.case_alert_run_lock(case_id), "1", ex=15, nx=True):
        return
    # Defer execution — give the queue time to drain.
    try:
        maybe_run_detections.apply_async(args=[case_id], countdown=20)
    except Exception as exc:
        logger.warning("[detections] case %s — could not schedule deferred run: %s", case_id, exc)


# ── ZIP auto-expansion helpers ────────────────────────────────────────────────

_ZIP_SKIP_BASENAMES = {".ds_store", "thumbs.db", "desktop.ini"}
_ZIP_SKIP_EXTS = {".zip"}  # no recursive nesting
JOB_TTL = 604800  # 7 days — matches api/services/jobs.py


def _is_fo_zip(path: Path) -> bool:
    """Return True if the file is a ZIP archive that should be expanded into child jobs."""
    try:
        return _zipfile.is_zipfile(str(path))
    except Exception:
        return False


def _expand_zip_into_child_jobs(
    parent_job_id: str,
    case_id: str,
    zip_path: Path,
    r: redis.Redis,
    keep_raw: str = "0",
) -> int:
    """
    Extract every entry from a ZIP and create individual child jobs, mirroring
    what _handle_zip_async() does in api/routers/ingest.py for direct uploads.

    Uses the FULL relative path from the ZIP as the job filename so that
    path-part based MIME detection in utils/file_type.py gives downstream
    plugins (e.g. scheduled_task, wer) the directory context they need.

    Returns the count of child jobs successfully dispatched.
    """
    minio_client = get_minio()
    count = 0

    with _zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # SECURITY + sanity: reject absolute paths / .. traversal; strip
            # surrogates. _safe_relative_path returns None for anything unsafe.
            entry_rel = _safe_relative_path(info.filename)
            if not entry_rel:
                logger.warning("[%s] Rejected unsafe zip entry: %r", parent_job_id, info.filename)
                continue
            base_name = entry_rel.split("/")[-1]

            if not base_name or base_name.startswith("."):
                continue
            if base_name.lower() in _ZIP_SKIP_BASENAMES:
                continue
            if Path(base_name).suffix.lower() in _ZIP_SKIP_EXTS:
                continue

            child_id = uuid.uuid4().hex
            minio_key = f"cases/{case_id}/{child_id}/{entry_rel}"

            # ── Create child job record (schema matches api/services/jobs.py) ──
            now = datetime.now(UTC).isoformat()
            r.hset(
                f"job:{child_id}",
                mapping={
                    "job_id": child_id,
                    "case_id": case_id,
                    "status": "UPLOADING",
                    "original_filename": entry_rel.encode("utf-8", errors="replace").decode(
                        "utf-8"
                    ),
                    "minio_object_key": minio_key,
                    "events_indexed": "0",
                    "error": "",
                    "plugin_used": "",
                    "plugin_stats": "{}",
                    "created_at": now,
                    "started_at": "",
                    "completed_at": "",
                    "task_id": "",
                    "source_zip": zip_path.name,
                    "size_bytes": str(info.file_size or info.compress_size or 1),
                    "keep_raw": keep_raw,
                },
            )
            r.expire(f"job:{child_id}", JOB_TTL)
            r.sadd(f"case:{case_id}:jobs", child_id)
            r.expire(f"case:{case_id}:jobs", JOB_TTL)
            r.zadd(f"case:{case_id}:jobs:zs", {child_id: time.time()})
            r.expire(f"case:{case_id}:jobs:zs", JOB_TTL)

            # ── Extract entry and upload to MinIO ─────────────────────────────
            try:
                with zf.open(info) as src:
                    data = src.read()
                _put_with_retry(minio_client, MINIO_BUCKET, minio_key, data)
                r.hset(
                    f"job:{child_id}",
                    mapping={
                        "minio_object_key": minio_key,
                        "size_bytes": str(len(data)),
                        "status": "PENDING",
                    },
                )
            except Exception as exc:
                logger.error(
                    "[%s] Failed to extract/upload '%s': %s",
                    parent_job_id,
                    entry_rel,
                    exc,
                )
                r.hset(
                    f"job:{child_id}",
                    mapping={
                        "status": "FAILED",
                        "error": f"Extraction failed: {exc}",
                        "completed_at": datetime.now(UTC).isoformat(),
                    },
                )
                continue

            # ── Dispatch child process_artifact task ──────────────────────────
            app.send_task(
                "ingest.process_artifact",
                args=[child_id, case_id, minio_key, entry_rel],
                queue="ingest",
            )
            count += 1

    return count


def _is_fo_tar(path: Path) -> bool:
    """Return True if the file is a TAR archive (including .tar.gz, .tgz, .tar.bz2)."""
    try:
        return _tarfile.is_tarfile(str(path))
    except Exception:
        return False


def _expand_tar_into_child_jobs(
    parent_job_id: str,
    case_id: str,
    tar_path: Path,
    r: redis.Redis,
    keep_raw: str = "0",
) -> int:
    """
    Extract every file entry from a TAR archive and create individual child jobs.
    Mirrors _expand_zip_into_child_jobs() for .tar.gz / .tgz / .tar.bz2 archives.
    """
    minio_client = get_minio()
    count = 0

    try:
        tf = _tarfile.open(tar_path, "r:*")
    except Exception as exc:
        logger.error("[%s] Cannot open TAR archive: %s", parent_job_id, exc)
        return 0

    with tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            entry_rel = _safe_relative_path(member.name)
            if not entry_rel:
                logger.warning("[%s] Rejected unsafe tar entry: %r", parent_job_id, member.name)
                continue
            base_name = entry_rel.split("/")[-1]

            if not base_name or base_name.startswith("."):
                continue
            if base_name.lower() in _ZIP_SKIP_BASENAMES:
                continue
            if Path(base_name).suffix.lower() in _ZIP_SKIP_EXTS:
                continue

            child_id = uuid.uuid4().hex
            minio_key = f"cases/{case_id}/{child_id}/{entry_rel}"

            now = datetime.now(UTC).isoformat()
            r.hset(
                f"job:{child_id}",
                mapping={
                    "job_id": child_id,
                    "case_id": case_id,
                    "status": "UPLOADING",
                    "original_filename": entry_rel.encode("utf-8", errors="replace").decode(
                        "utf-8"
                    ),
                    "minio_object_key": minio_key,
                    "events_indexed": "0",
                    "error": "",
                    "plugin_used": "",
                    "plugin_stats": "{}",
                    "created_at": now,
                    "started_at": "",
                    "completed_at": "",
                    "task_id": "",
                    "source_zip": tar_path.name,
                    "size_bytes": str(member.size or 1),
                    "keep_raw": keep_raw,
                },
            )
            r.expire(f"job:{child_id}", JOB_TTL)
            r.sadd(f"case:{case_id}:jobs", child_id)
            r.expire(f"case:{case_id}:jobs", JOB_TTL)
            r.zadd(f"case:{case_id}:jobs:zs", {child_id: time.time()})
            r.expire(f"case:{case_id}:jobs:zs", JOB_TTL)

            try:
                fobj = tf.extractfile(member)
                if fobj is None:
                    raise ValueError("extractfile returned None (symlink or special file)")
                data = fobj.read()
                _put_with_retry(minio_client, MINIO_BUCKET, minio_key, data)
                r.hset(
                    f"job:{child_id}",
                    mapping={
                        "minio_object_key": minio_key,
                        "size_bytes": str(len(data)),
                        "status": "PENDING",
                    },
                )
            except Exception as exc:
                logger.error(
                    "[%s] Failed to extract/upload '%s' from TAR: %s",
                    parent_job_id,
                    entry_rel,
                    exc,
                )
                r.hset(
                    f"job:{child_id}",
                    mapping={
                        "status": "FAILED",
                        "error": f"TAR extraction failed: {exc}",
                        "completed_at": datetime.now(UTC).isoformat(),
                    },
                )
                continue

            app.send_task(
                "ingest.process_artifact",
                args=[child_id, case_id, minio_key, entry_rel],
                queue="ingest",
            )
            count += 1

    return count


@app.task(bind=True, name="ingest.maybe_run_detections", queue="ingest")
def maybe_run_detections(self, case_id: str, _attempts: int = 0):
    """Deferred detection runner — chains itself until the case is idle, then
    fires every library rule once. Triggered by job-completion hooks."""
    r = get_redis()
    if _case_has_active_jobs(r, case_id):
        if _attempts >= 60:  # safety cap — ~20 minutes max chain
            logger.warning(
                "[detections] case %s — gave up waiting (still active after 60 retries)", case_id
            )
            return {"status": "abandoned"}
        # Still ingesting — re-check in 20 s.
        maybe_run_detections.apply_async(
            args=[case_id], kwargs={"_attempts": _attempts + 1}, countdown=20
        )
        return {"status": "deferred", "attempt": _attempts + 1}
    # Idle — fire library rules + watchlist sweep in one pass.
    try:
        _run_library_rules(r, case_id)
        try:
            _run_watchlist(r, case_id)
        except Exception as exc:
            logger.warning("[watchlist] case %s — sweep failed: %s", case_id, exc)
    finally:
        # Release the schedule lock so the next ingest cycle can chain again.
        r.delete(rk.case_alert_run_lock(case_id))
    return {"status": "completed"}


def _run_watchlist(r: redis.Redis, case_id: str) -> None:
    """Evaluate every IOC watchlist entry against this case. Persists the
    matches under fo:watchlist_runs:{case_id} so the UI can surface them."""
    raw = r.hgetall("fo:watchlist") or {}
    if not raw:
        return
    entries = []
    for v in raw.values():
        try:
            entries.append(json.loads(v.decode() if isinstance(v, bytes) else v))
        except Exception:
            continue
    if not entries:
        return
    hits = []
    for e in entries:
        body = {
            "size": 0,
            "query": {
                "query_string": {
                    "query": e.get("query", ""),
                    "default_operator": "AND",
                    "fields": ["*"],
                    "allow_leading_wildcard": True,
                    "analyze_wildcard": True,
                }
            },
        }
        try:
            res = _es_search(f"fo-case-{case_id}-*", body)
            count = res.get("hits", {}).get("total", {}).get("value", 0)
        except Exception:
            count = 0
        if count > 0:
            hits.append(
                {
                    "id": e.get("id"),
                    "label": e.get("label"),
                    "kind": e.get("kind"),
                    "value": e.get("value"),
                    "query": e.get("query"),
                    "hits": count,
                }
            )
    run = {
        "ran_at": datetime.now(UTC).isoformat(),
        "checked": len(entries),
        "hits": hits,
        "auto": True,
    }
    r.set(f"fo:watchlist_runs:{case_id}", json.dumps(run))
    r.expire(f"fo:watchlist_runs:{case_id}", 7 * 86400)
    logger.info("[watchlist] case %s — %d entries, %d with hits", case_id, len(entries), len(hits))


@app.task(bind=True, name="ingest.process_artifact", queue="ingest")
def process_artifact(
    self,
    job_id: str,
    case_id: str,
    minio_object_key: str,
    original_filename: str,
) -> dict[str, Any]:
    """
    Main ingest task.

    Args:
        job_id: Unique job identifier (also the Celery task ID).
        case_id: Case this artifact belongs to.
        minio_object_key: Object key in MinIO (e.g., "cases/abc123/job123/Security.evtx").
        original_filename: Original uploaded filename.

    Returns:
        Job result dict with stats.
    """
    r = get_redis()
    work_dir = Path(tempfile.mkdtemp(prefix=f"fo_{job_id}_"))
    local_file: Path | None = None
    # Initialized before the try so the except/cleanup handlers never hit an
    # UnboundLocalError if an early step (cancellation hget, status update,
    # MinIO download) raises before these are assigned below.
    artifact_sha256: str = ""
    claimed_sha256: bool = False

    try:
        # Check for cancellation before we do any real work.
        # The API sets status=CANCELLED on pending jobs; this ensures the task
        # returns immediately even if it was already dequeued.
        if r.hget(f"job:{job_id}", "status") == "CANCELLED":
            logger.info("[%s] Job was cancelled — skipping", job_id)
            shutil.rmtree(work_dir, ignore_errors=True)
            return {"status": "CANCELLED"}

        update_job_status(
            r,
            job_id,
            status="RUNNING",
            started_at=datetime.now(UTC).isoformat(),
            task_id=self.request.id,
        )

        # ── 1. Download artifact from MinIO ──────────────────────────────────
        logger.info("[%s] Downloading %s from MinIO", job_id, minio_object_key)
        minio = get_minio()
        # SECURITY: reject any original_filename that would escape work_dir
        # (zip-slip / tar-slip / absolute paths / drive letters).
        safe_rel = _safe_relative_path(original_filename) or f"file-{job_id}"
        local_file = (work_dir / safe_rel).resolve()
        if (
            work_dir.resolve() not in local_file.parents
            and local_file != work_dir.resolve() / safe_rel
        ):
            raise RuntimeError(f"Unsafe download path resolved outside work_dir: {local_file}")
        local_file.parent.mkdir(parents=True, exist_ok=True)
        minio.fget_object(MINIO_BUCKET, minio_object_key, str(local_file))
        logger.info(
            "[%s] Downloaded to %s (%d bytes)", job_id, local_file, local_file.stat().st_size
        )

        # ── 1b. Idempotent re-ingest — skip artifacts already seen for this case ──
        # The bus is at-least-once and operators re-upload the same bundle; dedup
        # on artifact sha256 so a re-ingest of an identical file is a no-op.
        # Archives are NOT deduped here — they fan out into child jobs below, each
        # of which carries its own (per-entry) sha256 that IS deduped.
        artifact_sha256 = bus_emit.compute_sha256(local_file)
        claimed_sha256 = False
        if not (_is_fo_zip(local_file) or _is_fo_tar(local_file)):
            if bus_emit.mark_and_check_seen(r, case_id, artifact_sha256):
                skipped_at = datetime.now(UTC).isoformat()
                logger.info(
                    "[%s] Duplicate artifact sha256=%s — skipping re-ingest",
                    job_id,
                    artifact_sha256,
                )
                update_job_status(
                    r,
                    job_id,
                    status="SKIPPED",
                    artifact_sha256=artifact_sha256,
                    error="Duplicate of an already-ingested artifact "
                    "(same sha256) — skipped (idempotent re-ingest).",
                    completed_at=skipped_at,
                )
                return {
                    "status": "SKIPPED",
                    "reason": "duplicate_sha256",
                    "sha256": artifact_sha256,
                    "events_indexed": 0,
                }
            claimed_sha256 = True
            update_job_status(r, job_id, artifact_sha256=artifact_sha256)

        # ── 2. Detect MIME type ───────────────────────────────────────────────
        mime_type = detect_mime(local_file)
        logger.info("[%s] Detected MIME: %s", job_id, mime_type)
        update_job_status(r, job_id, mime_type=mime_type)

        # ── 2b. ZIP auto-expansion ────────────────────────────────────────────
        # When a ZIP arrives via S3 triage pull the API never sees it, so
        # _handle_zip_async() never runs. Intercept here and create one child
        # job per entry — identical behaviour to the direct-upload path.
        # This makes every individual artifact file visible to modules.
        if _is_fo_zip(local_file):
            logger.info("[%s] ZIP detected — expanding into child jobs", job_id)
            keep_raw = r.hget(f"job:{job_id}", "keep_raw") or "0"
            child_count = _expand_zip_into_child_jobs(
                job_id, case_id, local_file, r, keep_raw=keep_raw
            )
            completed_at = datetime.now(UTC).isoformat()
            update_job_status(
                r,
                job_id,
                status="COMPLETED",
                plugin_used="archive (expanded)",
                events_indexed="0",
                completed_at=completed_at,
            )
            logger.info("[%s] ZIP expanded into %d child jobs", job_id, child_count)
            return {"status": "COMPLETED", "events_indexed": 0, "child_jobs": child_count}

        if _is_fo_tar(local_file):
            logger.info("[%s] TAR archive detected — expanding into child jobs", job_id)
            keep_raw = r.hget(f"job:{job_id}", "keep_raw") or "0"
            child_count = _expand_tar_into_child_jobs(
                job_id, case_id, local_file, r, keep_raw=keep_raw
            )
            completed_at = datetime.now(UTC).isoformat()
            update_job_status(
                r,
                job_id,
                status="COMPLETED",
                plugin_used="archive (tar expanded)",
                events_indexed="0",
                completed_at=completed_at,
            )
            logger.info("[%s] TAR expanded into %d child jobs", job_id, child_count)
            return {"status": "COMPLETED", "events_indexed": 0, "child_jobs": child_count}

        # ── 3. Find matching plugin ───────────────────────────────────────────
        # Honour per-job plugin override stored at upload/reingest time.
        plugin_hint = r.hget(f"job:{job_id}", "plugin_hint") or ""
        if plugin_hint:
            plugin_class = _plugin_loader.get_plugin_by_name(plugin_hint)
            if plugin_class is None:
                logger.warning(
                    "[%s] plugin_hint=%r not found — falling back to auto-detect",
                    job_id,
                    plugin_hint,
                )
                plugin_class = _plugin_loader.get_plugin(local_file, mime_type)
        else:
            plugin_class = _plugin_loader.get_plugin(local_file, mime_type)
        if plugin_class is None:
            skipped_at = datetime.now(UTC).isoformat()
            update_job_status(
                r,
                job_id,
                status="SKIPPED",
                error=f"No plugin found for '{original_filename}' (mime: {mime_type}). "
                "Use a module to analyse this file type.",
                completed_at=skipped_at,
            )
            _index_artifact_doc(
                job_id,
                case_id,
                original_filename,
                "",
                mime_type,
                0,
                True,
                minio_object_key,
                skipped_at,
            )
            return

        update_job_status(r, job_id, plugin_used=plugin_class.PLUGIN_NAME)

        # ── 4. Run plugin ────────────────────────────────────────────────────
        from citadel_contracts import PluginContext

        ctx = PluginContext(
            case_id=case_id,
            job_id=job_id,
            source_file_path=local_file,
            source_minio_url=f"minio://{MINIO_BUCKET}/{minio_object_key}",
            logger=logger,
        )
        plugin = plugin_class(ctx)

        indexer = ESBulkIndexer(ELASTICSEARCH_URL)
        ingested_at = datetime.now(UTC).isoformat()
        source_url = f"minio://{MINIO_BUCKET}/{minio_object_key}"

        # Buffer parsed events for the events.parsed bus emit only when the flag
        # is on — otherwise stay None so the indexing path keeps zero overhead.
        bus_events: list[dict] | None = [] if bus_emit.bus_emit_enabled() else None

        try:
            plugin.setup()
            events_indexed, events_failed = _run_plugin_and_index(
                plugin, indexer, r, job_id, case_id, source_url, ingested_at, bus_events
            )
            stats = plugin.get_stats()
        except Exception as plugin_exc:
            plugin.teardown()
            # ── Plaso fallback ───────────────────────────────────────────────
            logger.warning(
                "[%s] Plugin '%s' failed (%s) — trying log2timeline fallback",
                job_id,
                plugin_class.PLUGIN_NAME,
                plugin_exc,
            )
            update_job_status(r, job_id, plugin_used="plaso (fallback)")
            try:
                from babel.plaso.plaso_plugin import PlasoPlugin

                fallback = PlasoPlugin.create_from_source(local_file, work_dir, ctx)
                fallback.setup()
                events_indexed, events_failed = _run_plugin_and_index(
                    fallback, indexer, r, job_id, case_id, source_url, ingested_at, bus_events
                )
                fallback.teardown()
                stats = fallback.get_stats()
                stats["fallback_reason"] = str(plugin_exc)
            except Exception as plaso_exc:
                logger.error("[%s] Plaso fallback also failed: %s", job_id, plaso_exc)
                # ── Strings last resort ──────────────────────────────────────
                logger.warning("[%s] Trying strings fallback as last resort", job_id)
                update_job_status(r, job_id, plugin_used="strings (fallback)")
                try:
                    from babel.strings_fallback.strings_fallback_plugin import StringsFallbackPlugin

                    strings_fb = StringsFallbackPlugin(ctx)
                    strings_fb.setup()
                    events_indexed, events_failed = _run_plugin_and_index(
                        strings_fb, indexer, r, job_id, case_id, source_url, ingested_at, bus_events
                    )
                    strings_fb.teardown()
                    stats = strings_fb.get_stats()
                    stats["fallback_reason"] = str(plugin_exc)
                except Exception as strings_exc:
                    logger.error("[%s] Strings fallback also failed: %s", job_id, strings_exc)
                    raise plugin_exc  # surface the original error
        else:
            plugin.teardown()

        # ── 5. Mark complete ─────────────────────────────────────────────────
        completed_at = datetime.now(UTC).isoformat()
        result = {
            "status": "COMPLETED",
            "events_indexed": events_indexed,
            "events_failed": events_failed,
            "plugin_stats": stats,
            "completed_at": completed_at,
        }
        update_job_status(
            r,
            job_id,
            **{
                k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                for k, v in result.items()
            },
        )
        plugin_name = getattr(plugin, "PLUGIN_NAME", "")
        _index_artifact_doc(
            job_id,
            case_id,
            original_filename,
            plugin_name,
            mime_type,
            events_indexed,
            False,
            minio_object_key,
            completed_at,
        )
        logger.info("[%s] Completed: %d events indexed", job_id, events_indexed)

        # ── 5b. Bus emit → events.parsed (feature-flagged side channel) ───────
        # Publish the parsed ForensicEvents so Rosetta can normalize them to ECS.
        # No-op when BUS_EMIT_ENABLED is off; never fails the job (see bus_emit).
        if bus_events:
            raw_co = r.hget(f"case:{case_id}", "company")
            company = (raw_co.decode() if isinstance(raw_co, bytes) else raw_co) or None
            bus_emit.emit_events_parsed(
                r, bus_events, case_id=case_id, job_id=job_id, company=company
            )
        try:
            _auto_run_alert_rules(r, case_id)
        except Exception as exc:
            logger.warning("[%s] Alert rule auto-run failed: %s", job_id, exc)
        return result

    except Exception as exc:
        logger.exception("[%s] Failed: %s", job_id, exc)
        # Release the dedup claim so a genuine retry of this artifact isn't
        # permanently skipped (we only want to skip *successful* prior ingests).
        if claimed_sha256:
            bus_emit.forget_seen(r, case_id, artifact_sha256)
        update_job_status(
            r, job_id, status="FAILED", error=str(exc), completed_at=datetime.now(UTC).isoformat()
        )
        # Re-raise as RuntimeError so the IPC back to the Celery main process
        # never requires importing custom exception classes (e.g. PluginFatalError
        # from babel.base_plugin), which aren't on the main process's sys.path.
        raise RuntimeError(str(exc)) from None

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


@app.task(bind=True, name="ingest.s3_transfer", queue="ingest")
def s3_transfer(
    self,
    job_id: str,
    case_id: str,
    s3_config_key: str,
    s3_key: str,
    filename: str,
) -> None:
    """
    Stream a file from an external S3 bucket into internal MinIO, then
    dispatch process_artifact.  Runs entirely in the background — the HTTP
    request that triggered this returns immediately with a PENDING job ID.

    Job status lifecycle:
        PENDING  (created by API)
        UPLOADING  (this task: S3 → MinIO streaming)
        PENDING  (MinIO ready, waiting for process_artifact to start)
        RUNNING → COMPLETED / FAILED  (process_artifact)
    """
    r = get_redis()
    update_job_status(
        r,
        job_id,
        status="UPLOADING",
        started_at=datetime.now(UTC).isoformat(),
        task_id=self.request.id,
    )

    # ── 1. Load S3 config from Redis ─────────────────────────────────────────
    cfg_raw = r.get(s3_config_key)
    if not cfg_raw:
        update_job_status(
            r,
            job_id,
            status="FAILED",
            error="S3 configuration not found — was it removed from Settings?",
            completed_at=datetime.now(UTC).isoformat(),
        )
        return

    cfg = json.loads(cfg_raw)

    # ── 2. Build external S3 client ───────────────────────────────────────────
    from minio import Minio

    endpoint = cfg.get("endpoint", "")
    for proto in ("https://", "http://"):
        if endpoint.lower().startswith(proto):
            endpoint = endpoint[len(proto) :]
            break

    try:
        ext_client = Minio(
            endpoint,
            access_key=cfg.get("access_key", ""),
            secret_key=cfg.get("secret_key", ""),
            secure=cfg.get("use_ssl", True),
            region=cfg.get("region") or None,
        )

        # ── 3. Stream external S3 → internal MinIO (no temp file) ────────────
        stat = ext_client.stat_object(cfg["bucket"], s3_key)
        file_size = stat.size
        minio_key = f"cases/{case_id}/{job_id}/{filename}"

        logger.info(
            "[%s] S3 transfer: %s/%s → MinIO/%s (%d bytes)",
            job_id,
            cfg["bucket"],
            s3_key,
            minio_key,
            file_size,
        )

        response = None
        try:
            response = ext_client.get_object(cfg["bucket"], s3_key)
            int_client = get_minio()
            if not int_client.bucket_exists(MINIO_BUCKET):
                int_client.make_bucket(MINIO_BUCKET)
            int_client.put_object(
                MINIO_BUCKET,
                minio_key,
                response,
                length=file_size,
                part_size=10 * 1024 * 1024,  # 10 MB multipart chunks
            )
        finally:
            if response is not None:
                try:
                    response.close()
                    response.release_conn()
                except Exception:
                    pass

        logger.info("[%s] S3 transfer complete — %d bytes written", job_id, file_size)

        # ── 4. Update job and dispatch ingest ─────────────────────────────────
        update_job_status(r, job_id, minio_object_key=minio_key, status="PENDING")
        app.send_task(
            "ingest.process_artifact",
            args=[job_id, case_id, minio_key, filename],
            queue="ingest",
        )

    except Exception as exc:
        logger.exception("[%s] S3 transfer failed: %s", job_id, exc)
        update_job_status(
            r,
            job_id,
            status="FAILED",
            error=f"S3 transfer failed: {exc}",
            completed_at=datetime.now(UTC).isoformat(),
        )
        raise RuntimeError(str(exc)) from None


def _index_artifact_doc(
    job_id: str,
    case_id: str,
    filename: str,
    plugin_used: str,
    mime_type: str,
    events_indexed: int,
    skipped: bool,
    minio_key: str,
    completed_at: str,
) -> None:
    """Write a slim artifact doc to the fo-artifacts ES index."""
    doc = {
        "case_id": case_id,
        "job_id": job_id,
        "filename": _strip_surrogates(str(filename or "")),
        "plugin_used": plugin_used,
        "mime_type": mime_type,
        "events_indexed": events_indexed,
        "skipped": skipped,
        "minio_key": _strip_surrogates(str(minio_key or "")),
        "completed_at": completed_at,
    }
    url = f"{ELASTICSEARCH_URL}/fo-artifacts/_doc/{job_id}"
    data = json.dumps(doc).encode("utf-8", errors="replace")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception as exc:
        logger.warning("[%s] Failed to index artifact doc: %s", job_id, exc)


def _is_valid_timestamp(ts: str) -> bool:
    """Return True if ts is a parseable ISO 8601 timestamp."""
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


# Tracks how many events per plugin failed the contract — surfaced in stats.
_validation_warnings: dict[str, int] = {}


def _looks_like_stringified_dict(s: str) -> bool:
    """Heuristic — a 'message' that is just str(some_dict) is lazy."""
    if not isinstance(s, str) or len(s) < 8:
        return False
    s_strip = s.strip()
    return (s_strip.startswith("{'") and s_strip.endswith("}")) or (
        s_strip.startswith('{"') and s_strip.endswith("}") and "': '" in s_strip
    )


def _validate_event(event: dict, plugin_name: str, job_id: str) -> dict:
    """
    Enforce the event contract. Mutates and returns the event.

    Rules:
      1. message must be a non-empty string (loader fills generic if missing).
      2. message must not be a naive stringified dict (lazy parsing).
      3. For STRUCTURED_ARTIFACTS, raw must be a non-empty dict.
      4. Drop None values in enrichment dicts so ES mapping stays clean.
    """
    from citadel_contracts import STRUCTURED_ARTIFACTS

    art_type = event.get("artifact_type", "generic")
    msg = event.get("message", "")

    if not isinstance(msg, str) or not msg.strip():
        # Build a fallback message from artifact sub-object so timeline has
        # something readable rather than blank rows.
        sub = event.get(art_type) if isinstance(event.get(art_type), dict) else None
        if sub:
            head = ", ".join(f"{k}={v}" for k, v in list(sub.items())[:3] if v)
            event["message"] = f"{art_type}: {head}" if head else art_type
        else:
            event["message"] = art_type
        _validation_warnings[f"{plugin_name}:no_message"] = (
            _validation_warnings.get(f"{plugin_name}:no_message", 0) + 1
        )
    elif _looks_like_stringified_dict(msg):
        _validation_warnings[f"{plugin_name}:stringified_message"] = (
            _validation_warnings.get(f"{plugin_name}:stringified_message", 0) + 1
        )

    raw = event.get("raw")
    if not isinstance(raw, dict) or not raw:
        # Synthesize raw so we never lose data. Try art_type sub-object first,
        # then scan any other plugin-specific dict (e.g. linux_triage uses
        # "linux_process" when art_type is "process").
        STANDARD = {
            "timestamp",
            "timestamp_desc",
            "message",
            "artifact_type",
            "host",
            "user",
            "process",
            "network",
            "raw",
            "tags",
            "analyst_note",
            "is_flagged",
            "mitre",
            "fo_id",
            "case_id",
            "ingest_job_id",
            "source_file",
            "ingested_at",
        }
        sub = event.get(art_type) if isinstance(event.get(art_type), dict) else None
        if not sub:
            for k, v in event.items():
                if k in STANDARD or not isinstance(v, dict) or not v:
                    continue
                sub = v
                break
        if sub:
            event["raw"] = dict(sub)
        elif art_type in STRUCTURED_ARTIFACTS:
            _validation_warnings[f"{plugin_name}:no_raw"] = (
                _validation_warnings.get(f"{plugin_name}:no_raw", 0) + 1
            )

    for key in ("host", "user", "process", "network"):
        v = event.get(key)
        if isinstance(v, dict):
            event[key] = {k: vv for k, vv in v.items() if vv not in (None, "", [])}
    return event


# Upper bound on how many parsed events we buffer for the bus emit. A single
# artifact can yield millions of events (MFT, EVTX); we cap the in-memory copy so
# bus emit can't OOM the worker. Beyond the cap, ES indexing still gets every
# event — only the bus side-channel is truncated (and logs a warning).
BUS_EMIT_MAX_EVENTS = int(os.getenv("BUS_EMIT_MAX_EVENTS", "50000"))


def _run_plugin_and_index(
    plugin,
    indexer: ESBulkIndexer,
    r: redis.Redis,
    job_id: str,
    case_id: str,
    source_url: str,
    ingested_at: str,
    bus_events: list[dict] | None = None,
) -> tuple[int, int]:
    """Drive a plugin's parse() generator and bulk-index all events. Returns (indexed, failed).

    When ``bus_events`` is a list, parsed events are also appended to it (up to
    BUS_EMIT_MAX_EVENTS) so the caller can publish them to events.parsed. Passing
    None (the default) leaves the original behaviour untouched.
    """
    batch: list[dict] = []
    events_indexed = 0
    events_failed = 0
    plugin_name = getattr(plugin, "PLUGIN_NAME", "unknown")
    for raw_event in plugin.parse():
        try:
            event = _merge_base_fields(raw_event, case_id, job_id, source_url, ingested_at)
            event = _validate_event(event, plugin_name, job_id)
            batch.append(event)
            if bus_events is not None and len(bus_events) < BUS_EMIT_MAX_EVENTS:
                bus_events.append(event)
        except Exception as exc:
            events_failed += 1
            logger.warning(
                "[%s] Skipped malformed event from plugin %s: %s", job_id, plugin.PLUGIN_NAME, exc
            )
        if len(batch) >= BULK_SIZE:
            indexer.bulk_index(case_id, batch)
            events_indexed += len(batch)
            batch = []
            update_job_status(r, job_id, events_indexed=str(events_indexed), progress_pct="")
    if batch:
        indexer.bulk_index(case_id, batch)
        events_indexed += len(batch)
    # Snapshot + reset the per-process counter so each job reports its own deltas.
    plugin_warnings = {
        k: v for k, v in _validation_warnings.items() if k.startswith(f"{plugin_name}:")
    }
    for k in plugin_warnings:
        _validation_warnings.pop(k, None)
    if plugin_warnings:
        logger.info("[%s] plugin %s validation warnings: %s", job_id, plugin_name, plugin_warnings)
    return events_indexed, events_failed


def _merge_base_fields(
    event: dict,
    case_id: str,
    job_id: str,
    source_minio_url: str,
    ingested_at: str,
) -> dict:
    """Ensure all base ForensicEvent fields are present."""
    from citadel_contracts import classify_os

    base = {
        "fo_id": str(uuid.uuid4()),
        "case_id": case_id,
        "ingest_job_id": job_id,
        "source_file": source_minio_url,
        "ingested_at": ingested_at,
        "artifact_type": "generic",
        "os": "cross",
        # Default to ingested_at — plugins with real timestamps override this.
        # Using "" would cause ES to reject the doc (date field rejects empty strings).
        "timestamp": ingested_at,
        "timestamp_desc": "Ingestion Time",
        "message": "",
        "tags": [],
        "analyst_note": "",
        "is_flagged": False,
        "mitre": {},
        "host": {},
        "user": {},
        "process": {},
        "network": {},
        "raw": {},
    }
    base.update(event)
    # Set OS classification based on final artifact_type. Plugins may override
    # by setting "os" explicitly (e.g. evtx triggered from a macOS host).
    if not event.get("os"):
        base["os"] = classify_os(base.get("artifact_type", "generic"))
    # Deterministic ID for ES deduplication — re-ingesting the same file won't create duplicates.
    # Respect any fo_id a plugin has already set (e.g. registry plugin uses uuid4 per-event).
    if not event.get("fo_id"):
        _fp = (
            f"{case_id}|{event.get('timestamp', ingested_at)}"
            f"|{event.get('message', '')}"
            f"|{event.get('artifact_type', 'generic')}"
            f"|{event.get('host', {}).get('hostname', '')}"
            f"|{event.get('user', {}).get('name', '')}"
        )
        base["fo_id"] = hashlib.sha256(_fp.encode()).hexdigest()[:32]
    # Coerce falsy timestamps (empty string, None) from plugins to ingested_at
    # so the event is never rejected by the ES date mapping.
    if not base.get("timestamp"):
        base["timestamp"] = ingested_at
        if not base.get("timestamp_desc") or base["timestamp_desc"] == "Unknown":
            base["timestamp_desc"] = "Ingestion Time"
    elif not _is_valid_timestamp(str(base["timestamp"])):
        logger.debug("Invalid timestamp %r, falling back to ingested_at", base["timestamp"])
        base["timestamp"] = ingested_at
        base["timestamp_desc"] = "Ingestion Time (coerced)"
    # Ensure every event has a raw representation stored in ES.
    # Plugins that set raw take precedence; for the rest we copy the artifact
    # sub-object directly so structure is preserved (the ES mapping marks
    # raw as enabled:false → stored in _source, never indexed).
    if not base.get("raw"):
        art_type = base.get("artifact_type", "generic")
        art_data = base.get(art_type) if art_type != "generic" else None
        if art_data and isinstance(art_data, dict) and art_data:
            base["raw"] = dict(art_data)
    return base
