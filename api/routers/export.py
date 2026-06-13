"""Case data export — CSV, chain of custody, full .citadel archive."""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import re
import tarfile
import tempfile
import time
import urllib.request
import uuid
from datetime import UTC, datetime

import redis_keys as rk
from auth.dependencies import require_admin, require_case_access
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from license.gate import require_feature
from pydantic import BaseModel
from services import jobs as job_svc
from services.cases import get_case, update_case
from services.elasticsearch import _request as es_req

from config import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["export"])

ARCHIVE_VERSION = "1"
ARCHIVE_FORMAT = "citadel-archive-v1"


def _strip_http(url: str) -> str:
    for pfx in ("https://", "http://"):
        if url.lower().startswith(pfx):
            return url[len(pfx) :]
    return url


def _make_minio(
    endpoint: str, access_key: str, secret_key: str, use_ssl: bool = True, region: str | None = None
):
    from minio import Minio

    return Minio(
        _strip_http(endpoint),
        access_key=access_key,
        secret_key=secret_key,
        secure=use_ssl,
        region=region,
    )


def _archive_client():
    """Read archive S3 settings from Redis and return (Minio client, bucket)."""
    r = get_redis()
    raw = r.get(rk.ARCHIVE_SETTINGS)
    if not raw:
        raise HTTPException(
            status_code=400, detail="Archive S3 not configured. Set it up in Settings → Archiving."
        )
    cfg = json.loads(raw)
    endpoint = cfg.get("s3_endpoint", "")
    bucket = cfg.get("s3_bucket", "")
    if not endpoint or not bucket:
        raise HTTPException(
            status_code=400, detail="Archive S3 not configured. Set it up in Settings → Archiving."
        )
    return _make_minio(
        endpoint,
        cfg.get("s3_access_key", ""),
        cfg.get("s3_secret_key", ""),
        bool(cfg.get("s3_use_ssl", True)),
        cfg.get("s3_region") or None,
    ), bucket


# ── Archive settings model ─────────────────────────────────────────────────────


class ArchiveSettingsIn(BaseModel):
    auto_archive_enabled: bool = False
    auto_archive_days: int = 14
    auto_export_enabled: bool = False
    s3_endpoint: str = ""
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_bucket: str = ""
    s3_use_ssl: bool = True
    s3_vendor: str = ""
    s3_region: str = ""


@router.get(
    "/admin/archive-settings",
    dependencies=[Depends(require_admin), Depends(require_feature("s3_archive"))],
)
def get_archive_settings():
    r = get_redis()
    raw = r.get(rk.ARCHIVE_SETTINGS)
    cfg = json.loads(raw) if raw else {}
    return {
        "auto_archive_enabled": cfg.get("auto_archive_enabled", False),
        "auto_archive_days": int(cfg.get("auto_archive_days", 14)),
        "auto_export_enabled": cfg.get("auto_export_enabled", False),
        "s3_endpoint": cfg.get("s3_endpoint", ""),
        "s3_access_key": cfg.get("s3_access_key", ""),
        "s3_secret_key_set": bool(cfg.get("s3_secret_key")),
        "s3_bucket": cfg.get("s3_bucket", ""),
        "s3_use_ssl": cfg.get("s3_use_ssl", True),
        "s3_vendor": cfg.get("s3_vendor", ""),
        "s3_region": cfg.get("s3_region", ""),
    }


@router.put(
    "/admin/archive-settings",
    dependencies=[Depends(require_admin), Depends(require_feature("s3_archive"))],
)
def update_archive_settings(body: ArchiveSettingsIn):
    r = get_redis()
    existing_raw = r.get(rk.ARCHIVE_SETTINGS)
    existing = json.loads(existing_raw) if existing_raw else {}
    cfg = body.model_dump()
    if not cfg["s3_secret_key"]:
        cfg["s3_secret_key"] = existing.get("s3_secret_key", "")
    r.set(rk.ARCHIVE_SETTINGS, json.dumps(cfg))
    return get_archive_settings()


@router.post(
    "/admin/archive-settings/test",
    dependencies=[Depends(require_admin), Depends(require_feature("s3_archive"))],
)
def test_archive_s3():
    """Test connection to the configured archive S3 bucket."""
    import itertools

    try:
        client, bucket = _archive_client()
        objects = list(itertools.islice(client.list_objects(bucket), 5))
        return {"ok": True, "message": f"Connected. Found {len(objects)} object(s) in sample."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Connection test failed: {exc}")


@router.get(
    "/admin/archive-s3/browse",
    dependencies=[Depends(require_admin), Depends(require_feature("s3_archive"))],
)
def browse_archive_s3(prefix: str = "", delimiter: str = "/"):
    """Browse the archive S3 bucket — lists .citadel files and virtual directories."""
    try:
        client, bucket = _archive_client()
        objects = client.list_objects(bucket, prefix=prefix, delimiter=delimiter)
        files, dirs = [], []
        for obj in objects:
            if obj.is_dir:
                dirs.append({"key": obj.object_name, "is_dir": True})
            else:
                files.append(
                    {
                        "key": obj.object_name,
                        "size": obj.size,
                        "modified": obj.last_modified.isoformat() if obj.last_modified else None,
                        "is_dir": False,
                    }
                )
        return {"dirs": dirs, "files": files, "prefix": prefix}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Browse failed: {exc}")


@router.post(
    "/cases/import/archive-s3",
    dependencies=[Depends(require_admin), Depends(require_feature("s3_archive"))],
)
def import_archive_from_s3(body: dict):
    """Stream a .citadel file from the archive S3 bucket and import it as a new case."""
    s3_key = body.get("key", "")
    if not s3_key:
        raise HTTPException(status_code=400, detail="key is required")
    try:
        client, bucket = _archive_client()
        response = client.get_object(bucket, s3_key)
        data = response.read()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"S3 download failed: {exc}")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".citadel.tar.gz")
    try:
        os.write(tmp_fd, data)
        os.close(tmp_fd)
        result = _import_archive_file(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return result


# ── CSV export ────────────────────────────────────────────────────────────────


@router.get(
    "/cases/{case_id}/export/csv",
    dependencies=[Depends(require_feature("export")), Depends(require_case_access)],
)
def export_csv(case_id: str, artifact_type: str = "", flagged_only: bool = False, q: str = ""):
    """Export case events as CSV (max 10 000 rows)."""
    idx = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"
    must = []
    if q:
        safe_q = q[:512]
        must.append({"query_string": {"query": safe_q, "default_operator": "AND", "lenient": True}})
    if flagged_only:
        must.append({"term": {"is_flagged": True}})
    body = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"timestamp": "asc"}],
        "size": 10000,
        "_source": [
            "timestamp",
            "artifact_type",
            "message",
            "host",
            "user",
            "is_flagged",
            "tags",
            "analyst_note",
        ],
    }
    try:
        resp = es_req("POST", f"/{idx}/_search", body)
    except Exception as exc:
        logger.warning("ES query failed for CSV export (case %s): %s", case_id, exc)
        resp = {"hits": {"hits": []}}

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        ["timestamp", "artifact_type", "host", "user", "message", "flagged", "tags", "analyst_note"]
    )
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        host = s.get("host") or {}
        user = s.get("user") or {}
        w.writerow(
            [
                s.get("timestamp", ""),
                s.get("artifact_type", ""),
                host.get("hostname", "") if isinstance(host, dict) else host,
                user.get("name", "") if isinstance(user, dict) else user,
                s.get("message", ""),
                s.get("is_flagged", False),
                ",".join(s.get("tags") or []),
                s.get("analyst_note", ""),
            ]
        )
    buf.seek(0)
    name = f"case-{case_id[:8]}-{artifact_type or 'all'}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}"},
    )


# ── Chain of custody ──────────────────────────────────────────────────────────


@router.get(
    "/cases/{case_id}/chain-of-custody",
    dependencies=[Depends(require_feature("export")), Depends(require_case_access)],
)
def chain_of_custody(case_id: str):
    """
    Return a chain of custody document listing all ingested artifacts with
    SHA-256 hashes, sizes, ingest timestamps, and processing provenance.

    Suitable for inclusion in legal/forensic case files.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    job_ids = job_svc.list_case_job_ids(case_id)
    artifacts = []
    for jid in job_ids:
        j = job_svc.get_job(jid)
        if not j:
            continue
        artifacts.append(
            {
                "job_id": j.get("job_id", ""),
                "filename": j.get("original_filename", ""),
                "source_archive": j.get("source_zip", ""),
                "sha256": j.get("sha256", ""),
                "size_bytes": j.get("size_bytes", ""),
                "status": j.get("status", ""),
                "plugin_used": j.get("plugin_used", ""),
                "events_indexed": j.get("events_indexed", 0),
                "received_at": j.get("created_at", ""),
                "processing_started": j.get("started_at", ""),
                "processing_done": j.get("completed_at", ""),
                "storage_key": j.get("minio_object_key", ""),
            }
        )

    artifacts.sort(key=lambda a: a.get("received_at") or "")

    return {
        "document_type": "chain_of_custody",
        "version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "case_id": case_id,
        "case_name": case.get("name", ""),
        "case_status": case.get("status", ""),
        "case_created_at": case.get("created_at", ""),
        "analyst": case.get("analyst", ""),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "integrity_note": (
            "SHA-256 hashes are computed server-side from the staging file "
            "before transfer to object storage. An empty sha256 field means "
            "the artifact was ingested before integrity tracking was enabled."
        ),
    }


# ── ES scroll helper ──────────────────────────────────────────────────────────


def _scroll_all_events(case_id: str):
    """Yield every ES source document for the case using the scroll API."""
    idx = f"fo-case-{case_id}-*"
    body = {"query": {"match_all": {}}, "size": 1000, "sort": ["_doc"]}
    try:
        resp = es_req("POST", f"/{idx}/_search?scroll=2m", body)
    except Exception as exc:
        logger.warning("ES scroll init failed for case %s: %s", case_id, exc)
        return

    scroll_id = resp.get("_scroll_id")
    hits = resp.get("hits", {}).get("hits", [])
    while hits:
        for h in hits:
            yield h["_source"]
        if not scroll_id:
            break
        try:
            resp = es_req("POST", "/_search/scroll", {"scroll": "2m", "scroll_id": scroll_id})
        except Exception as exc:
            logger.warning("ES scroll continuation failed for case %s: %s", case_id, exc)
            break
        scroll_id = resp.get("_scroll_id")
        hits = resp.get("hits", {}).get("hits", [])

    if scroll_id:
        try:
            es_req("DELETE", "/_search/scroll", {"scroll_id": scroll_id})
        except Exception:
            pass


# ── Full archive export ───────────────────────────────────────────────────────


def _build_archive(case_id: str, tmp_path: str) -> int:
    """Write a .citadel tar.gz to tmp_path. Returns total event count."""
    r = get_redis()
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    job_ids = job_svc.list_case_job_ids(case_id)
    jobs = [j for j in (job_svc.get_job(jid) for jid in job_ids) if j]

    notes_raw = r.hgetall(rk.case_notes(case_id)) or {}
    alert_raw = r.get(rk.case_alert_rules(case_id))
    search_raw = r.get(rk.case_saved_searches(case_id))

    alert_rules = json.loads(alert_raw) if alert_raw else []
    saved_searches = json.loads(search_raw) if search_raw else []

    event_count = 0

    with tarfile.open(tmp_path, "w:gz", compresslevel=6) as tar:

        def _add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))

        _add("case.json", json.dumps(case, indent=2).encode())
        _add("jobs.json", json.dumps(jobs, indent=2).encode())
        _add("notes.json", json.dumps(dict(notes_raw), indent=2).encode())
        _add("alert_rules.json", json.dumps(alert_rules, indent=2).encode())
        _add("saved_searches.json", json.dumps(saved_searches, indent=2).encode())

        # Events: compressed NDJSON (one JSON object per line, gzip-9)
        ev_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=ev_buf, mode="wb", compresslevel=9) as gz:
            for ev in _scroll_all_events(case_id):
                gz.write((json.dumps(ev, separators=(",", ":")) + "\n").encode())
                event_count += 1
        _add("events.ndjson.gz", ev_buf.getvalue())

        manifest = {
            "version": ARCHIVE_VERSION,
            "format": ARCHIVE_FORMAT,
            "case_id": case_id,
            "case_name": case.get("name", ""),
            "exported_at": datetime.now(UTC).isoformat(),
            "event_count": event_count,
            "job_count": len(jobs),
        }
        _add("manifest.json", json.dumps(manifest, indent=2).encode())

    return event_count


@router.get(
    "/cases/{case_id}/export/archive",
    dependencies=[Depends(require_feature("export")), Depends(require_case_access)],
)
def export_archive(case_id: str):
    """
    Export complete case data as a .citadel archive (gzip tar).

    Includes: case metadata, artifact records with SHA-256 hashes, investigator
    notes, alert rules, saved searches, and ALL timeline events as compressed
    NDJSON. Suitable for long-term storage and cross-instance transfer.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    safe = re.sub(r"[^\w\-]", "_", case.get("name", case_id))[:40]
    fname = f"case-{safe}.citadel"

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".citadel.tar.gz")
    os.close(tmp_fd)

    try:
        _build_archive(case_id, tmp_path)
    except HTTPException:
        raise
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Export failed: {exc}")

    def _stream():
        try:
            with open(tmp_path, "rb") as f:
                while chunk := f.read(64 * 1024):
                    yield chunk
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return StreamingResponse(
        _stream(),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Full archive import ───────────────────────────────────────────────────────


def _bulk_index_events(case_id: str, events_gz: bytes) -> int:
    """Bulk-index events from gzip-compressed NDJSON into Elasticsearch."""
    from config import settings

    es_url = settings.ELASTICSEARCH_URL
    count = 0          # docs actually indexed (excludes per-item failures)
    failed = 0         # docs ES rejected
    lines: list[str] = []
    pending = 0        # docs in the current (unflushed) batch

    def _flush():
        nonlocal count, failed, pending
        if not lines:
            return
        batch = pending
        body = ("\n".join(lines) + "\n").encode()
        req = urllib.request.Request(
            f"{es_url}/_bulk",
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read() or b"{}")
            # ES _bulk returns HTTP 200 even when individual docs fail; the
            # top-level "errors" flag and per-item status reveal real failures.
            if resp.get("errors"):
                batch_failed = 0
                for item in resp.get("items", []):
                    op = next(iter(item.values()), {}) if item else {}
                    if op.get("error") or op.get("status", 200) >= 400:
                        batch_failed += 1
                failed += batch_failed
                count += batch - batch_failed
                logger.warning("Bulk index: %d of %d docs failed", batch_failed, batch)
            else:
                count += batch
        except Exception as exc:
            failed += batch
            logger.warning("Bulk index flush failed (%d docs lost): %s", batch, exc)
        lines.clear()
        pending = 0

    with gzip.GzipFile(fileobj=io.BytesIO(events_gz)) as gz:
        for raw in gz:
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except Exception:
                continue
            ev["case_id"] = case_id
            artifact_type = ev.get("artifact_type", "unknown")
            idx = f"fo-case-{case_id}-{artifact_type}"
            lines.append(json.dumps({"index": {"_index": idx}}))
            lines.append(json.dumps(ev, separators=(",", ":")))
            pending += 1
            if len(lines) >= 2000:
                _flush()

    _flush()
    if failed:
        logger.warning("Bulk index for case %s: %d indexed, %d failed", case_id, count, failed)
    return count


def _import_archive_file(tmp_path: str) -> dict:
    """Parse a .citadel tar.gz at tmp_path, create a new case, and return result dict."""
    try:
        tf = tarfile.open(tmp_path, "r:gz")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid archive: {exc}")

    def _read(name: str) -> bytes:
        try:
            m = tf.getmember(name)
            f = tf.extractfile(m)
            return f.read() if f else b""
        except KeyError:
            return b""

    with tf:
        manifest_raw = _read("manifest.json")
        if not manifest_raw:
            raise HTTPException(
                status_code=400, detail="Not a valid .citadel archive (missing manifest.json)"
            )
        manifest = json.loads(manifest_raw)
        if manifest.get("format") != ARCHIVE_FORMAT:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported archive format: {manifest.get('format')}",
            )
        case_data = json.loads(_read("case.json") or b"{}")
        jobs_data = json.loads(_read("jobs.json") or b"[]")
        notes_data = json.loads(_read("notes.json") or b"{}")
        alert_rules = json.loads(_read("alert_rules.json") or b"[]")
        saved_searches = json.loads(_read("saved_searches.json") or b"[]")
        events_gz = _read("events.ndjson.gz")

    r = get_redis()
    new_case_id = uuid.uuid4().hex[:12]
    now = datetime.now(UTC).isoformat()

    r.hset(
        f"case:{new_case_id}",
        mapping={
            "case_id": new_case_id,
            "name": case_data.get("name", f"Imported {now[:10]}"),
            "description": case_data.get("description", ""),
            "analyst": case_data.get("analyst", ""),
            "status": case_data.get("status", "active"),
            "created_at": now,
            "updated_at": now,
            "tags": json.dumps(case_data.get("tags") or []),
        },
    )
    r.sadd("cases:all", new_case_id)

    if notes_data.get("body"):
        r.hset(rk.case_notes(new_case_id), mapping={"body": notes_data["body"], "updated_at": now})
    if alert_rules:
        r.set(rk.case_alert_rules(new_case_id), json.dumps(alert_rules))
    if saved_searches:
        r.set(rk.case_saved_searches(new_case_id), json.dumps(saved_searches))

    for job in jobs_data:
        jid = job.get("job_id")
        if not jid:
            continue
        job_copy = {k: str(v) for k, v in job.items()}
        job_copy["case_id"] = new_case_id
        r.hset(f"job:{jid}", mapping=job_copy)
        r.expire(f"job:{jid}", job_svc.JOB_TTL)
        r.sadd(f"case:{new_case_id}:jobs", jid)
        r.zadd(f"case:{new_case_id}:jobs:zs", {jid: time.time()})

    event_count = 0
    if events_gz:
        try:
            event_count = _bulk_index_events(new_case_id, events_gz)
        except Exception as exc:
            logger.error("Event re-indexing failed for import: %s", exc)

    return {
        "case_id": new_case_id,
        "case_name": case_data.get("name", ""),
        "events_imported": event_count,
        "jobs_restored": len(jobs_data),
        "original_case_id": manifest.get("case_id"),
        "original_exported": manifest.get("exported_at"),
    }


@router.post("/cases/import/archive")
async def import_archive(file: UploadFile = File(...)):
    """Import a .citadel archive uploaded from the browser."""
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".citadel.tar.gz")
    os.close(tmp_fd)
    try:
        with open(tmp_path, "wb") as out:
            while chunk := await file.read(4 * 1024 * 1024):
                out.write(chunk)
        return _import_archive_file(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── Archive restore helper ─────────────────────────────────────────────────────


def _restore_archive_into_case(case_id: str, tf: tarfile.TarFile, pre_index_hook=None) -> dict:
    """Restore archive contents into an existing case. Returns stats dict.

    All archive members are read and parsed (validated) up front. ``pre_index_hook``
    (if given) is invoked only AFTER that validation succeeds and immediately
    BEFORE any data is written/indexed — used by the restore endpoint to delete
    the old indices only once the archive is known-good, so a corrupt or
    unreadable archive can never wipe an existing case.
    """

    def _read(name):
        try:
            m = tf.getmember(name)
            f = tf.extractfile(m)
            return f.read() if f else b""
        except KeyError:
            return b""

    r = get_redis()
    now = datetime.now(UTC).isoformat()
    # Read + parse everything first; a parse error here raises before we touch
    # (or delete) any existing case data.
    notes_data = json.loads(_read("notes.json") or b"{}")
    alert_rules = json.loads(_read("alert_rules.json") or b"[]")
    saved_searches = json.loads(_read("saved_searches.json") or b"[]")
    events_gz = _read("events.ndjson.gz")

    # Archive validated/extracted — now safe to drop the old indices.
    if pre_index_hook is not None:
        pre_index_hook()

    if notes_data.get("body"):
        r.hset(rk.case_notes(case_id), mapping={"body": notes_data["body"], "updated_at": now})
    if alert_rules:
        r.set(rk.case_alert_rules(case_id), json.dumps(alert_rules))
    if saved_searches:
        r.set(rk.case_saved_searches(case_id), json.dumps(saved_searches))
    event_count = _bulk_index_events(case_id, events_gz) if events_gz else 0
    return {"event_count": event_count}


# ── Purge & restore endpoints ─────────────────────────────────────────────────


def _get_archive_s3(case_id: str):
    """Return (Minio client, endpoint, bucket, key). Raises HTTPException if S3 not configured."""
    r = get_redis()
    raw = r.get(rk.ARCHIVE_SETTINGS)
    if not raw:
        raise HTTPException(
            status_code=400, detail="Archive S3 not configured. Set it up in Settings → Archiving."
        )
    cfg = json.loads(raw)
    endpoint = cfg.get("s3_endpoint", "")
    bucket = cfg.get("s3_bucket", "")
    if not endpoint or not bucket:
        raise HTTPException(
            status_code=400, detail="Archive S3 not configured. Set it up in Settings → Archiving."
        )
    client = _make_minio(
        endpoint,
        cfg.get("s3_access_key", ""),
        cfg.get("s3_secret_key", ""),
        bool(cfg.get("s3_use_ssl", True)),
        cfg.get("s3_region") or None,
    )
    key = f"case_archive/{case_id}/case-{case_id}.citadel"
    return client, endpoint, bucket, key


@router.post("/cases/{case_id}/upload-archive")
def upload_archive_case(case_id: str, _case: dict = Depends(require_case_access)):
    """Build .citadel and upload to S3 without deleting local data. Creates a restorable backup."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    client, endpoint, bucket, key = _get_archive_s3(case_id)
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".citadel.tar.gz")
    os.close(tmp_fd)
    try:
        event_count = _build_archive(case_id, tmp_path)
        client.fput_object(bucket, key, tmp_path, content_type="application/gzip")
        update_case(case_id, archive_key=key, archive_bucket=bucket, archive_endpoint=endpoint)
        return {"ok": True, "archive_key": key, "event_count": event_count}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


@router.post("/cases/{case_id}/purge-archive")
def purge_archive_case(case_id: str, _case: dict = Depends(require_case_access)):
    """Build .citadel archive, upload to configured archive S3, delete ES + MinIO, mark purged."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    client, endpoint, bucket, key = _get_archive_s3(case_id)

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".citadel.tar.gz")
    os.close(tmp_fd)
    try:
        event_count = _build_archive(case_id, tmp_path)
        client.fput_object(bucket, key, tmp_path, content_type="application/gzip")

        from services.elasticsearch import delete_case_indices

        delete_case_indices(case_id)

        from services import storage

        storage.delete_case_objects(case_id)

        update_case(
            case_id,
            status="archived",
            local_purged="true",
            archive_key=key,
            archive_bucket=bucket,
            archive_endpoint=endpoint,
        )

        return {"ok": True, "archive_key": key, "event_count": event_count}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Purge failed: {exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


@router.post("/cases/{case_id}/restore-archive")
def restore_archive_case(case_id: str, _case: dict = Depends(require_case_access)):
    """Download .citadel from S3 and restore ES + notes into this case."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    r = get_redis()
    raw = r.get(rk.ARCHIVE_SETTINGS)
    cfg = json.loads(raw) if raw else {}

    endpoint = case.get("archive_endpoint", "")
    bucket = case.get("archive_bucket", "")
    key = case.get("archive_key", "")
    access_key = cfg.get("s3_access_key", "")
    secret_key = cfg.get("s3_secret_key", "")
    use_ssl = bool(cfg.get("s3_use_ssl", True))
    region = cfg.get("s3_region", "") or None

    if not endpoint or not bucket or not key:
        raise HTTPException(status_code=400, detail="Missing archive location on case record")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".citadel.tar.gz")
    os.close(tmp_fd)
    try:
        client = _make_minio(endpoint, access_key, secret_key, use_ssl, region)
        client.fget_object(bucket, key, tmp_path)

        try:
            tf = tarfile.open(tmp_path, "r:gz")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid archive: {exc}")

        with tf:
            # Don't delete the existing indices until the archive has been
            # downloaded, opened, and its members read + parsed successfully.
            # _restore_archive_into_case validates everything first, then calls
            # this hook (clearing old indices to avoid duplicate docs) immediately
            # before the first bulk write. An early failure (bad download, corrupt
            # tar, unparseable JSON) raises before the hook runs, leaving the
            # existing case data intact.
            from services.elasticsearch import delete_case_indices

            stats = _restore_archive_into_case(
                case_id, tf, pre_index_hook=lambda: delete_case_indices(case_id)
            )

        update_case(case_id, status="active", local_purged="false")
        return {"ok": True, **stats}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Restore failed: {exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
