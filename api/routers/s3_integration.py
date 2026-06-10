"""
External S3 Integration — two independent configurations.

  TRIAGE UPLOAD storage  (fo:s3_triage_config)
      Where agents push collected evidence (triage ZIPs, memory dumps, etc.).
      Analysts browse this bucket and pull files into cases on demand.

  CASE DATA IMPORT storage  (fo:s3_config)
      Browse any external S3-compatible bucket and import files into a case
      for parsing — AWS S3, MinIO, Wasabi, GCS, Scaleway Object Storage, …

Both configs are stored in Redis as JSON strings.
All file transfers stream directly: external S3 → internal MinIO, no full RAM buffer.
"""

from __future__ import annotations

import itertools
import json
import logging
import uuid

import redis
import redis_keys as rk
from fastapi import APIRouter, HTTPException, Query
from minio import Minio
from pydantic import BaseModel
from services import jobs as job_svc
from services.cases import get_case

from config import get_redis as _redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["s3"])

# ── Redis keys ────────────────────────────────────────────────────────────────
_S3_IMPORT_KEY = rk.S3_IMPORT_CONFIG
_S3_TRIAGE_KEY = rk.S3_TRIAGE_CONFIG
_S3_IMPORT_LIST_KEY = rk.S3_IMPORT_CONFIGS_LIST

_PUBLIC_FIELDS = ("endpoint", "access_key", "bucket", "region", "vendor", "use_ssl")

# Scaleway Object Storage regions → endpoint mapping
SCALEWAY_ENDPOINTS = {
    "nl-ams": "s3.nl-ams.scw.cloud",  # Amsterdam
    "fr-par": "s3.fr-par.scw.cloud",  # Paris
    "pl-waw": "s3.pl-waw.scw.cloud",  # Warsaw
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _load(r: redis.Redis, key: str) -> dict:
    raw = r.get(key)
    return json.loads(raw) if raw else {}


def _save(r: redis.Redis, key: str, cfg: dict) -> None:
    r.set(key, json.dumps(cfg))


def _build_client(cfg: dict) -> Minio:
    """Build a Minio client pointing at the external S3 config."""
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No S3 configuration saved.")
    endpoint = cfg["endpoint"]
    for prefix in ("https://", "http://"):
        if endpoint.lower().startswith(prefix):
            endpoint = endpoint[len(prefix) :]
            break
    return Minio(
        endpoint,
        access_key=cfg.get("access_key", ""),
        secret_key=cfg.get("secret_key", ""),
        secure=cfg.get("use_ssl", True),
        region=cfg.get("region") or None,
    )


# ── Pydantic models ───────────────────────────────────────────────────────────


class S3ConfigIn(BaseModel):
    endpoint: str
    access_key: str
    secret_key: str = ""
    bucket: str
    region: str = ""
    vendor: str = "aws"  # aws | scaleway | minio | wasabi | gcs | other
    use_ssl: bool = True


class S3ConfigOut(BaseModel):
    endpoint: str
    access_key: str
    secret_key_set: bool
    bucket: str
    region: str
    vendor: str
    use_ssl: bool


class S3ImportIn(BaseModel):
    s3_key: str
    filename: str | None = None


class S3BatchImportIn(BaseModel):
    keys: list[str]


class S3NamedConfigIn(BaseModel):
    name: str
    endpoint: str
    access_key: str
    secret_key: str = ""
    bucket: str
    region: str = ""
    vendor: str = "aws"
    use_ssl: bool = True


class S3NamedConfigOut(BaseModel):
    id: str
    name: str
    endpoint: str
    access_key: str
    secret_key_set: bool
    bucket: str
    region: str
    vendor: str
    use_ssl: bool


# ── Shared config CRUD factory ────────────────────────────────────────────────


def _make_config_routes(redis_key: str, path_prefix: str, label: str):
    """
    Return (get_fn, put_fn, delete_fn, test_fn) handlers bound to a specific
    Redis key and URL prefix.  Avoids copy-pasting identical logic twice.
    """

    def get_cfg():
        r = _redis()
        cfg = _load(r, redis_key)
        return S3ConfigOut(
            endpoint=cfg.get("endpoint", ""),
            access_key=cfg.get("access_key", ""),
            secret_key_set=bool(cfg.get("secret_key")),
            bucket=cfg.get("bucket", ""),
            region=cfg.get("region", ""),
            vendor=cfg.get("vendor", "aws"),
            use_ssl=cfg.get("use_ssl", True),
        )

    def put_cfg(body: S3ConfigIn):
        r = _redis()
        existing = _load(r, redis_key)
        cfg = {
            "endpoint": body.endpoint,
            "access_key": body.access_key,
            "bucket": body.bucket,
            "region": body.region,
            "vendor": body.vendor,
            "use_ssl": body.use_ssl,
            "secret_key": body.secret_key if body.secret_key else existing.get("secret_key", ""),
        }
        _save(r, redis_key, cfg)
        return S3ConfigOut(**{**cfg, "secret_key_set": bool(cfg["secret_key"])})

    def delete_cfg():
        _redis().delete(redis_key)

    def test_cfg():
        r = _redis()
        cfg = _load(r, redis_key)
        if not cfg or not cfg.get("endpoint"):
            raise HTTPException(status_code=400, detail=f"No {label} S3 config saved yet.")
        try:
            client = _build_client(cfg)
            objects = list(itertools.islice(client.list_objects(cfg["bucket"]), 5))
            return {
                "ok": True,
                "bucket": cfg["bucket"],
                "objects": len(objects),
                "message": f"Connected. Found {len(objects)} object(s) in sample.",
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Connection test failed: {exc}")

    return get_cfg, put_cfg, delete_cfg, test_cfg


# ── Case Data Import endpoints (/admin/s3-config) ─────────────────────────────
# Existing path — kept identical so current clients are not broken.

_imp_get, _imp_put, _imp_del, _imp_test = _make_config_routes(
    _S3_IMPORT_KEY, "/admin/s3-config", "import"
)
# Give each closure a unique __name__ so FastAPI generates distinct operation IDs.
_imp_get.__name__ = "get_s3_import_config"
_imp_put.__name__ = "put_s3_import_config"
_imp_del.__name__ = "delete_s3_import_config"
_imp_test.__name__ = "test_s3_import_config"

router.get("/admin/s3-config", response_model=S3ConfigOut)(_imp_get)
router.put("/admin/s3-config", response_model=S3ConfigOut)(_imp_put)
router.delete("/admin/s3-config", status_code=204)(_imp_del)
router.post("/admin/s3-config/test")(_imp_test)


# ── Triage Upload S3 endpoints (/admin/s3-triage-config) ──────────────────────

_tri_get, _tri_put, _tri_del, _tri_test = _make_config_routes(
    _S3_TRIAGE_KEY, "/admin/s3-triage-config", "triage"
)
_tri_get.__name__ = "get_s3_triage_config"
_tri_put.__name__ = "put_s3_triage_config"
_tri_del.__name__ = "delete_s3_triage_config"
_tri_test.__name__ = "test_s3_triage_config"

router.get("/admin/s3-triage-config", response_model=S3ConfigOut)(_tri_get)
router.put("/admin/s3-triage-config", response_model=S3ConfigOut)(_tri_put)
router.delete("/admin/s3-triage-config", status_code=204)(_tri_del)
router.post("/admin/s3-triage-config/test")(_tri_test)


# NOTE: The presence-only /s3-triage/status endpoint lives in collector.py
# instead of here, because this router is mounted with require_admin at the
# main.py include level — route-level dep overrides don't relax router-level
# deps in FastAPI. The collector router is mounted with require_analyst_or_admin.


# ── Pre-signed upload URL ─────────────────────────────────────────────────────

import re as _re
from datetime import UTC, timedelta


@router.post("/admin/s3-triage/presign")
def generate_triage_presign(
    filename: str = "fo-artifacts.zip",
    expires_hours: int = 24,
):
    """
    Generate a pre-signed PUT URL for the triage S3 bucket.

    The caller can upload directly to the returned URL using a plain HTTP PUT
    without needing S3 credentials. The URL is valid for `expires_hours` hours.
    Use this to give field operators a time-limited, single-object upload slot
    instead of sharing permanent S3 credentials.
    """
    r = _redis()
    cfg = _load(r, _S3_TRIAGE_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(
            status_code=400,
            detail="No S3 triage config saved. Configure it in Admin → S3 Triage first.",
        )

    from datetime import datetime

    client = _build_client(cfg)
    bucket = cfg["bucket"]

    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    safe = _re.sub(r"[^\w.\-]", "_", filename)[:120]
    key = f"uploads/{ts}-{safe}"
    expires = timedelta(hours=max(1, min(expires_hours, 168)))  # 1h–7d

    try:
        url = client.presigned_put_object(bucket, key, expires=expires)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not generate presigned URL: {exc}")

    expires_at = (datetime.now(UTC) + expires).isoformat()
    return {
        "url": url,
        "key": key,
        "bucket": bucket,
        "expires_at": expires_at,
        "expires_hours": expires_hours,
        "note": (
            "PUT the file directly to `url`. No S3 credentials needed. "
            "After upload, browse Admin → S3 Triage to import into a case."
        ),
    }


# ── Browse endpoints ──────────────────────────────────────────────────────────


def _browse(redis_key: str, label: str, prefix: str, delimiter: str):
    r = _redis()
    cfg = _load(r, redis_key)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail=f"No {label} S3 configuration saved.")
    try:
        client = _build_client(cfg)
        items = client.list_objects(
            cfg["bucket"],
            prefix=prefix or None,
            recursive=delimiter == "",
        )
        folders, files = [], []
        for obj in items:
            if obj.is_dir:
                folders.append({"key": obj.object_name, "type": "folder"})
            else:
                files.append(
                    {
                        "key": obj.object_name,
                        "type": "file",
                        "size": obj.size,
                        "last_modified": obj.last_modified.isoformat()
                        if obj.last_modified
                        else None,
                        "etag": obj.etag,
                    }
                )
        return {"prefix": prefix, "bucket": cfg["bucket"], "folders": folders, "files": files}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to browse S3: {exc}")


@router.get("/s3/browse")
def browse_import_s3(
    prefix: str = Query(""),
    delimiter: str = Query("/"),
):
    """Browse the case-data-import S3 bucket."""
    return _browse(_S3_IMPORT_KEY, "import", prefix, delimiter)


@router.get("/s3-triage/browse")
def browse_triage_s3(
    prefix: str = Query(""),
    delimiter: str = Query("/"),
):
    """Browse the triage-upload S3 bucket."""
    return _browse(_S3_TRIAGE_KEY, "triage", prefix, delimiter)


# ── Import: case data S3 → case ───────────────────────────────────────────────


@router.post("/cases/{case_id}/s3-import")
def import_from_s3(case_id: str, body: S3ImportIn):
    """
    Enqueue an async S3 → MinIO → ingest pipeline for a single file.

    Returns immediately with a job ID; the actual transfer and parsing run
    in a background Celery worker so the client never blocks on large files.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    cfg = _load(_redis(), _S3_IMPORT_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No import S3 configuration saved.")

    filename = body.filename or body.s3_key.rsplit("/", 1)[-1] or "unknown"
    job_id = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")
    job_svc.update_job(job_id, s3_config_key=_S3_IMPORT_KEY, s3_source_key=body.s3_key)

    from services.celery_dispatch import dispatch_s3_transfer

    dispatch_s3_transfer(job_id, case_id, _S3_IMPORT_KEY, body.s3_key, filename)

    return {
        "job_id": job_id,
        "case_id": case_id,
        "filename": filename,
        "s3_key": body.s3_key,
        "status": "PENDING",
    }


# ── Pull: triage S3 → case ───────────────────────────────────────────────────


@router.post("/cases/{case_id}/s3-triage-pull")
def pull_from_triage(case_id: str, body: S3ImportIn):
    """
    Pull a file from the triage-upload S3 bucket into a case for processing.

    Intended workflow: agents push collected archives to the triage bucket;
    analysts open a case, browse the bucket, and pull relevant archives here.
    Streams directly — safe for large triage ZIPs and memory dumps.
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    r = _redis()
    cfg = _load(r, _S3_TRIAGE_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(
            status_code=400,
            detail="No triage S3 configuration saved. Configure it in Settings → Triage Upload Storage.",
        )

    filename = body.filename or body.s3_key.rsplit("/", 1)[-1] or "unknown"
    job_id = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")
    job_svc.update_job(job_id, s3_config_key=_S3_TRIAGE_KEY, s3_source_key=body.s3_key)

    from services.celery_dispatch import dispatch_s3_transfer

    dispatch_s3_transfer(job_id, case_id, _S3_TRIAGE_KEY, body.s3_key, filename)

    return {
        "job_id": job_id,
        "case_id": case_id,
        "filename": filename,
        "s3_key": body.s3_key,
        "status": "PENDING",
    }


# ── Batch import helpers ──────────────────────────────────────────────────────


def _batch_dispatch(case_id: str, cfg_redis_key: str, keys: list[str]) -> dict:
    """Enqueue S3 transfer tasks for multiple objects and return immediately.

    Creates a job record for each key, stores S3 metadata for retry routing,
    then dispatches a background Celery task — no blocking I/O in the request.
    Returns {'jobs': [...], 'errors': [...]} so callers can surface creation failures.
    """
    from services.celery_dispatch import dispatch_s3_transfer

    jobs, errors = [], []
    for s3_key in keys:
        filename = s3_key.rsplit("/", 1)[-1] or "unknown"
        job_id = uuid.uuid4().hex
        minio_key = f"cases/{case_id}/{job_id}/{filename}"
        try:
            job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")
            job_svc.update_job(job_id, s3_config_key=cfg_redis_key, s3_source_key=s3_key)
            dispatch_s3_transfer(job_id, case_id, cfg_redis_key, s3_key, filename)
            jobs.append(
                {"job_id": job_id, "filename": filename, "s3_key": s3_key, "status": "PENDING"}
            )
        except Exception as exc:
            logger.warning("Batch dispatch failed for %s: %s", s3_key, exc)
            errors.append({"s3_key": s3_key, "error": str(exc)})
    return {"jobs": jobs, "errors": errors}


@router.post("/cases/{case_id}/s3-import-batch")
def import_batch_from_s3(case_id: str, body: S3BatchImportIn):
    """Enqueue async transfer tasks for multiple objects from the import S3 bucket."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    cfg = _load(_redis(), _S3_IMPORT_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(status_code=400, detail="No import S3 configuration saved.")
    return _batch_dispatch(case_id, _S3_IMPORT_KEY, body.keys)


@router.post("/cases/{case_id}/s3-triage-pull-batch")
def pull_batch_from_triage(case_id: str, body: S3BatchImportIn):
    """Enqueue async transfer tasks for multiple objects from the triage S3 bucket."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    cfg = _load(_redis(), _S3_TRIAGE_KEY)
    if not cfg or not cfg.get("endpoint"):
        raise HTTPException(
            status_code=400,
            detail="No triage S3 configuration saved. Configure it in Settings → Triage Upload Storage.",
        )
    return _batch_dispatch(case_id, _S3_TRIAGE_KEY, body.keys)


# ── Multi-source Import S3 CRUD (/admin/s3-import-configs) ───────────────────
# Each config lives in the list AND as `fo:s3_config:{id}` so Celery dispatch
# (which calls r.get(config_key)) requires zero changes.


def _load_import_list(r: redis.Redis) -> list[dict]:
    raw = r.get(_S3_IMPORT_LIST_KEY)
    return json.loads(raw) if raw else []


def _save_import_list(r: redis.Redis, configs: list[dict]) -> None:
    r.set(_S3_IMPORT_LIST_KEY, json.dumps(configs))


def _sync_individual_key(r: redis.Redis, cfg: dict) -> None:
    """Mirror config to fo:s3_config:{id} for Celery task lookup."""
    r.set(rk.s3_import_config(cfg["id"]), json.dumps(cfg))


def _delete_individual_key(r: redis.Redis, cfg_id: str) -> None:
    r.delete(rk.s3_import_config(cfg_id))


def _named_cfg_to_out(cfg: dict) -> S3NamedConfigOut:
    return S3NamedConfigOut(
        id=cfg["id"],
        name=cfg.get("name", ""),
        endpoint=cfg.get("endpoint", ""),
        access_key=cfg.get("access_key", ""),
        secret_key_set=bool(cfg.get("secret_key")),
        bucket=cfg.get("bucket", ""),
        region=cfg.get("region", ""),
        vendor=cfg.get("vendor", "aws"),
        use_ssl=cfg.get("use_ssl", True),
    )


@router.get("/admin/s3-import-configs", response_model=list[S3NamedConfigOut])
def list_import_configs():
    r = _redis()
    return [_named_cfg_to_out(c) for c in _load_import_list(r)]


@router.post("/admin/s3-import-configs", response_model=S3NamedConfigOut, status_code=201)
def add_import_config(body: S3NamedConfigIn):
    r = _redis()
    configs = _load_import_list(r)
    new_cfg = {
        "id": uuid.uuid4().hex,
        "name": body.name,
        "endpoint": body.endpoint,
        "access_key": body.access_key,
        "secret_key": body.secret_key,
        "bucket": body.bucket,
        "region": body.region,
        "vendor": body.vendor,
        "use_ssl": body.use_ssl,
    }
    configs.append(new_cfg)
    _save_import_list(r, configs)
    _sync_individual_key(r, new_cfg)
    return _named_cfg_to_out(new_cfg)


@router.put("/admin/s3-import-configs/{config_id}", response_model=S3NamedConfigOut)
def update_import_config(config_id: str, body: S3NamedConfigIn):
    r = _redis()
    configs = _load_import_list(r)
    for i, cfg in enumerate(configs):
        if cfg["id"] == config_id:
            updated = {
                **cfg,
                "name": body.name,
                "endpoint": body.endpoint,
                "access_key": body.access_key,
                "secret_key": body.secret_key if body.secret_key else cfg.get("secret_key", ""),
                "bucket": body.bucket,
                "region": body.region,
                "vendor": body.vendor,
                "use_ssl": body.use_ssl,
            }
            configs[i] = updated
            _save_import_list(r, configs)
            _sync_individual_key(r, updated)
            return _named_cfg_to_out(updated)
    raise HTTPException(status_code=404, detail="Import config not found")


@router.delete("/admin/s3-import-configs/{config_id}", status_code=204)
def delete_import_config(config_id: str):
    r = _redis()
    configs = _load_import_list(r)
    new_configs = [c for c in configs if c["id"] != config_id]
    if len(new_configs) == len(configs):
        raise HTTPException(status_code=404, detail="Import config not found")
    _save_import_list(r, new_configs)
    _delete_individual_key(r, config_id)


@router.post("/admin/s3-import-configs/{config_id}/test")
def test_import_config(config_id: str):
    r = _redis()
    configs = _load_import_list(r)
    cfg = next((c for c in configs if c["id"] == config_id), None)
    if not cfg:
        raise HTTPException(status_code=404, detail="Import config not found")
    try:
        client = _build_client(cfg)
        objects = list(itertools.islice(client.list_objects(cfg["bucket"]), 5))
        return {
            "ok": True,
            "bucket": cfg["bucket"],
            "objects": len(objects),
            "message": f"Connected. Found {len(objects)} object(s) in sample.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Connection test failed: {exc}")


@router.get("/s3-import/browse/{config_id}")
def browse_named_import_s3(
    config_id: str,
    prefix: str = Query(""),
    delimiter: str = Query("/"),
):
    """Browse a named import S3 source by its config ID."""
    r = _redis()
    configs = _load_import_list(r)
    cfg = next((c for c in configs if c["id"] == config_id), None)
    if not cfg:
        raise HTTPException(status_code=404, detail="Import config not found")
    try:
        client = _build_client(cfg)
        items = client.list_objects(cfg["bucket"], prefix=prefix or None, recursive=delimiter == "")
        folders, files = [], []
        for obj in items:
            if obj.is_dir:
                folders.append({"key": obj.object_name, "type": "folder"})
            else:
                files.append(
                    {
                        "key": obj.object_name,
                        "type": "file",
                        "size": obj.size,
                        "last_modified": obj.last_modified.isoformat()
                        if obj.last_modified
                        else None,
                        "etag": obj.etag,
                    }
                )
        return {
            "config_id": config_id,
            "prefix": prefix,
            "bucket": cfg["bucket"],
            "folders": folders,
            "files": files,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to browse S3: {exc}")


@router.post("/cases/{case_id}/s3-import-named")
def import_from_named_s3(case_id: str, config_id: str, body: S3ImportIn):
    """Import a file from a named multi-source config into a case."""
    if not get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    r = _redis()
    configs = _load_import_list(r)
    cfg = next((c for c in configs if c["id"] == config_id), None)
    if not cfg:
        raise HTTPException(status_code=404, detail="Import config not found")

    redis_key = rk.s3_import_config(config_id)
    filename = body.filename or body.s3_key.rsplit("/", 1)[-1] or "unknown"
    job_id = uuid.uuid4().hex
    minio_key = f"cases/{case_id}/{job_id}/{filename}"

    job_svc.create_job(job_id, case_id, filename, minio_key, source_zip="")
    job_svc.update_job(job_id, s3_config_key=redis_key, s3_source_key=body.s3_key)

    from services.celery_dispatch import dispatch_s3_transfer

    dispatch_s3_transfer(job_id, case_id, redis_key, body.s3_key, filename)

    return {
        "job_id": job_id,
        "case_id": case_id,
        "filename": filename,
        "s3_key": body.s3_key,
        "config_id": config_id,
        "status": "PENDING",
    }


# ── Scaleway region helper ─────────────────────────────────────────────────────


@router.get("/s3/scaleway-regions")
def scaleway_regions():
    """Return the list of Scaleway Object Storage regions and their endpoints."""
    return [
        {
            "region": k,
            "endpoint": v,
            "label": {
                "nl-ams": "Amsterdam (nl-ams)",
                "fr-par": "Paris (fr-par)",
                "pl-waw": "Warsaw (pl-waw)",
            }[k],
        }
        for k in SCALEWAY_ENDPOINTS
    ]
