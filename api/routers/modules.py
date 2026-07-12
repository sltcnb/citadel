"""
Analysis Modules registry and run management.

Modules are on-demand analysis tools that run asynchronously via Celery
against files already ingested into a case.  They differ from Ingesters:

  Ingesters  — parse uploaded raw files into the timeline (EVTX, logs, etc.)
  Modules    — perform deeper forensic analysis on stored artifacts
               (threat hunting, malware scanning, metadata extraction…)

Each module run is independent: you select source files from the case,
launch the module, and results appear in the Module Runs panel without
affecting the main event timeline.

Module definitions live in api/modules_registry/*.yaml  — add a new YAML file
to register a new module without touching this code.
"""

from __future__ import annotations

import ast
import asyncio
import json as _json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

import redis_keys as rk
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

try:
    import yaml as _yaml  # type: ignore

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from auth.dependencies import require_admin
from services import module_runs as run_svc
from services import storage
from services.cases import get_case
from services.jobs import get_job, list_case_job_ids_recent
from services.module_runs import MALWARE_CASE_ID, get_redis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["modules"])

CUSTOM_MODULES_DIR = Path(os.getenv("MODULES_DIR", "/app/anvil"))

# Module definitions are loaded from YAML files in api/modules_registry/
_REGISTRY_DIR = Path(__file__).parent.parent / "modules_registry"

# Modules shipped with the image (modules_builtin/) — classified as built-in,
# not custom, so they don't show the "Custom" badge in the UI.
# Key = module_id (filename stem minus "_module"), value = UI category.
_BUILTIN_MODULE_CATEGORIES: dict[str, str] = {
    "access_log_analysis": "Web Security",
    "capa": "Malware Analysis",
    "de4dot": "Malware Analysis",
    "exiftool": "Metadata",
    "floss": "Malware Analysis",
    "grep_search": "Investigation",
    "malwoverview": "Threat Intelligence",
    "ole_analysis": "Document Analysis",
    "oletools": "Document Analysis",
    "pe_analysis": "Malware Analysis",
    "strings": "Investigation",
    "strings_analysis": "Investigation",
}


# ── YAML registry loader ──────────────────────────────────────────────────────
# input_extensions : list of file extensions to match (lower-case, with dot)
# input_filenames  : list of exact basenames to match (case-insensitive)
# Both empty       → accept ANY source file (e.g. "strings")
# Non-empty        → match if extension OR filename matches


def _load_modules_from_registry() -> list[dict]:
    """
    Load module definitions from api/modules_registry/*.yaml.

    Each YAML file defines one module:
        id: hayabusa
        name: Hayabusa
        description: ...
        input_extensions: [".evtx"]
        input_filenames: []
        available: true
        # optional fields:
        unavailable_reason: "..."
        category: "Threat Hunting"
        tags: [sigma, evtx]
    """
    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not installed — module registry cannot be loaded from YAML files")
        return []
    if not _REGISTRY_DIR.exists():
        logger.warning("Modules registry directory %s not found", _REGISTRY_DIR)
        return []

    modules: list[dict] = []
    for path in sorted(_REGISTRY_DIR.glob("*.yaml")):
        try:
            with path.open() as fh:
                data = _yaml.safe_load(fh)
            if not isinstance(data, dict) or not data.get("id"):
                logger.warning("Skipping %s — missing 'id' field", path.name)
                continue
            module: dict = {
                "id": data["id"],
                "name": data.get("name", data["id"]),
                "description": data.get("description", ""),
                "input_extensions": data.get("input_extensions") or [],
                "input_filenames": data.get("input_filenames") or [],
                "available": bool(data.get("available", True)),
                "category": data.get("category", ""),
                "tags": data.get("tags") or [],
                # ES-only modules query Elasticsearch directly (no source files).
                "run_on_events": bool(data.get("run_on_events", False)),
            }
            if not module["available"]:
                module["unavailable_reason"] = data.get("unavailable_reason", "Unavailable")
            modules.append(module)
        except Exception as exc:
            logger.error("Failed to load module from %s: %s", path.name, exc)
    return modules


_MODULES_CACHE: list[dict] | None = None


def _get_modules() -> list[dict]:
    global _MODULES_CACHE
    if _MODULES_CACHE is None:
        _MODULES_CACHE = _load_modules_from_registry()
    return _MODULES_CACHE


def invalidate_modules_cache() -> None:
    """Force the YAML module registry to reload on next request."""
    global _MODULES_CACHE, _CUSTOM_MODULES_CACHE
    _MODULES_CACHE = None
    _CUSTOM_MODULES_CACHE = None


def _get_modules_by_id() -> dict[str, dict]:
    return {m["id"]: m for m in _get_modules()}


# ── Request models ────────────────────────────────────────────────────────────


class SourceFileRef(BaseModel):
    job_id: str = ""
    filename: str = ""
    minio_key: str = ""

    class Config:
        extra = "ignore"  # frontend sometimes adds derived fields; don't 422 on them


class CreateModuleRunRequest(BaseModel):
    module_id: str
    job_ids: list[str] = []  # legacy: bare IDs resolved via Redis
    source_files: list[SourceFileRef] = []  # preferred: pre-resolved metadata
    params: dict[str, Any] = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────


def _module_meta(text: str) -> dict[str, Any]:
    """Extract a module's typed metadata WITHOUT executing it.

    AST-based: reads module-level constants (``MODULE_NAME``,
    ``MODULE_DESCRIPTION``, ``INPUT_EXTENSIONS``, ``INPUT_FILENAMES``,
    ``ARTIFACT_TYPE``, ``INDEX_SKIP``) and the ``estimated_runtime`` class
    attribute of the BaseModule subclass. Robust to any string formatting
    (single-line, implicitly-concatenated, parenthesized multi-line) — which the
    old line-anchored regex was not — and import-free, so it works in the API
    container that lacks processor-only deps (pefile, yara, …).
    """
    meta: dict[str, Any] = {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return meta
    wanted = {
        "MODULE_NAME",
        "MODULE_DESCRIPTION",
        "INPUT_EXTENSIONS",
        "INPUT_FILENAMES",
        "ARTIFACT_TYPE",
        "INDEX_SKIP",
    }
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id in wanted:
                    try:
                        meta[tgt.id] = ast.literal_eval(node.value)
                    except (ValueError, SyntaxError):
                        pass
        # estimated_runtime lives on the BaseModule subclass as a class attr
        elif isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name) and tgt.id == "estimated_runtime":
                            try:
                                meta["estimated_runtime"] = ast.literal_eval(stmt.value)
                            except (ValueError, SyntaxError):
                                pass
    return meta


_CUSTOM_MODULES_CACHE: list[dict] | None = None


def _get_custom_modules() -> list[dict]:
    """Scan CUSTOM_MODULES_DIR and return metadata for each *_module.py file.

    Uses AST static analysis (see :func:`_module_meta`) rather than exec_module
    so this works in the API container which does not have processor-only
    packages (pefile, yara, etc.) installed.

    Result is cached in-process — the directory contents are static for the
    lifetime of the container, so re-reading + AST-parsing every file on each
    /modules request (which made the request slow enough to time out the UI)
    is wasteful. Cleared via invalidate_modules_cache().
    """
    global _CUSTOM_MODULES_CACHE
    if _CUSTOM_MODULES_CACHE is not None:
        return _CUSTOM_MODULES_CACHE
    if not CUSTOM_MODULES_DIR.exists():
        _CUSTOM_MODULES_CACHE = []
        return _CUSTOM_MODULES_CACHE
    built_in_ids = {m["id"] for m in _get_modules()}
    result = []

    for f in sorted(CUSTOM_MODULES_DIR.glob("*_module.py")):
        module_id = f.stem[: -len("_module")]
        if module_id in built_in_ids:
            continue
        builtin_category = _BUILTIN_MODULE_CATEGORIES.get(module_id)
        is_custom = builtin_category is None
        try:
            meta = _module_meta(f.read_text(encoding="utf-8", errors="ignore"))
            entry = {
                "id": module_id,
                "name": meta.get("MODULE_NAME") or module_id.replace("_", " ").title(),
                "description": meta.get("MODULE_DESCRIPTION") or "Custom analysis module",
                "input_extensions": meta.get("INPUT_EXTENSIONS") or [],
                "input_filenames": meta.get("INPUT_FILENAMES") or [],
                "available": True,
                "custom": is_custom,
                "category": builtin_category if not is_custom else "Custom",
            }
            if meta.get("ARTIFACT_TYPE"):
                entry["artifact_type"] = meta["ARTIFACT_TYPE"]
            if meta.get("estimated_runtime") is not None:
                entry["estimated_runtime"] = meta["estimated_runtime"]
            result.append(entry)
        except Exception as exc:
            result.append(
                {
                    "id": module_id,
                    "name": module_id.replace("_", " ").title(),
                    "description": f"Load error: {exc}",
                    "input_extensions": [],
                    "input_filenames": [],
                    "available": False,
                    "unavailable_reason": f"Load error: {exc}",
                    "custom": is_custom,
                }
            )
    _CUSTOM_MODULES_CACHE = result
    return result


@router.get("/modules")
def list_modules():
    return {"modules": _get_modules() + _get_custom_modules()}


_SOURCES_CHUNK = 2_000  # pipeline batch size for Redis fallback
_SOURCES_MAX = 5_000  # cap for Redis fallback path


@router.get("/cases/{case_id}/sources")
def list_case_sources(case_id: str):
    """Return completed ingest jobs for a case (usable as module inputs)."""
    from services.elasticsearch import list_case_artifacts

    from config import get_redis

    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # ── Fast path: query the fo-artifacts ES index ────────────────────────────
    artifacts = list_case_artifacts(case_id)
    if artifacts:
        sources = [
            {
                "job_id": a["job_id"],
                "original_filename": a.get("filename", ""),
                "plugin_used": a.get("plugin_used", ""),
                "events_indexed": a.get("events_indexed", 0),
                "minio_object_key": a.get("minio_key", ""),
                "skipped": bool(a.get("skipped", False)),
            }
            for a in artifacts
        ]
        sources.sort(key=lambda s: s["original_filename"])
        return {"sources": sources}

    # ── Fallback: Redis sorted set + chunked pipeline ─────────────────────────
    job_ids = list_case_job_ids_recent(case_id)
    if not job_ids:
        return {"sources": []}

    r = get_redis()
    _fields = (
        "job_id",
        "status",
        "original_filename",
        "plugin_used",
        "events_indexed",
        "minio_object_key",
    )

    sources = []
    for chunk_start in range(0, len(job_ids), _SOURCES_CHUNK):
        chunk = job_ids[chunk_start : chunk_start + _SOURCES_CHUNK]
        pipe = r.pipeline(transaction=False)
        for jid in chunk:
            pipe.hmget(f"job:{jid}", *_fields)
        rows = pipe.execute()
        for jid, vals in zip(chunk, rows):
            status = vals[1]
            if status not in ("COMPLETED", "SKIPPED"):
                continue
            try:
                events_indexed = int(vals[4] or 0)
            except (ValueError, TypeError):
                events_indexed = 0
            sources.append(
                {
                    "job_id": vals[0] or jid,
                    "original_filename": vals[2] or "",
                    "plugin_used": vals[3] or "",
                    "events_indexed": events_indexed,
                    "minio_object_key": vals[5] or "",
                    "skipped": status == "SKIPPED",
                }
            )
        if len(sources) >= _SOURCES_MAX:
            break

    sources.sort(key=lambda s: s["original_filename"])
    return {"sources": sources, "truncated": len(job_ids) > _SOURCES_MAX}


@router.get("/cases/{case_id}/recommended-modules")
def recommend_modules(case_id: str):
    """Rank modules by how many of the case's ingested files they can consume.

    Matching mirrors the source-file filter used at run creation:
    extension OR exact basename. Modules with no declared inputs (e.g.
    "strings") accept anything — they're returned as generic suggestions
    rather than ranked matches so specific tools surface first.
    """
    sources = list_case_sources(case_id).get("sources", [])
    filenames = [
        s["original_filename"]
        for s in sources
        if s.get("original_filename") and not s.get("skipped")
    ]

    recommended: list[dict] = []
    generic: list[dict] = []
    for module in _get_modules() + _get_custom_modules():
        if not module.get("available"):
            continue
        exts = {e.lower() for e in module.get("input_extensions") or []}
        names = {n.lower() for n in module.get("input_filenames") or []}
        entry = {
            "id": module["id"],
            "name": module["name"],
            "description": module.get("description", ""),
            "category": module.get("category", ""),
        }
        if not exts and not names:
            generic.append({**entry, "matched_files": len(filenames), "generic": True})
            continue
        matched = [
            fn
            for fn in filenames
            if Path(fn).suffix.lower() in exts or Path(fn).name.lower() in names
        ]
        if matched:
            recommended.append(
                {
                    **entry,
                    "matched_files": len(matched),
                    "sample_matches": sorted(matched)[:5],
                    "generic": False,
                }
            )

    recommended.sort(key=lambda m: (-m["matched_files"], m["name"].lower()))
    generic.sort(key=lambda m: m["name"].lower())
    return {
        "recommended": recommended,
        "generic": generic,
        "total_sources": len(filenames),
    }


@router.post("/cases/{case_id}/module-runs", status_code=201)
def create_module_run(case_id: str, req: CreateModuleRunRequest):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    module = _get_modules_by_id().get(req.module_id)
    if not module:
        # Also check custom Python modules from the modules/ directory
        custom_by_id = {m["id"]: m for m in _get_custom_modules()}
        module = custom_by_id.get(req.module_id)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module '{req.module_id}' not found")
    if not module.get("available"):
        reason = module.get("unavailable_reason", "Module unavailable")
        raise HTTPException(status_code=400, detail=reason)
    # ES-only modules (run_on_events) query Elasticsearch directly — no source
    # files needed (e.g. cti_match, auth_summary, network_summary, rare_process).
    if not module.get("run_on_events") and not req.source_files and not req.job_ids:
        raise HTTPException(status_code=400, detail="At least one source job is required")

    source_files: list[dict] = []

    # Preferred path: caller already resolved filename + minio_key (no Redis needed)
    if req.source_files:
        for sf in req.source_files:
            source_files.append(
                {
                    "job_id": sf.job_id,
                    "filename": sf.filename,
                    "minio_key": sf.minio_key,
                }
            )
    else:
        # Legacy path: bare job_ids — look up Redis. Fails if TTL expired.
        for job_id in req.job_ids:
            job = get_job(job_id)
            if not job:
                raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
            if job.get("status") not in ("COMPLETED", "SKIPPED"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Job '{job_id}' has not completed yet (status: {job.get('status')})",
                )
            source_files.append(
                {
                    "job_id": job_id,
                    "filename": job.get("original_filename", ""),
                    "minio_key": job.get("minio_object_key", ""),
                }
            )

    # Pre-flight: drop sources whose MinIO object disappeared. Don't 422 the
    # whole run — analysts get useful runs even when a few legacy files are
    # missing. If EVERY source is gone, then refuse with a clear error.
    kept: list[dict] = []
    missing: list[str] = []
    for sf in source_files:
        key = sf.get("minio_key") or ""
        if not key:
            kept.append(sf)
            continue
        try:
            present = storage.object_exists(key)
        except Exception as exc:
            logger.warning("object_exists failed for %s: %s (treating as present)", key, exc)
            present = True
        if present:
            kept.append(sf)
        else:
            missing.append(key)
    # ES-only modules (run_on_events) legitimately have zero source files —
    # they query Elasticsearch, not the object store. Don't 422 them.
    if not kept and not module.get("run_on_events"):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "source_files_missing",
                "message": f"All {len(missing)} selected source file(s) are missing from storage. Nothing left to run.",
                "missing_keys": missing[:50],
            },
        )
    if missing:
        logger.info(
            "Skipping %d missing sources for module %s on case %s",
            len(missing),
            req.module_id,
            case_id,
        )
    source_files = kept

    run_id = uuid.uuid4().hex
    run_svc.create_module_run(run_id, case_id, req.module_id, source_files)

    try:
        from services.celery_dispatch import dispatch_module

        dispatch_module(run_id, case_id, req.module_id, source_files, req.params)
    except Exception as exc:
        logger.error("Celery dispatch failed for module run %s: %s", run_id, exc)
        run_svc.update_module_run(run_id, status="FAILED", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Task dispatch failed: {exc}")

    return {"run_id": run_id, "status": "PENDING"}


@router.get("/cases/{case_id}/module-runs")
def list_module_runs(case_id: str):
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"runs": run_svc.list_case_module_runs(case_id)}


@router.get("/module-runs/{run_id}")
def get_module_run(run_id: str):
    run = run_svc.get_module_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Module run not found")
    return run


@router.post("/module-runs/{run_id}/retry")
def retry_module_run(run_id: str):
    """Re-dispatch a FAILED or stuck PENDING module run."""
    run = run_svc.get_module_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Module run not found")
    if run.get("status") not in ("FAILED", "PENDING"):
        raise HTTPException(
            status_code=409,
            detail=f"Only FAILED or PENDING runs can be retried (status: {run.get('status')})",
        )

    case_id = run["case_id"]
    module_id = run["module_id"]
    source_files = run.get("source_files") or []

    # Pre-flight: re-validate all source files still exist in MinIO before retry.
    missing = [
        sf["minio_key"]
        for sf in source_files
        if sf.get("minio_key") and not storage.object_exists(sf["minio_key"])
    ]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "source_files_missing",
                "message": f"{len(missing)} source file(s) not found in storage.",
                "missing_keys": missing,
            },
        )

    run_svc.reset_module_run_for_retry(run_id)

    try:
        from services.celery_dispatch import dispatch_module

        dispatch_module(run_id, case_id, module_id, source_files, {})
    except Exception as exc:
        logger.error("Celery dispatch failed for module run retry %s: %s", run_id, exc)
        run_svc.update_module_run(run_id, status="FAILED", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Task dispatch failed: {exc}")

    return {"run_id": run_id, "status": "PENDING", "message": "Module run re-queued"}


@router.post("/module-runs/{run_id}/cancel")
def cancel_module_run(run_id: str):
    """Co-operative cancel — sets a flag the worker honours at phase
    boundaries (queue pickup, between file downloads, before indexing).
    A module binary mid-execution finishes first; its output is then
    discarded and the run marked CANCELLED."""
    run = run_svc.get_module_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Module run not found")
    if run.get("status") not in ("PENDING", "RUNNING"):
        raise HTTPException(
            status_code=409,
            detail=f"Only PENDING or RUNNING runs can be cancelled (status: {run.get('status')})",
        )
    r = get_redis()
    r.set(rk.module_cancel(run_id), "1", ex=7200)
    # A PENDING run may sit in the queue for a while — reflect intent in the
    # UI immediately. The worker still checks the flag on pickup and exits
    # cleanly without doing any work.
    if run.get("status") == "PENDING":
        run_svc.update_module_run(run_id, status="CANCELLED", error="Cancelled before execution")
        return {"run_id": run_id, "status": "CANCELLED"}
    return {"run_id": run_id, "status": "CANCELLING"}


# ── Standalone malware analysis (no case required) ────────────────────────────


class StandaloneRunRequest(BaseModel):
    module_id: str
    files: list[dict]  # [{filename: str, minio_key: str}]
    params: dict[str, Any] = {}


_MAX_MALWARE_UPLOAD = int(os.getenv("MAX_MALWARE_UPLOAD_BYTES", str(2 * 1024**3)))  # 2 GiB


def _max_malware_upload_bytes() -> int:
    """Effective upload cap in bytes. Derived from the admin-configurable
    ``max_upload_gib`` platform setting at request time; falls back to the
    env default on any Redis/resolver error so ingest never breaks."""
    try:
        from routers.platform_settings import get_platform_config

        gib = int(get_platform_config()["max_upload_gib"])
        if gib >= 1:
            return gib * 1024**3
    except Exception:
        pass
    return _MAX_MALWARE_UPLOAD


@router.post("/malware-analysis/upload", status_code=201)
async def upload_malware_file(file: UploadFile = File(...)):
    """
    Upload a file directly for standalone malware analysis.
    Returns the MinIO key so it can be referenced in a subsequent /malware-analysis/runs call.

    Streams to a bounded temp file (cap: MAX_MALWARE_UPLOAD_BYTES) instead of
    reading the whole body into RAM, and offloads the blocking MinIO PUT to a
    worker thread so neither a huge sample nor a slow upload stalls the event loop.
    """
    import tempfile

    upload_id = uuid.uuid4().hex
    filename = file.filename or "upload"
    minio_key = f"malware_analysis/uploads/{upload_id}/{filename}"

    max_upload = _max_malware_upload_bytes()
    size = 0
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = tmp.name
    try:
        while True:
            chunk = await file.read(8 * 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_upload:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds the {max_upload // 1024**3} GiB upload limit",
                )
            tmp.write(chunk)
        tmp.close()
        loop = asyncio.get_event_loop()
        with open(tmp_path, "rb") as fh:
            await loop.run_in_executor(None, storage.upload_fileobj, minio_key, fh, size)
    finally:
        tmp.close()
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    logger.info("Malware upload: %s → %s (%d bytes)", filename, minio_key, size)
    return {"upload_id": upload_id, "filename": filename, "minio_key": minio_key, "size": size}


@router.post("/malware-analysis/runs", status_code=201)
def create_standalone_run(req: StandaloneRunRequest):
    """
    Create a standalone malware analysis run (Cuckoo, de4dot, …).
    Files are either directly-uploaded artifacts or MinIO keys from an existing case.
    """
    # Resolve module
    module = _get_modules_by_id().get(req.module_id)
    if not module:
        custom_by_id = {m["id"]: m for m in _get_custom_modules()}
        module = custom_by_id.get(req.module_id)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module '{req.module_id}' not found")
    if not module.get("available"):
        raise HTTPException(
            status_code=400, detail=module.get("unavailable_reason", "Module unavailable")
        )
    if not req.files:
        raise HTTPException(status_code=400, detail="At least one file is required")

    source_files = [
        {"job_id": "", "filename": f.get("filename", ""), "minio_key": f.get("minio_key", "")}
        for f in req.files
    ]

    run_id = uuid.uuid4().hex
    run_svc.create_module_run(run_id, MALWARE_CASE_ID, req.module_id, source_files)

    try:
        from services.celery_dispatch import dispatch_module

        dispatch_module(run_id, MALWARE_CASE_ID, req.module_id, source_files, req.params)
    except Exception as exc:
        logger.error("Celery dispatch failed for standalone run %s: %s", run_id, exc)
        run_svc.update_module_run(run_id, status="FAILED", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Task dispatch failed: {exc}")

    return {"run_id": run_id, "status": "PENDING"}


@router.get("/malware-analysis/runs")
def list_standalone_runs():
    """List all standalone malware analysis runs (newest first)."""
    return {"runs": run_svc.list_malware_runs()}


# ── YARA utilities ────────────────────────────────────────────────────────────


class ValidateYaraRequest(BaseModel):
    rules: str


@router.post("/modules/yara/validate")
def validate_yara_rules(req: ValidateYaraRequest):
    """
    Validate YARA rules syntax without running a scan.
    Returns {valid: true} or {valid: false, error: "..."}.
    """
    try:
        import yara  # type: ignore

        yara.compile(source=req.rules)
        return {"valid": True}
    except ImportError:
        # yara-python not available in the API container — skip validation
        return {"valid": True, "warning": "yara-python not available in API; validation skipped"}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


# ── Cuckoo Sandbox integration settings ───────────────────────────────────────
# Config is stored in Redis so admins can change it from Settings without
# needing to update K8s env vars or trigger a pod restart.
# The processor reads this key first, then falls back to CUCKOO_API_URL / CUCKOO_API_TOKEN.

_CUCKOO_CONFIG_KEY = rk.CUCKOO_CONFIG


class CuckooConfigUpdate(BaseModel):
    api_url: str
    api_token: str = ""  # leave blank to keep existing token


@router.get("/admin/cuckoo-config")
def get_cuckoo_config():
    """Return current Cuckoo configuration (token presence only, not the value)."""
    r = get_redis()
    data = r.hgetall(_CUCKOO_CONFIG_KEY) or {}
    # Also surface env-var fallback so UI shows "configured via env"
    env_url = os.getenv("CUCKOO_API_URL", "")
    env_token = os.getenv("CUCKOO_API_TOKEN", "")
    api_url = data.get("api_url") or env_url
    token_set = bool(data.get("api_token") or env_token)
    return {
        "api_url": api_url,
        "api_token_set": token_set,
        "configured": bool(api_url),
        "source": "redis" if data.get("api_url") else ("env" if env_url else "none"),
    }


@router.put("/admin/cuckoo-config", dependencies=[Depends(require_admin)])
def set_cuckoo_config(req: CuckooConfigUpdate):
    """Save Cuckoo API URL (and optionally token) to Redis."""
    r = get_redis()
    r.hset(_CUCKOO_CONFIG_KEY, "api_url", req.api_url.rstrip("/"))
    if req.api_token:
        r.hset(_CUCKOO_CONFIG_KEY, "api_token", req.api_token)
    token_set = bool(req.api_token or r.hexists(_CUCKOO_CONFIG_KEY, "api_token"))
    return {"api_url": req.api_url.rstrip("/"), "api_token_set": token_set, "configured": True}


@router.delete("/admin/cuckoo-config", dependencies=[Depends(require_admin)])
def clear_cuckoo_config():
    """Remove Cuckoo configuration from Redis (env-var fallback still applies)."""
    get_redis().delete(_CUCKOO_CONFIG_KEY)
    env_url = os.getenv("CUCKOO_API_URL", "")
    return {"cleared": True, "env_fallback": bool(env_url), "api_url_env": env_url}


# ── VirusTotal / malwoverview config ──────────────────────────────────────────
# Config is stored in Redis so admins can set the VT key from Settings without
# needing a pod restart.  The processor reads fo:config:malwoverview first,
# then falls back to the VT_API_KEY environment variable.

_MALWOVERVIEW_CONFIG_KEY = rk.MALWOVERVIEW_CONFIG


class MalwoverviewConfigUpdate(BaseModel):
    vt_api_key: str = ""  # leave blank to keep existing key


@router.get("/admin/malwoverview-config")
def get_malwoverview_config():
    """Return current VirusTotal/malwoverview configuration (key presence only, not the value)."""
    r = get_redis()
    data = r.hgetall(_MALWOVERVIEW_CONFIG_KEY) or {}
    env_key = os.getenv("VT_API_KEY", "")
    key_set = bool(data.get("vt_api_key") or env_key)
    return {
        "vt_api_key_set": key_set,
        "configured": key_set,
        "source": "redis" if data.get("vt_api_key") else ("env" if env_key else "none"),
    }


@router.put("/admin/malwoverview-config", dependencies=[Depends(require_admin)])
def set_malwoverview_config(req: MalwoverviewConfigUpdate):
    """Save VirusTotal API key to Redis."""
    r = get_redis()
    if req.vt_api_key:
        r.hset(_MALWOVERVIEW_CONFIG_KEY, "vt_api_key", req.vt_api_key)
    key_set = bool(req.vt_api_key or r.hexists(_MALWOVERVIEW_CONFIG_KEY, "vt_api_key"))
    return {"vt_api_key_set": key_set, "configured": key_set}


@router.delete("/admin/malwoverview-config", dependencies=[Depends(require_admin)])
def clear_malwoverview_config():
    """Remove VirusTotal configuration from Redis (env-var fallback still applies)."""
    get_redis().delete(_MALWOVERVIEW_CONFIG_KEY)
    env_key = os.getenv("VT_API_KEY", "")
    return {"cleared": True, "env_fallback": bool(env_key)}


# ── Live log streaming (SSE) ──────────────────────────────────────────────────


@router.get("/module-runs/{run_id}/log-stream")
async def stream_module_log(run_id: str):
    """
    Server-Sent Events stream of log lines for a running module.

    Pushes one JSON object per line: {text: str} during the run,
    then {done: true, status: str} when the run reaches a terminal state.

    Log lines are written to the fo:module_log:{run_id} Redis list by
    the module task at key milestones. The SSE endpoint drains the list
    incrementally and closes when status is COMPLETED or FAILED.
    """
    run = run_svc.get_module_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Module run not found")

    async def event_generator():
        r = get_redis()
        loop = asyncio.get_event_loop()
        cursor = 0
        idle_ticks = 0
        max_idle_ticks = 120  # 120 × 1s = 2 min max wait with no progress

        def _poll(cur: int):
            """All Redis reads for one tick, batched so they run in a worker
            thread — synchronous Redis here would block the event loop (and every
            other request) once enough SSE clients are connected."""
            entries = r.lrange(rk.module_log(run_id), cur, -1)
            status = r.hget(rk.module_run(run_id), "status")
            tool_log = None
            if status in ("COMPLETED", "FAILED", "CANCELLED") and not entries:
                tool_log = r.hget(rk.module_run(run_id), "tool_log") or ""
            return entries, status, tool_log

        while idle_ticks < max_idle_ticks:
            entries, status, tool_log = await loop.run_in_executor(None, _poll, cursor)
            if entries:
                idle_ticks = 0
                for entry in entries:
                    cursor += 1
                    yield f"data: {_json.dumps({'text': entry})}\n\n"

            if status in ("COMPLETED", "FAILED", "CANCELLED") and not entries:
                if tool_log:
                    yield f"data: {_json.dumps({'text': tool_log, 'type': 'summary'})}\n\n"
                yield f"data: {_json.dumps({'done': True, 'status': status})}\n\n"
                return

            idle_ticks += 1
            await asyncio.sleep(1)

        yield f"data: {_json.dumps({'done': True, 'status': 'TIMEOUT'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Studio utility endpoints ──────────────────────────────────────────────────


class QueryTestRequest(BaseModel):
    case_id: str
    query: str


@router.post("/studio/query-test")
def studio_query_test(req: QueryTestRequest):
    """
    Rule playground: run a Lucene query against a case and return the first 10 matching events.
    Used by the Studio alert-rule editor to preview query results without leaving the editor.
    """
    from services.elasticsearch import search_events_for_rule

    if not req.query.strip():
        return {"hits": [], "error": "Empty query"}
    try:
        hits = search_events_for_rule(req.case_id, req.query, size=10)
        return {"hits": hits}
    except Exception as exc:
        return {"hits": [], "error": str(exc)}


class YaraTestRequest(BaseModel):
    case_id: str
    job_id: str
    rules: str


@router.post("/studio/yara-test")
def studio_yara_test(req: YaraTestRequest):
    """
    YARA playground: compile rules and scan a source file from a case, returning matches.
    Downloads up to 10 MB of the file into memory inside the API pod.
    """
    try:
        import yara  # type: ignore
    except ImportError:
        return {"matches": [], "error": "yara-python is not installed in this container"}

    # Compile rules
    try:
        compiled = yara.compile(source=req.rules)
    except Exception as exc:
        return {"matches": [], "error": f"Rule compile error: {exc}"}

    # Resolve minio_key for the job
    job = get_job(req.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    minio_key = job.get("minio_object_key", "")
    if not minio_key:
        return {"matches": [], "error": "Job has no associated file"}

    # Stream up to 10 MB — stop as soon as the cap is reached so an arbitrarily
    # large object is never fully buffered into the pod's RAM.
    _MAX_YARA_BYTES = 10 * 1024 * 1024
    try:
        buf = bytearray()
        for chunk in storage.stream_object(minio_key):
            buf.extend(chunk)
            if len(buf) >= _MAX_YARA_BYTES:
                break
        data = bytes(buf[:_MAX_YARA_BYTES])
    except Exception as exc:
        return {"matches": [], "error": f"File download failed: {exc}"}

    # Scan
    try:
        raw_matches = compiled.match(data=data)
        matches = [
            {
                "rule": m.rule,
                "tags": list(m.tags),
                "strings": [
                    {
                        "identifier": s.identifier,
                        "offset": s.instances[0].offset if s.instances else 0,
                    }
                    for s in m.strings
                ][:20],
            }
            for m in raw_matches
        ]
        return {"matches": matches, "scanned_bytes": len(data)}
    except Exception as exc:
        return {"matches": [], "error": f"Scan error: {exc}"}


# ── Module artifact download & re-ingest ─────────────────────────────────────

from fastapi.responses import RedirectResponse  # noqa: E402


@router.get("/cases/{case_id}/modules/{run_id}/artifacts/{filename}")
def download_module_artifact(case_id: str, run_id: str, filename: str):
    """
    Return a short-lived presigned download URL for a module output artifact
    (e.g. a de4dot-deobfuscated .NET binary).
    The client is redirected directly to MinIO so no large binary passes through
    the API server.
    """
    key = f"cases/{case_id}/modules/{run_id}/artifacts/{filename}"
    try:
        url = storage.get_presigned_url(key, expires_seconds=3600)
        return RedirectResponse(url, status_code=302)
    except Exception as exc:
        logger.warning("Artifact download failed (%s): %s", key, exc)
        raise HTTPException(status_code=404, detail="Artifact not found or expired")


@router.post("/cases/{case_id}/modules/{run_id}/artifacts/{filename}/reingest")
def reingest_module_artifact(case_id: str, run_id: str, filename: str):
    """
    Re-ingest a module output artifact (e.g. a de4dot-deobfuscated binary) back
    into the case timeline as a new ingest job.

    The artifact already lives in MinIO so we skip the upload stage entirely —
    just create a job record pointing at the existing key and dispatch Celery.
    """
    from services import jobs as job_svc
    from services.celery_dispatch import dispatch_ingest

    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    minio_key = f"cases/{case_id}/modules/{run_id}/artifacts/{filename}"
    job_id = uuid.uuid4().hex

    job_svc.create_job(job_id, case_id, filename, "")
    job_svc.update_job(job_id, minio_object_key=minio_key, status="PENDING")

    try:
        dispatch_ingest(job_id, case_id, minio_key, filename)
    except Exception as exc:
        job_svc.update_job(job_id, status="FAILED", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to dispatch ingest: {exc}")

    return {"job_id": job_id, "filename": filename, "status": "PENDING"}
