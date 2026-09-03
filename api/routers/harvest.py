"""
Harvest router — ForensicHarvester-style triage with automatic ingest dispatch.

Endpoints
─────────
GET  /harvest/categories              — list all supported collection categories
GET  /harvest/levels                  — list levels and their default categories
POST /cases/{case_id}/harvest         — start a harvest run (image or mounted dir)
GET  /harvest/runs/{run_id}           — poll a harvest run's status
DELETE /harvest/runs/{run_id}         — cancel a pending/running harvest run (best-effort)
"""

from __future__ import annotations

import json
import posixpath
import uuid
from datetime import UTC, datetime

import redis
from auth.dependencies import get_company_filter, get_current_user, require_case_access
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(tags=["harvest"])

from config import settings

REDIS_URL = settings.REDIS_URL  # carries REDIS_PASSWORD auth
RUN_TTL = 7 * 24 * 3600


def _get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _check_harvest_run_access(raw: dict, current_user: dict) -> None:
    """Enforce the caller's company restriction for a run reached by run_id only
    (no case_id path param). Mirrors jobs.py::_check_job_case_access: 404 if the
    run's case is missing, 403 if it belongs to another company."""
    from services.cases import get_case as _get_case

    run_case_id = raw.get("case_id")
    case = _get_case(run_case_id) if run_case_id else None
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    flt = get_company_filter(current_user)
    if flt is not None and case.get("company", "") not in flt:
        raise HTTPException(
            status_code=403,
            detail="Access denied: case belongs to a different company",
        )


# ── category / level metadata (mirrors harvest_task constants) ────────────────
# Imported lazily at request time so the API pod doesn't need the processor deps.


def _get_categories() -> dict:
    """Return HARVEST_CATEGORIES from the worker task module when it is
    importable (dev/monolith deployments), else the static mirror below.

    The worker module pulls in celery/redis/robustness, so in the API container
    the import fails cleanly and the mirror is used."""
    try:
        from harvest_task import HARVEST_CATEGORIES
    except ImportError:
        return _STATIC_CATEGORIES
    return {name: defn.get("description", "") for name, defn in HARVEST_CATEGORIES.items()}


def _get_levels() -> dict:
    try:
        from harvest_task import LEVEL_CATEGORIES
    except ImportError:
        return _STATIC_LEVELS
    return LEVEL_CATEGORIES


# ── Static mirrors of the task-module constants ───────────────────────────────
# These are kept in sync with harvest_task.py manually.

_STATIC_CATEGORIES: dict = {
    "registry": "Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)",
    "eventlogs": "Windows Event Log files (.evtx)",
    "prefetch": "Prefetch / Superfetch execution artifacts (.pf)",
    "mft": "NTFS Master File Table ($MFT, $LogFile)",
    "jumplists": "Jump Lists + Recent — per-user file-access & app-launch timeline",
    "thumbcache": "Thumbnail / icon cache DBs — proves files existed & were viewed",
    "timeline_activity": "Toast notification history (wpndatabase.db)",
    "windows_search": "Windows Search index (Windows.edb) — indexed file metadata",
    "recyclebin": "Recycle Bin — deleted-file metadata ($I) and content ($R), all SIDs",
    "persistence": "Scheduled tasks and WMI repository",
    "network": "Network configuration: hosts, WLAN profiles, firewall logs",
    "usb_devices": "USB plug history (setupapi logs)",
    "browser_chrome": "Google Chrome browser artifacts",
    "browser_firefox": "Mozilla Firefox browser artifacts",
    "browser_edge": "Microsoft Edge browser artifacts",
    "downloads": "Every user's Downloads folder (top-level files)",
    "browser_ie": "Internet Explorer WebCache",
    "credentials": "LSA secrets, DPAPI, Credential Manager",
    "email_outlook": "Outlook .pst / .ost databases",
    "email_thunderbird": "Thunderbird email profiles",
    "remote_access": "Remote access tool logs (AnyDesk, TeamViewer, …)",
    "rdp": "RDP / Terminal Services artifacts",
    "ssh_ftp": "SSH / FTP client artifacts (PuTTY, WinSCP, …)",
    "office": "Microsoft Office MRU / trusted documents",
    "antivirus": "Windows Defender quarantine and detection logs",
    "wer_crashes": "Windows Error Reporting crash dumps and reports",
    "iis_web": "IIS web server logs",
    "active_directory": "Active Directory (NTDS.dit, SYSVOL)",
    "dev_tools": "Developer tool artifacts (.gitconfig, PowerShell history, …)",
    "password_managers": "Password manager databases (KeePass, …)",
    "vpn": "VPN configuration files (OpenVPN, WireGuard, …)",
    "encryption": "BitLocker and EFS encryption metadata",
    "boot_uefi": "Boot configuration (BCD, EFI binaries)",
    "logs": "Windows CBS, DISM, Windows Update, Setup logs",
    "memory": "Memory artifacts (pagefile.sys, hiberfil.sys)",
    "execution": "Execution evidence: SRUM, Amcache, Prefetch",
    "filesystem": "NTFS metadata files ($MFT, $LogFile, $Boot)",
    "cloud_onedrive": "OneDrive sync artifacts",
    "cloud_google_drive": "Google Drive sync artifacts",
    "cloud_dropbox": "Dropbox sync artifacts",
    "teams": "Microsoft Teams chat and log artifacts",
    "slack": "Slack workspace artifacts",
    "discord": "Discord cache and log files",
    "signal": "Signal Desktop message database",
    "whatsapp": "WhatsApp Desktop artifacts",
    "telegram": "Telegram Desktop artifacts",
    "gaming": "Gaming platform artifacts (Steam, Epic, …)",
    "printing": "Print spool files",
    "etw_diagnostics": "ETW diagnostic traces",
    "windows_apps": "Windows UWP / modern app artifacts",
    "wsl": "Windows Subsystem for Linux filesystem and config",
    "virtualization": "Hyper-V, Docker, and VHD inventory",
    "recovery": "Volume Shadow Copies, Windows.old",
    "database_clients": "Database client artifacts (SSMS, DBeaver)",
    "hashing": "Hash catalogue of all collected files (exhaustive only)",
    "file_listing": "Full volume file listing CSV (exhaustive only)",
    "yara_scanner": "YARA pattern scan results against PE files (exhaustive only)",
}

_STATIC_LEVELS: dict = {
    "small": [
        "registry",
        "eventlogs",
        "prefetch",
        "mft",
        "persistence",
        "network",
        "usb_devices",
        "credentials",
        "antivirus",
        "wer_crashes",
        "logs",
        "execution",
        "jumplists",
        "recyclebin",
    ],
    "complete": [
        "registry",
        "eventlogs",
        "prefetch",
        "mft",
        "persistence",
        "network",
        "usb_devices",
        "credentials",
        "antivirus",
        "wer_crashes",
        "logs",
        "execution",
        "jumplists",
        "thumbcache",
        "timeline_activity",
        "windows_search",
        "recyclebin",
        "filesystem",
        "browser_chrome",
        "browser_firefox",
        "browser_edge",
        "browser_ie",
        "downloads",
        "email_outlook",
        "email_thunderbird",
        "teams",
        "slack",
        "discord",
        "signal",
        "cloud_onedrive",
        "cloud_google_drive",
        "cloud_dropbox",
        "remote_access",
        "rdp",
        "ssh_ftp",
        "office",
        "iis_web",
        "active_directory",
        "dev_tools",
        "vpn",
        "encryption",
        "boot_uefi",
        "etw_diagnostics",
        "windows_apps",
        "virtualization",
        "recovery",
    ],
    "exhaustive": [
        "registry",
        "eventlogs",
        "prefetch",
        "mft",
        "persistence",
        "network",
        "usb_devices",
        "credentials",
        "antivirus",
        "wer_crashes",
        "logs",
        "execution",
        "jumplists",
        "thumbcache",
        "timeline_activity",
        "windows_search",
        "recyclebin",
        "filesystem",
        "browser_chrome",
        "browser_firefox",
        "browser_edge",
        "browser_ie",
        "downloads",
        "email_outlook",
        "email_thunderbird",
        "teams",
        "slack",
        "discord",
        "signal",
        "whatsapp",
        "telegram",
        "cloud_onedrive",
        "cloud_google_drive",
        "cloud_dropbox",
        "remote_access",
        "rdp",
        "ssh_ftp",
        "office",
        "iis_web",
        "active_directory",
        "dev_tools",
        "vpn",
        "encryption",
        "boot_uefi",
        "etw_diagnostics",
        "windows_apps",
        "wsl",
        "virtualization",
        "recovery",
        "database_clients",
        "gaming",
        "printing",
        "password_managers",
        "memory",
        "hashing",
        "file_listing",
    ],
}


# ── request / response schemas ────────────────────────────────────────────────


class HarvestRequest(BaseModel):
    level: str = Field(
        "complete",
        description="Collection level: 'small', 'complete', or 'exhaustive'",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Override the level — collect only these specific categories. "
        "Leave empty to use all categories in the selected level.",
    )
    minio_object_key: str | None = Field(
        None,
        description="MinIO object key of a raw disk image (.dd/.raw/.img) to process. "
        "Mutually exclusive with mounted_path.",
    )
    mounted_path: str | None = Field(
        None,
        description="Path to a directory already mounted on the worker "
        "(e.g. /mnt/disk after BitLocker unlock). "
        "Mutually exclusive with minio_object_key.",
    )


def _validate_mounted_path(raw: str) -> str:
    """Confine ``mounted_path`` to the configured harvest roots.

    This value is a worker-side filesystem path and the worker reads whatever
    it is handed, so an unvalidated value let any caller who can start a
    harvest read /etc, /root or /var/log with the worker's privileges. The
    endpoint's case-access check says *which case* you may harvest into, not
    *which directory* you may harvest from.

    Containment is checked on the lexically normalised path rather than
    os.path.realpath: the directory lives on the worker, not in the API
    container, so resolving symlinks here would answer a question about the
    wrong filesystem. Normalisation collapses '..' and duplicate separators,
    which is what defeats the traversal.
    """
    path = (raw or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="mounted_path must not be empty")
    if "\x00" in path:
        raise HTTPException(status_code=400, detail="mounted_path contains a null byte")
    if not path.startswith("/"):
        raise HTTPException(
            status_code=400,
            detail="mounted_path must be an absolute path (e.g. /mnt/disk)",
        )

    normalised = posixpath.normpath(path)
    roots = settings.HARVEST_MOUNT_ROOTS
    allowed = any(
        normalised == root or normalised.startswith(root.rstrip("/") + "/")
        for root in roots
    )
    if not allowed:
        raise HTTPException(
            status_code=400,
            detail=(
                f"mounted_path must be inside one of the configured harvest "
                f"roots ({', '.join(roots)}). Set HARVEST_MOUNT_ROOTS to change them."
            ),
        )
    return normalised


class HarvestRunStatus(BaseModel):
    run_id: str
    status: str
    case_id: str | None = None
    level: str | None = None
    categories: list[str] | None = None
    started_at: str | None = None
    completed_at: str | None = None
    current_category: str | None = None
    total_dispatched: int | None = None
    task_id: str | None = None
    error: str | None = None


# ── endpoints ─────────────────────────────────────────────────────────────────


@router.get("/harvest/categories")
def list_categories():
    """
    Return all supported collection categories with their descriptions.

    Each category maps to one or more artifact families that will be located on
    a Windows filesystem and automatically dispatched as ingest jobs.
    """
    cats = _get_categories()
    return {
        "count": len(cats),
        "categories": [{"name": name, "description": desc} for name, desc in sorted(cats.items())],
    }


@router.get("/harvest/levels")
def list_levels():
    """
    Return the three collection levels (small / complete / exhaustive) and the
    category list each one activates.
    """
    levels = _get_levels()
    return {
        "levels": {name: {"categories": cats, "count": len(cats)} for name, cats in levels.items()}
    }


@router.post("/cases/{case_id}/harvest")
def start_harvest(case_id: str, req: HarvestRequest, _case: dict = Depends(require_case_access)):
    """
    Start a harvest run against a disk image or mounted directory.

    The task runs on the `modules` Celery queue.  Use GET /harvest/runs/{run_id}
    to poll progress.  Each artifact found is dispatched as a child ingest job
    (visible in the normal Jobs list under the case).
    """
    # Validate level
    if req.level not in _get_levels():
        raise HTTPException(
            status_code=400,
            detail=f"Invalid level '{req.level}'. Must be: small, complete, exhaustive",
        )

    # Validate categories
    if req.categories:
        known = _get_categories()
        unknown = [c for c in req.categories if c not in known]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown categories: {unknown}")

    # Validate source
    if req.mounted_path:
        req.mounted_path = _validate_mounted_path(req.mounted_path)
    if not req.minio_object_key and not req.mounted_path:
        raise HTTPException(
            status_code=400,
            detail="Either minio_object_key or mounted_path must be provided",
        )
    if req.minio_object_key and req.mounted_path:
        raise HTTPException(
            status_code=400,
            detail="Provide either minio_object_key or mounted_path, not both",
        )

    # Create run
    run_id = str(uuid.uuid4())
    r = _get_redis()

    r.hset(
        f"harvest_run:{run_id}",
        mapping={
            "run_id": run_id,
            "case_id": case_id,
            "status": "PENDING",
            "level": req.level,
            "categories": json.dumps(req.categories),
            "minio_object_key": req.minio_object_key or "",
            "mounted_path": req.mounted_path or "",
            "created_at": datetime.now(UTC).isoformat(),
        },
    )
    r.expire(f"harvest_run:{run_id}", RUN_TTL)

    # Dispatch Celery task (via direct Redis push — same pattern as other routers)
    from services.celery_dispatch import dispatch_harvest

    dispatch_harvest(
        run_id=run_id,
        case_id=case_id,
        level=req.level,
        categories=req.categories,
        minio_object_key=req.minio_object_key,
        mounted_path=req.mounted_path,
    )

    return {
        "run_id": run_id,
        "status": "PENDING",
        "message": f"Harvest started. Poll /harvest/runs/{run_id} for progress.",
    }


@router.get("/harvest/runs/{run_id}", response_model=HarvestRunStatus)
def get_run_status(run_id: str, current_user: dict = Depends(get_current_user)):
    """Return the current status of a harvest run."""
    r = _get_redis()
    raw = r.hgetall(f"harvest_run:{run_id}")
    if not raw:
        raise HTTPException(status_code=404, detail=f"Harvest run {run_id!r} not found")
    _check_harvest_run_access(raw, current_user)

    # Parse categories JSON string back to list
    cats_raw = raw.get("categories", "[]")
    try:
        cats = json.loads(cats_raw) if cats_raw else []
    except (json.JSONDecodeError, TypeError):
        cats = []

    total = raw.get("total_dispatched")
    return HarvestRunStatus(
        run_id=run_id,
        status=raw.get("status", "UNKNOWN"),
        case_id=raw.get("case_id"),
        level=raw.get("level"),
        categories=cats or None,
        started_at=raw.get("started_at") or None,
        completed_at=raw.get("completed_at") or None,
        current_category=raw.get("current_category") or None,
        total_dispatched=int(total) if total else None,
        task_id=raw.get("task_id") or None,
        error=raw.get("error") or None,
    )


@router.delete("/harvest/runs/{run_id}")
def cancel_run(run_id: str, current_user: dict = Depends(get_current_user)):
    """
    Cancel a harvest run (best-effort — revokes the Celery task if still queued).
    """
    r = _get_redis()
    raw = r.hgetall(f"harvest_run:{run_id}")
    if not raw:
        raise HTTPException(status_code=404, detail=f"Harvest run {run_id!r} not found")
    _check_harvest_run_access(raw, current_user)

    # Only cancel runs that are still in flight — never clobber a terminal state
    # (COMPLETED / FAILED / already CANCELLED).
    current_status = raw.get("status", "UNKNOWN")
    if current_status not in ("PENDING", "RUNNING"):
        return {"run_id": run_id, "status": current_status}

    # Cooperative cancel: the worker polls this flag at category boundaries
    # (same pattern as module runs — rk.module_cancel) and stops cleanly.
    # The old `celery.revoked` Redis-list push was a placebo: nothing read it.
    import redis_keys as rk

    r.set(rk.harvest_cancel(run_id), "1", ex=RUN_TTL)

    r.hset(
        f"harvest_run:{run_id}",
        mapping={
            "status": "CANCELLED",
            "completed_at": datetime.now(UTC).isoformat(),
        },
    )

    return {"run_id": run_id, "status": "CANCELLED"}
