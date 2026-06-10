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
import os
import uuid
from datetime import UTC, datetime

import redis
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(tags=["harvest"])

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
RUN_TTL = 7 * 24 * 3600


def _get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


# ── category / level metadata (mirrors harvest_task constants) ────────────────
# Imported lazily at request time so the API pod doesn't need the processor deps.


def _get_categories() -> dict:
    """Return HARVEST_CATEGORIES from the task module (or a static copy)."""
    try:
        import importlib
        import sys

        # processor tasks aren't installed in the API container;
        # fall back to a static definition that mirrors the task module.
        raise ImportError
    except ImportError:
        return _STATIC_CATEGORIES


def _get_levels() -> dict:
    try:
        raise ImportError
    except ImportError:
        return _STATIC_LEVELS


# ── Static mirrors of the task-module constants ───────────────────────────────
# These are kept in sync with harvest_task.py manually.

_STATIC_CATEGORIES: dict = {
    "registry": "Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)",
    "eventlogs": "Windows Event Log files (.evtx)",
    "prefetch": "Prefetch / Superfetch execution artifacts (.pf)",
    "mft": "NTFS Master File Table ($MFT, $LogFile)",
    "persistence": "Scheduled tasks and WMI repository",
    "network": "Network configuration: hosts, WLAN profiles, firewall logs",
    "usb_devices": "USB plug history (setupapi logs)",
    "browser_chrome": "Google Chrome browser artifacts",
    "browser_firefox": "Mozilla Firefox browser artifacts",
    "browser_edge": "Microsoft Edge browser artifacts",
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
        "filesystem",
        "browser_chrome",
        "browser_firefox",
        "browser_edge",
        "browser_ie",
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
        "filesystem",
        "browser_chrome",
        "browser_firefox",
        "browser_edge",
        "browser_ie",
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
def start_harvest(case_id: str, req: HarvestRequest):
    """
    Start a harvest run against a disk image or mounted directory.

    The task runs on the `modules` Celery queue.  Use GET /harvest/runs/{run_id}
    to poll progress.  Each artifact found is dispatched as a child ingest job
    (visible in the normal Jobs list under the case).
    """
    # Validate level
    if req.level not in _STATIC_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid level '{req.level}'. Must be: small, complete, exhaustive",
        )

    # Validate categories
    if req.categories:
        unknown = [c for c in req.categories if c not in _STATIC_CATEGORIES]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown categories: {unknown}")

    # Validate source
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
def get_run_status(run_id: str):
    """Return the current status of a harvest run."""
    r = _get_redis()
    raw = r.hgetall(f"harvest_run:{run_id}")
    if not raw:
        raise HTTPException(status_code=404, detail=f"Harvest run {run_id!r} not found")

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
def cancel_run(run_id: str):
    """
    Cancel a harvest run (best-effort — revokes the Celery task if still queued).
    """
    r = _get_redis()
    raw = r.hgetall(f"harvest_run:{run_id}")
    if not raw:
        raise HTTPException(status_code=404, detail=f"Harvest run {run_id!r} not found")

    task_id = raw.get("task_id")
    if task_id:
        try:
            # Best-effort revoke via Redis; harvest_task will check at next opportunity
            import redis as _redis_lib

            _r = _redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
            _r.lpush("celery.revoked", task_id)
        except Exception:
            pass

    r.hset(
        f"harvest_run:{run_id}",
        mapping={
            "status": "CANCELLED",
            "completed_at": datetime.now(UTC).isoformat(),
        },
    )

    return {"run_id": run_id, "status": "CANCELLED"}
