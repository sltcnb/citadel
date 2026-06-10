"""
Harvest task — structured forensic triage with automatic ingest dispatch.

Supports two source modes:
  image   : raw disk image (.dd/.raw/.img) stored in MinIO — read via pytsk3
  mounted : directory path already mounted on the worker (e.g. via dislocker-fuse)

For each selected level/category the task locates known Windows artifact files,
uploads them to MinIO, and fires a child `process_artifact` ingest job so each
file is parsed by the appropriate plugin (EVTX, Registry, MFT, Prefetch, …).

Job status is persisted in Redis under the key  harvest_run:<run_id>.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis
from celery_app import app

logger = logging.getLogger(__name__)

# ── environment ───────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio-service:9000")
MINIO_ACCESS = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "forensics-cases")
RUN_TTL = 7 * 24 * 3600  # 7 days

try:
    import pytsk3 as _pytsk3

    _TSK_OK = True
except ImportError:
    _TSK_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Category definitions
#   paths       : specific file paths relative to the Windows filesystem root
#   dir_exts    : (directory, extension) pairs — collect all matching files in dir
#   user_paths  : paths relative to each user profile dir (Users/<user>/<path>)
#   description : human-readable label
# ─────────────────────────────────────────────────────────────────────────────
HARVEST_CATEGORIES: dict[str, dict] = {
    "registry": {
        "description": "Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, …)",
        "paths": [
            "Windows/System32/config/SYSTEM",
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/SAM",
            "Windows/System32/config/SECURITY",
            "Windows/System32/config/DEFAULT",
            "Windows/System32/config/COMPONENTS",
            "Windows/System32/config/BCD",
            "Windows/System32/Amcache.hve",
        ],
        "user_paths": [
            "NTUSER.DAT",
            "AppData/Local/Microsoft/Windows/UsrClass.dat",
        ],
    },
    "eventlogs": {
        "description": "Windows Event Log files (.evtx)",
        "critical_paths": [
            "Windows/System32/winevt/Logs/Security.evtx",
            "Windows/System32/winevt/Logs/System.evtx",
            "Windows/System32/winevt/Logs/Application.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx",
            "Windows/System32/winevt/Logs/Microsoft-Windows-WinRM%4Operational.evtx",
        ],
        "dir_exts": [("Windows/System32/winevt/Logs", ".evtx")],
    },
    "prefetch": {
        "description": "Prefetch / Superfetch execution artifacts (.pf)",
        "dir_exts": [("Windows/Prefetch", ".pf")],
    },
    "mft": {
        "description": "NTFS Master File Table ($MFT, $LogFile, $UsnJrnl)",
        "paths": ["$MFT", "$LogFile"],
    },
    "persistence": {
        "description": "Scheduled tasks and WMI repository",
        "dir_exts": [
            ("Windows/System32/Tasks", None),
            ("Windows/SysWOW64/Tasks", None),
        ],
        "paths": [
            "Windows/System32/wbem/Repository/OBJECTS.DATA",
            "Windows/System32/wbem/Repository/INDEX.BTR",
        ],
    },
    "network": {
        "description": "Network configuration: hosts, WLAN profiles, firewall logs",
        "paths": [
            "Windows/System32/drivers/etc/hosts",
            "Windows/System32/LogFiles/Firewall/pfirewall.log",
        ],
        "dir_exts": [("ProgramData/Microsoft/Wlansvc/Profiles/Interfaces", ".xml")],
    },
    "usb_devices": {
        "description": "USB plug history (setupapi logs)",
        "paths": [
            "Windows/INF/setupapi.dev.log",
            "Windows/INF/setupapi.setup.log",
        ],
    },
    "browser_chrome": {
        "description": "Google Chrome browser artifacts (History, Cookies, …)",
        "user_paths": [
            "AppData/Local/Google/Chrome/User Data/Default/History",
            "AppData/Local/Google/Chrome/User Data/Default/Cookies",
            "AppData/Local/Google/Chrome/User Data/Default/Web Data",
            "AppData/Local/Google/Chrome/User Data/Default/Login Data",
            "AppData/Local/Google/Chrome/User Data/Default/Bookmarks",
        ],
    },
    "browser_firefox": {
        "description": "Mozilla Firefox browser artifacts (places.sqlite, …)",
        "user_paths": [],  # profiles discovered dynamically — handled in task
        "firefox": True,
    },
    "browser_edge": {
        "description": "Microsoft Edge browser artifacts",
        "user_paths": [
            "AppData/Local/Microsoft/Edge/User Data/Default/History",
            "AppData/Local/Microsoft/Edge/User Data/Default/Cookies",
            "AppData/Local/Microsoft/Edge/User Data/Default/Web Data",
            "AppData/Local/Microsoft/Edge/User Data/Default/Login Data",
        ],
    },
    "browser_ie": {
        "description": "Internet Explorer WebCache",
        "user_paths": [
            "AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
            "AppData/Local/Microsoft/Windows/WebCache/WebCacheV24.dat",
        ],
    },
    "credentials": {
        "description": "LSA secrets, DPAPI, Credential Manager artifacts",
        "paths": [
            "Windows/System32/config/SAM",
            "Windows/System32/config/SECURITY",
        ],
        "user_paths": [
            "AppData/Local/Microsoft/Credentials",
            "AppData/Roaming/Microsoft/Credentials",
            "AppData/Local/Microsoft/Protect",
        ],
    },
    "email_outlook": {
        "description": "Outlook email database (.pst / .ost)",
        "user_paths": [
            "Documents/Outlook Files",
            "AppData/Local/Microsoft/Outlook",
        ],
    },
    "email_thunderbird": {
        "description": "Thunderbird email profiles",
        "user_paths": ["AppData/Roaming/Thunderbird/Profiles"],
    },
    "remote_access": {
        "description": "Remote access tool logs (AnyDesk, TeamViewer, …)",
        "user_paths": ["AppData/Roaming/AnyDesk"],
        "dir_exts": [("ProgramData/TeamViewer/Logs", ".log")],
    },
    "rdp": {
        "description": "RDP / Terminal Services artifacts",
        "user_paths": [
            "AppData/Local/Microsoft/Terminal Server Client/Cache",
        ],
    },
    "ssh_ftp": {
        "description": "SSH / FTP client artifacts (PuTTY, WinSCP, …)",
        "user_paths": [
            ".ssh",
            "AppData/Roaming/PuTTY",
            "AppData/Roaming/WinSCP.ini",
        ],
    },
    "office": {
        "description": "Microsoft Office MRU / trusted documents",
        "user_paths": ["AppData/Roaming/Microsoft/Office"],
    },
    "antivirus": {
        "description": "Windows Defender quarantine and detection logs",
        "paths": [
            "ProgramData/Microsoft/Windows Defender/Quarantine",
            "ProgramData/Microsoft/Windows Defender/Support",
        ],
        "dir_exts": [("ProgramData/Microsoft/Windows Defender/Support", ".log")],
    },
    "wer_crashes": {
        "description": "Windows Error Reporting crash dumps and reports",
        "dir_exts": [
            ("ProgramData/Microsoft/Windows/WER/ReportQueue", None),
            ("ProgramData/Microsoft/Windows/WER/ReportArchive", None),
        ],
    },
    "iis_web": {
        "description": "IIS web server logs",
        "dir_exts": [("inetpub/logs/LogFiles", ".log")],
        "paths": ["Windows/System32/inetsrv/config/applicationHost.config"],
    },
    "active_directory": {
        "description": "Active Directory (NTDS.dit, SYSVOL)",
        "paths": [
            "Windows/NTDS/ntds.dit",
            "Windows/NTDS/edb.log",
        ],
    },
    "dev_tools": {
        "description": "Developer tool artifacts (.gitconfig, PowerShell history, …)",
        "user_paths": [
            ".gitconfig",
            ".git-credentials",
            "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            ".aws/credentials",
            ".azure/accessTokens.json",
        ],
    },
    "password_managers": {
        "description": "Password manager databases (KeePass .kdbx, …)",
        "user_paths": [],
        "dir_exts": [],
    },
    "vpn": {
        "description": "VPN configuration files (OpenVPN, WireGuard, …)",
        "dir_exts": [("ProgramData/OpenVPN/config", ".ovpn")],
        "paths": ["ProgramData/WireGuard"],
    },
    "encryption": {
        "description": "BitLocker and EFS encryption metadata",
        "paths": [
            "Windows/System32/FVE/BDE-Recovery.txt",
        ],
    },
    "boot_uefi": {
        "description": "Boot configuration (BCD, EFI binaries)",
        "paths": [
            "Windows/System32/config/BCD",
            "Windows/bootstat.dat",
        ],
    },
    "logs": {
        "description": "Windows CBS, DISM, Windows Update, Setup logs",
        "paths": [
            "Windows/Logs/CBS/CBS.log",
            "Windows/Logs/DISM/dism.log",
            "Windows/WindowsUpdate.log",
        ],
        "dir_exts": [("Windows/Panther", ".log")],
    },
    "memory": {
        "description": "Memory artifacts (pagefile.sys, hiberfil.sys)",
        "paths": [
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ],
    },
    "execution": {
        "description": "Execution evidence: Prefetch, SRUM, Amcache",
        "paths": [
            "Windows/System32/sru/SRUDB.dat",
            "Windows/System32/Amcache.hve",
        ],
        "dir_exts": [("Windows/Prefetch", ".pf")],
    },
    "filesystem": {
        "description": "NTFS metadata files ($MFT, $LogFile, $Boot)",
        "paths": ["$MFT", "$LogFile", "$Boot"],
    },
    "cloud_onedrive": {
        "description": "OneDrive sync artifacts",
        "user_paths": ["AppData/Local/Microsoft/OneDrive"],
    },
    "cloud_google_drive": {
        "description": "Google Drive sync artifacts",
        "user_paths": ["AppData/Local/Google/DriveFS"],
    },
    "cloud_dropbox": {
        "description": "Dropbox sync artifacts",
        "user_paths": ["AppData/Local/Dropbox"],
    },
    "teams": {
        "description": "Microsoft Teams chat and log artifacts",
        "user_paths": ["AppData/Roaming/Microsoft/Teams/logs.txt"],
    },
    "slack": {
        "description": "Slack workspace artifacts",
        "user_paths": ["AppData/Roaming/Slack/logs"],
    },
    "discord": {
        "description": "Discord cache and log files",
        "user_paths": ["AppData/Roaming/discord/Local Storage"],
    },
    "signal": {
        "description": "Signal Desktop message database",
        "user_paths": ["AppData/Roaming/Signal/databases/db.sqlite"],
    },
    "whatsapp": {
        "description": "WhatsApp Desktop artifacts",
        "user_paths": ["AppData/Local/Packages/5319275A.WhatsAppDesktop_cv1g1gvanyjgm"],
    },
    "telegram": {
        "description": "Telegram Desktop artifacts",
        "user_paths": ["AppData/Roaming/Telegram Desktop/tdata"],
    },
    "gaming": {
        "description": "Gaming platform artifacts (Steam, Epic, …)",
        "user_paths": ["AppData/Local/Steam"],
        "dir_exts": [("ProgramData/Epic/EpicGamesLauncher/Data/Logs", ".log")],
    },
    "printing": {
        "description": "Print spool files",
        "dir_exts": [("Windows/System32/spool/PRINTERS", None)],
    },
    "etw_diagnostics": {
        "description": "ETW diagnostic traces",
        "dir_exts": [("Windows/System32/LogFiles/WMI", ".etl")],
    },
    "windows_apps": {
        "description": "Windows UWP / modern app artifacts (Sticky Notes, Cortana, …)",
        "user_paths": [
            "AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe",
        ],
    },
    "wsl": {
        "description": "Windows Subsystem for Linux filesystem and config",
        "user_paths": ["AppData/Local/Packages/CanonicalGroupLimited.Ubuntu"],
    },
    "virtualization": {
        "description": "Hyper-V, Docker, and VHD inventory",
        "dir_exts": [("ProgramData/Microsoft/Windows/Hyper-V", ".vhd")],
    },
    "recovery": {
        "description": "Volume Shadow Copies, Windows.old",
        "paths": ["System Volume Information"],
    },
    "database_clients": {
        "description": "Database client artifacts (SSMS, DBeaver)",
        "user_paths": [
            "AppData/Roaming/Microsoft SQL Server Management Studio",
            "AppData/Roaming/DBeaverData",
        ],
    },
    "hashing": {
        "description": "Hash catalogue of all collected files",
        "paths": [],  # generated by task, not collected from disk
    },
    "file_listing": {
        "description": "Full volume file listing CSV",
        "paths": [],  # generated by task
    },
    "yara_scanner": {
        "description": "YARA pattern scan results against PE files",
        "paths": [],  # generated by task
    },
}

LEVEL_CATEGORIES: dict[str, list[str]] = {
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
        "email_other",
        "teams",
        "slack",
        "discord",
        "signal",
        "whatsapp",
        "telegram",
        "cloud_onedrive",
        "cloud_google_drive",
        "cloud_dropbox",
        "cloud_other",
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
        "vpn",
        "memory",
        "hashing",
        "file_listing",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem accessor — abstraction over pytsk3 image vs mounted directory
# ─────────────────────────────────────────────────────────────────────────────


class _FsAccess:
    """
    Unified filesystem access over either:
    - A raw disk image file opened with pytsk3
    - A mounted directory already accessible on the local filesystem
    """

    def __init__(self, source: str, partition_offset: int = 0):
        self._source = source
        self._partition_offset = partition_offset
        self._img_info = None
        self._fs_info = None
        self._is_image = False
        self._mount_root: Path | None = None

        src_path = Path(source)
        if src_path.is_dir():
            # Mounted directory
            self._mount_root = src_path
        else:
            # Raw image file
            if not _TSK_OK:
                raise RuntimeError(
                    "pytsk3 is not installed — cannot open disk image. "
                    "Use a mounted directory instead."
                )
            self._img_info = _pytsk3.Img_Info(source)
            self._is_image = True
            # Open the filesystem at the given offset (default 0 = no partition table)
            self._fs_info = self._open_fs(partition_offset)

    # ── pytsk3 helpers ────────────────────────────────────────────────────────

    def _open_fs(self, offset: int) -> Any:
        """Try to open an NTFS filesystem at the given byte offset."""
        try:
            return _pytsk3.FS_Info(self._img_info, offset=offset)
        except Exception:
            return None

    @classmethod
    def _find_ntfs_offset(cls, img_info: Any) -> int:
        """Scan partition table to find the first NTFS partition offset."""
        try:
            volume = _pytsk3.Volume_Info(img_info)
            blk = volume.info.block_size
            for part in volume:
                if not (part.flags & _pytsk3.TSK_VS_PART_FLAG_ALLOC):
                    continue
                offset = part.addr * blk
                try:
                    fs = _pytsk3.FS_Info(img_info, offset=offset)
                    ftype = fs.info.ftype
                    if ftype in (_pytsk3.TSK_FS_TYPE_NTFS, _pytsk3.TSK_FS_TYPE_NTFS_DETECT):
                        return offset
                except Exception:
                    continue
        except Exception:
            pass
        return 0

    @classmethod
    def open_auto(cls, source: str) -> _FsAccess:
        """Open a raw disk image, auto-detecting the NTFS partition."""
        src = Path(source)
        if src.is_dir():
            return cls(source)

        if not _TSK_OK:
            raise RuntimeError("pytsk3 not available")

        img = _pytsk3.Img_Info(source)
        offset = cls._find_ntfs_offset(img)
        return cls(source, partition_offset=offset)

    # ── public API ────────────────────────────────────────────────────────────

    def exists(self, rel_path: str) -> bool:
        """Check if a path exists."""
        try:
            if self._is_image:
                self._fs_info.open(self._tsk_path(rel_path))
                return True
            return (self._mount_root / self._local_path(rel_path)).exists()
        except Exception:
            return False

    def list_dir(self, rel_path: str) -> list[str]:
        """List filenames in a directory. Returns [] if not found."""
        try:
            if self._is_image:
                d = self._fs_info.open_dir(self._tsk_path(rel_path))
                return [
                    e.info.name.name.decode("utf-8", errors="replace")
                    for e in d
                    if e.info.name.name not in (b".", b"..")
                ]
            p = self._mount_root / self._local_path(rel_path)
            return [x.name for x in p.iterdir()] if p.is_dir() else []
        except Exception:
            return []

    def extract_to(self, rel_path: str, dest: Path) -> bool:
        """
        Extract a file from the source filesystem to `dest`.
        Returns True on success.
        """
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if self._is_image:
                return self._extract_image_file(rel_path, dest)
            src = self._mount_root / self._local_path(rel_path)
            if src.is_file() and src.stat().st_size > 0:
                shutil.copy2(src, dest)
                return True
            return False
        except Exception as exc:
            logger.debug("extract_to %s failed: %s", rel_path, exc)
            return False

    # ── internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _tsk_path(rel_path: str) -> str:
        """Normalise a Windows-style relative path for pytsk3 (forward slashes, leading /)."""
        p = rel_path.replace("\\", "/")
        return p if p.startswith("/") else "/" + p

    @staticmethod
    def _local_path(rel_path: str) -> Path:
        """Convert a Windows-style relative path to a local Path object."""
        parts = rel_path.replace("\\", "/").split("/")
        return Path(*parts)

    def _extract_image_file(self, rel_path: str, dest: Path) -> bool:
        tsk_p = self._tsk_path(rel_path)
        f = self._fs_info.open(tsk_p)
        size = f.info.meta.size if f.info.meta else 0
        if size <= 0:
            return False
        CHUNK = 1024 * 1024
        with dest.open("wb") as fh:
            offset = 0
            while offset < size:
                to_read = min(CHUNK, size - offset)
                data = f.read_random(offset, to_read)
                if not data:
                    break
                fh.write(data)
                offset += len(data)
        return dest.stat().st_size > 0

    def close(self) -> None:
        self._img_info = None
        self._fs_info = None


# ─────────────────────────────────────────────────────────────────────────────
# Redis / MinIO helpers
# ─────────────────────────────────────────────────────────────────────────────


def _get_redis() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _get_minio():
    from minio import Minio

    return Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS, secret_key=MINIO_SECRET, secure=False)


def _update_run(r: redis.Redis, run_id: str, **fields) -> None:
    key = f"harvest_run:{run_id}"
    r.hset(
        key,
        mapping={k: (json.dumps(v) if not isinstance(v, str) else v) for k, v in fields.items()},
    )
    r.expire(key, RUN_TTL)


# ─────────────────────────────────────────────────────────────────────────────
# Collection helpers
# ─────────────────────────────────────────────────────────────────────────────


def _upload_and_dispatch(
    minio,
    r: redis.Redis,
    local_file: Path,
    case_id: str,
    run_id: str,
    original_filename: str,
    harvest_category: str,
    *,
    minio_name: str | None = None,
) -> str | None:
    """
    Upload *local_file* to MinIO and dispatch a child ingest job.

    Args:
        original_filename: Basename as the ingest task should see it.  This is
            used by plugin_loader.get_plugin() for filename-based matching
            (e.g. "NTUSER.DAT", "History").  Must NOT include a user prefix.
        minio_name: Optional override for the filename component of the MinIO
            key.  Defaults to *original_filename*.  Use this to store
            user-specific variants without collisions, e.g. "john_NTUSER.DAT".

    Returns:
        job_id on success, None on failure.
    """
    key_name = minio_name or original_filename
    minio_key = f"cases/{case_id}/harvest_{run_id}/{harvest_category}/{key_name}"
    job_id = str(uuid.uuid4())

    try:
        if not minio.bucket_exists(MINIO_BUCKET):
            minio.make_bucket(MINIO_BUCKET)
        minio.fput_object(MINIO_BUCKET, minio_key, str(local_file))

        # Register job in Redis
        r.hset(
            f"job:{job_id}",
            mapping={
                "job_id": job_id,
                "case_id": case_id,
                "status": "PENDING",
                "original_filename": original_filename,
                "minio_object_key": minio_key,
                "events_indexed": "0",
                "error": "",
                "plugin_used": "",
                "plugin_stats": "{}",
                "created_at": datetime.now(UTC).isoformat(),
                "started_at": "",
                "completed_at": "",
                "task_id": "",
                "harvest_run_id": run_id,
                "harvest_category": harvest_category,
            },
        )
        r.expire(f"job:{job_id}", RUN_TTL)

        # Dispatch ingest — pass original_filename so the worker restores the
        # correct local filename and plugin selection works by name.
        app.send_task(
            "ingest.process_artifact",
            args=[job_id, case_id, minio_key, original_filename],
            queue="ingest",
        )
        return job_id
    except Exception as exc:
        logger.warning("[%s] Failed to upload/dispatch %s: %s", run_id, original_filename, exc)
        return None


def _collect_category(
    fs: _FsAccess,
    category: str,
    cat_def: dict,
    level: str,
    work_dir: Path,
    minio,
    r: redis.Redis,
    case_id: str,
    run_id: str,
) -> int:
    """Collect all artifacts for one category. Returns number of files dispatched."""
    dispatched = 0

    def _do_file(
        rel_path: str,
        original_filename: str,
        *,
        local_name: str | None = None,
        minio_name: str | None = None,
    ) -> bool:
        """
        Extract *rel_path* from the filesystem, upload to MinIO, dispatch ingest.

        Args:
            original_filename: Plugin-matching filename (e.g. "NTUSER.DAT").
            local_name: Local disk name to avoid filesystem collisions when
                multiple users provide the same filename (e.g. "john_NTUSER.DAT").
                Defaults to *original_filename*.
            minio_name: MinIO key component override (e.g. "john_NTUSER.DAT").
                Defaults to *local_name* or *original_filename*.
        """
        nonlocal dispatched
        local_dest = work_dir / (local_name or original_filename)
        if fs.extract_to(rel_path, local_dest):
            job = _upload_and_dispatch(
                minio,
                r,
                local_dest,
                case_id,
                run_id,
                original_filename,
                category,
                minio_name=minio_name or local_name,
            )
            if job:
                dispatched += 1
                try:
                    local_dest.unlink()
                except Exception:
                    pass
                return True
        return False

    # 1. Specific named paths
    for path in cat_def.get("paths", []):
        _do_file(path, Path(path).name)

    # 2. Critical paths (used by eventlogs for 'small' level)
    if level == "small" and cat_def.get("critical_paths"):
        for path in cat_def["critical_paths"]:
            _do_file(path, Path(path).name)
    elif cat_def.get("critical_paths") and not cat_def.get("dir_exts"):
        for path in cat_def["critical_paths"]:
            _do_file(path, Path(path).name)

    # 3. Directory scans
    for scan_dir, ext in cat_def.get("dir_exts", []):
        entries = fs.list_dir(scan_dir)
        for entry in entries:
            if ext and not entry.lower().endswith(ext.lower()):
                continue
            rel = f"{scan_dir}/{entry}"
            safe_name = entry.replace(":", "_").replace("%", "_")
            _do_file(rel, safe_name)

    # 4. User-profile paths
    # Critical: pass the ORIGINAL filename (without user prefix) as original_filename
    # so that plugin_loader can match by exact name (e.g. "NTUSER.DAT", "History").
    # Use a user-prefixed local_name / minio_name to avoid filesystem & MinIO collisions.
    user_paths = cat_def.get("user_paths", [])
    firefox = cat_def.get("firefox", False)
    if user_paths or firefox:
        users_dir = "Users"
        users = [
            u
            for u in fs.list_dir(users_dir)
            if u not in (".", "..", "Public", "Default", "Default User", "All Users")
        ]
        for user in users:
            # Standard user_paths
            for upath in user_paths:
                rel = f"{users_dir}/{user}/{upath}"
                orig_filename = Path(upath).name  # e.g. "NTUSER.DAT"
                scoped_name = f"{user}_{orig_filename}"  # e.g. "john_NTUSER.DAT"
                _do_file(rel, orig_filename, local_name=scoped_name, minio_name=scoped_name)

            # Firefox: discover profiles dynamically
            if firefox:
                profiles_dir = f"{users_dir}/{user}/AppData/Roaming/Mozilla/Firefox/Profiles"
                profiles = fs.list_dir(profiles_dir)
                for profile in profiles:
                    for fname in (
                        "places.sqlite",
                        "cookies.sqlite",
                        "downloads.sqlite",
                        "formhistory.sqlite",
                        "key4.db",
                    ):
                        rel = f"{profiles_dir}/{profile}/{fname}"
                        scoped_name = f"{user}_{profile}_{fname}"
                        _do_file(rel, fname, local_name=scoped_name, minio_name=scoped_name)

    return dispatched


# ─────────────────────────────────────────────────────────────────────────────
# Celery task
# ─────────────────────────────────────────────────────────────────────────────


@app.task(bind=True, name="harvest.run_harvest", queue="modules")
def run_harvest(
    self,
    run_id: str,
    case_id: str,
    level: str = "complete",
    categories: list[str] = None,
    minio_object_key: str = None,  # disk image in MinIO
    mounted_path: str = None,  # directory already mounted on worker
    threads: int = 1,
) -> dict[str, Any]:
    """
    Run a forensic triage harvest and dispatch each artifact as an ingest job.

    Either `minio_object_key` (raw disk image) or `mounted_path` (mounted dir)
    must be provided.
    """
    r = _get_redis()
    minio = _get_minio()
    work_dir = Path(tempfile.mkdtemp(prefix=f"harvest_{run_id}_"))
    fs: _FsAccess | None = None

    try:
        _update_run(
            r,
            run_id,
            status="RUNNING",
            started_at=datetime.now(UTC).isoformat(),
            task_id=self.request.id,
            case_id=case_id,
            level=level,
        )

        # ── 1. Resolve source ─────────────────────────────────────────────────
        if mounted_path:
            source_path = mounted_path
            logger.info("[%s] Harvest from mounted path: %s", run_id, mounted_path)
        elif minio_object_key:
            image_name = Path(minio_object_key).name
            local_image = work_dir / image_name
            logger.info("[%s] Downloading image from MinIO: %s", run_id, minio_object_key)
            minio.fget_object(MINIO_BUCKET, minio_object_key, str(local_image))
            logger.info("[%s] Downloaded %d bytes", run_id, local_image.stat().st_size)
            source_path = str(local_image)
        else:
            raise ValueError("Either minio_object_key or mounted_path must be provided")

        # ── 2. Open filesystem accessor ───────────────────────────────────────
        _update_run(r, run_id, status="OPENING_FILESYSTEM")
        try:
            fs = _FsAccess.open_auto(source_path)
        except Exception as exc:
            raise RuntimeError(f"Cannot open source filesystem: {exc}") from exc

        # ── 3. Resolve categories ─────────────────────────────────────────────
        run_cats: list[str] = categories or []
        if not run_cats:
            run_cats = LEVEL_CATEGORIES.get(level, LEVEL_CATEGORIES["complete"])
        # Remove duplicates, preserve order
        seen = set()
        run_cats = [c for c in run_cats if not (c in seen or seen.add(c))]
        logger.info("[%s] Harvesting %d categories: %s", run_id, len(run_cats), run_cats)
        _update_run(r, run_id, categories=json.dumps(run_cats))

        # ── 4. Collect each category ──────────────────────────────────────────
        total_dispatched = 0
        cat_extract_dir = work_dir / "extracted"
        cat_extract_dir.mkdir()

        for cat in run_cats:
            cat_def = HARVEST_CATEGORIES.get(cat)
            if not cat_def:
                logger.warning("[%s] Unknown category %r — skipped", run_id, cat)
                continue
            if (
                not cat_def.get("paths")
                and not cat_def.get("dir_exts")
                and not cat_def.get("user_paths")
                and not cat_def.get("critical_paths")
                and not cat_def.get("firefox")
            ):
                logger.debug("[%s] Category %r has no paths — skipped", run_id, cat)
                continue

            cat_work = cat_extract_dir / cat
            cat_work.mkdir(exist_ok=True)
            _update_run(r, run_id, current_category=cat, total_dispatched=str(total_dispatched))

            try:
                n = _collect_category(fs, cat, cat_def, level, cat_work, minio, r, case_id, run_id)
                total_dispatched += n
                logger.info("[%s] Category %-25s → %d files dispatched", run_id, cat, n)
            except Exception as exc:
                logger.error("[%s] Category %s failed: %s", run_id, cat, exc)

        # ── 5. Complete ────────────────────────────────────────────────────────
        result = {
            "status": "COMPLETED",
            "total_dispatched": str(total_dispatched),
            "completed_at": datetime.now(UTC).isoformat(),
        }
        _update_run(r, run_id, **result)
        logger.info("[%s] Harvest complete — %d ingest jobs dispatched", run_id, total_dispatched)
        return result

    except Exception as exc:
        logger.exception("[%s] Harvest failed: %s", run_id, exc)
        _update_run(
            r, run_id, status="FAILED", error=str(exc), completed_at=datetime.now(UTC).isoformat()
        )
        raise RuntimeError(str(exc)) from None

    finally:
        if fs:
            try:
                fs.close()
            except Exception:
                pass
        shutil.rmtree(work_dir, ignore_errors=True)
