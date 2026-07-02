#!/usr/bin/env python3
"""
Citadel Artifact Collector
==========================
Collect forensic artifacts from a live Windows or Linux system and package
them as a timestamped ZIP archive, then optionally upload directly to a case.

Usage
-----
  talon                                               # collect everything (live OS)
  talon --collect evtx,registry,prefetch              # selective collection
  talon --path /mnt/evidence                          # dead-box: mounted directory
  talon --disk /dev/sdb1 --bitlocker-key 123456-...  # dead-box: raw device (Linux)
  talon --api-url http://CITADEL/api/v1 --case-id XYZ # upload to case
  talon --output /tmp/evidence.zip                    # custom output path
  talon --dry-run --verbose                           # preview only
  talon --fetch "mimikatz*" --fetch "re:\\.(ps1|hta)$" # IOC file sweep
  talon --fetch evil.exe --fetch-root C:\\Users        # scoped filename fetch

Build
-----
  Linux ELF:   ./build.sh        → dist/talon
  Windows EXE: build.bat         → dist\\talon.exe
"""

from __future__ import annotations

# ── Embedded configuration (injected by Citadel at download time) ─────────────
# When non-empty, these values are used as defaults and can still be overridden
# by CLI arguments.
EMBEDDED_CONFIG: dict = {}

# ─────────────────────────────────────────────────────────────────────────────

import argparse
import datetime
import errno
import fnmatch
import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

# ── Load config.json when EMBEDDED_CONFIG was not injected ───────────────────
# ForensicsOperator package mode: config.json ships next to this script.
# Format: {artifact_key: true/false, output_dir, path, disk, skip_problematic, ...}
# BitLocker key: CLI arg takes priority; config.json supported for bootstrap workflows.
if not EMBEDDED_CONFIG:
    _cfg_path = Path(__file__).with_name("config.json")
    if _cfg_path.exists():
        try:
            _raw = json.loads(_cfg_path.read_text("utf-8"))
            _known_cats = {
                "evtx",
                "registry",
                "prefetch",
                "mft",
                "execution",
                "persistence",
                "filesystem",
                "network_cfg",
                "usb_devices",
                "credentials",
                "antivirus",
                "wer_crashes",
                "win_logs",
                "boot_uefi",
                "encryption",
                "etw_diagnostics",
                "browser",
                "browser_chrome",
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
                "lnk",
                "tasks",
                "office",
                "dev_tools",
                "password_managers",
                "database_clients",
                "gaming",
                "windows_apps",
                "wsl",
                "vpn",
                "iis_web",
                "active_directory",
                "virtualization",
                "recovery",
                "printing",
                "pe",
                "documents",
                "memory_artifacts",
                "logs",
                "history",
                "config",
                "cron",
                "ssh",
                "triage",
                "network",
                "suricata",
                "zeek",
                "edr",
                "plist",
                "services",
                "launchagents",
                "network_config",
                "audit_logs",
                "containers",
                "packages",
                "user_artifacts",
                "sysmon",
                "file_search",
            }
            # New format: {"collect": [...], ...}  Old format: {key: true/false, ...}
            if "collect" in _raw and isinstance(_raw["collect"], list):
                _collect = [k for k in _raw["collect"] if k in _known_cats]
            else:
                _collect = [k for k, v in _raw.items() if k in _known_cats and v is True]
            EMBEDDED_CONFIG = {
                "collect": _collect,
                "output_dir": _raw.get("output_dir", "./output"),
                "case_name": _raw.get("case_name", ""),
                "path": _raw.get("path", ""),
                "disk": _raw.get("disk", ""),
                "bitlocker_key": _raw.get("bitlocker_key", ""),
                "skip_problematic": bool(_raw.get("skip_problematic", False)),
                "verbose": bool(_raw.get("verbose", False)),
                "api_url": _raw.get("api_url", ""),
                "case_id": _raw.get("case_id", ""),
                "api_token": _raw.get("api_token", ""),
                "presigned_url": _raw.get("presigned_url", ""),
                "presigned_log_url": _raw.get("presigned_log_url", ""),
                "fetch_patterns": list(_raw.get("fetch_patterns", []) or []),
                "fetch_roots": list(_raw.get("fetch_roots", []) or []),
                "fetch_max_files": int(_raw.get("fetch_max_files", 0) or 0),
                "fetch_max_mb": int(_raw.get("fetch_max_mb", 0) or 0),
            }
        except Exception as _cfg_err:
            print(f"  [!] Warning: could not read config.json: {_cfg_err}", file=sys.stderr)

VERSION = "1.2.0"
HOSTNAME = socket.gethostname()
TS_NOW = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


# ─────────────────────────────────────────────────────────────────────────────
# Execution log — tee everything to a sibling .log file from the very first line,
# so a crash, an OOM kill, or a SIGTERM still leaves (and uploads) a record of
# how far collection got and why it stopped.
# ─────────────────────────────────────────────────────────────────────────────


class _Tee:
    """Mirror a stream to the original console *and* a log file.

    Every write is flushed immediately so nothing is lost if the process is
    killed mid-run. Never raises on the logging side — a broken log handle must
    not take down collection.
    """

    def __init__(self, console, logfh):
        self._console = console
        self._logfh = logfh

    def write(self, txt):
        try:
            self._console.write(txt)
            self._console.flush()
        except Exception:
            pass
        try:
            self._logfh.write(txt)
            self._logfh.flush()
        except Exception:
            pass

    def flush(self):
        for s in (self._console, self._logfh):
            try:
                s.flush()
            except Exception:
                pass

    def __getattr__(self, n):
        return getattr(self._console, n)


# Module-level handle so signal handlers and the finally block can reach the log.
_LOG_FH = None
_LOG_PATH: Path | None = None


def _setup_execution_log(output: Path) -> Path | None:
    """Open <output>.collector.log and tee stdout+stderr into it. Returns the
    log path (or None if the log file could not be opened — collection still
    proceeds, just without an on-disk transcript)."""
    global _LOG_FH, _LOG_PATH
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        log_path = output.with_suffix(output.suffix + ".collector.log")
        fh = open(log_path, "w", encoding="utf-8", errors="replace", buffering=1)
    except Exception as exc:
        print(f"  [!] Could not open execution log: {exc}", file=sys.stderr)
        return None
    _LOG_FH = fh
    _LOG_PATH = log_path
    fh.write(
        f"# Talon execution log — host={HOSTNAME} ts={TS_NOW} "
        f"os={platform.system()} {platform.release()} pid={os.getpid()}\n"
    )
    fh.flush()
    sys.stdout = _Tee(sys.stdout, fh)
    sys.stderr = _Tee(sys.stderr, fh)
    return log_path


def _close_execution_log() -> None:
    global _LOG_FH
    if _LOG_FH is not None:
        try:
            _LOG_FH.flush()
            _LOG_FH.close()
        except Exception:
            pass
        _LOG_FH = None


class _Killed(SystemExit):
    """Raised by the signal handler so main()'s finally block runs (flush +
    upload the log) before the process exits on SIGTERM/SIGINT."""


def _install_signal_handlers() -> None:
    import signal

    def _handler(signum, _frame):
        # Don't do heavy work in the handler — just record and unwind to finally.
        try:
            print(
                f"\n  [!] Received signal {signum} — flushing execution log and aborting.",
                file=sys.stderr,
            )
        except Exception:
            pass
        raise _Killed(143 if signum == getattr(signal, "SIGTERM", None) else 130)

    for _name in ("SIGTERM", "SIGINT", "SIGBREAK", "SIGHUP"):
        _sig = getattr(signal, _name, None)
        if _sig is not None:
            try:
                signal.signal(_sig, _handler)
            except (ValueError, OSError, RuntimeError):
                pass  # not on main thread / not supported on this OS


def _fmt_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


def _disk_free(path: Path) -> tuple[int, int] | None:
    """(free_bytes, total_bytes) for the volume holding path, or None if it
    can't be determined. Walks up to the nearest existing parent."""
    p = path
    for _ in range(8):
        try:
            if p.exists():
                u = shutil.disk_usage(str(p))
                return u.free, u.total
        except Exception:
            pass
        if p.parent == p:
            break
        p = p.parent
    return None


# Refuse to start / keep going below this much free space on the output volume.
_LOW_SPACE_BYTES = 200 * 1024 * 1024  # 200 MB


def _log_disk_space(output: Path, staging: Path) -> None:
    """Log free space on both the output volume and the staging/temp volume.
    A full disk is the most common cause of a truncated 22-byte ZIP and of the
    process being OOM/IO-killed mid-collection — so record it up front."""
    for label, p in (("output", output.parent), ("staging", staging)):
        info = _disk_free(p)
        if info is None:
            print(f"  Disk ({label}) : free space unknown for {p}")
            continue
        free, total = info
        warn = "  ⚠ LOW" if free < _LOW_SPACE_BYTES else ""
        print(
            f"  Disk ({label}) : {_fmt_bytes(free)} free of {_fmt_bytes(total)}  "
            f"[{p}]{warn}"
        )
        if free < _LOW_SPACE_BYTES:
            print(
                f"  [!] Only {_fmt_bytes(free)} free on the {label} volume — collection may "
                "truncate or fail. Free space or point --output at a larger volume.",
                file=sys.stderr,
            )


def _enable_backup_privilege() -> bool:
    """Enable SeBackupPrivilege so we can read ACL-protected files on dead-box disks."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        import ctypes.wintypes

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        class _LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.c_long)]

        class _LUID_AND_ATTR(ctypes.Structure):
            _fields_ = [("Luid", _LUID), ("Attributes", ctypes.wintypes.DWORD)]

        class _TOKEN_PRIVS(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.wintypes.DWORD),
                ("Privileges", _LUID_AND_ATTR * 1),
            ]

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        h = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h),
        ):
            return False

        luid = _LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeBackupPrivilege", ctypes.byref(luid)):
            kernel32.CloseHandle(h)
            return False

        tp = _TOKEN_PRIVS()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        advapi32.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None)
        ok = kernel32.GetLastError() == 0
        kernel32.CloseHandle(h)
        return ok
    except Exception:
        return False


BANNER = f"""
╔══════════════════════════════════════════════════════════════╗
║         ForensicsOperator Harvester  v{VERSION}                    ║
╚══════════════════════════════════════════════════════════════╝"""

_HR = "  " + "─" * 62  # section separator line

# Default collection sets — all enabled when nothing is specified
DEFAULT_WINDOWS = {
    "evtx",
    "registry",
    "prefetch",
    "lnk",
    "browser",
    "tasks",
    "mft",
    "triage",
    "sysmon",
    "antivirus",
}
DEFAULT_LINUX = {
    "logs",
    "history",
    "config",
    "cron",
    "ssh",
    "triage",
    "persistence",
    "network_config",
    "audit_logs",
    "containers",
    "suricata",
    "zeek",
    "antivirus",
    "sysmon",
}
DEFAULT_MACOS = {
    "logs",
    "history",
    "config",
    "launchagents",
    "browser",
    "plist",
    "triage",
    "network",
}
# "pe" and "documents" are opt-in — they can be large and broad in scope.
# Add explicitly: --collect pe,documents,evtx
# "memory" is intentionally NOT in the defaults — dumps are multi-GB.
# Add explicitly with --collect memory or --collect memory,evtx,...

# Human-readable names (used in the header printout)
ARTIFACT_LABELS = {
    # ── Live Windows ──────────────────────────────────────────────────────────
    "evtx": "Event Logs (EVTX)",
    "registry": "Registry Hives",
    "prefetch": "Prefetch Files",
    "lnk": "LNK / Recent Items",
    "browser": "Browser Artifacts (all)",
    "tasks": "Scheduled Tasks",
    "mft": "Master File Table ($MFT)",
    "pe": "PE / Executable Binaries",
    "documents": "Office Documents & PDFs",
    "downloads": "Downloads Folders (all files)",
    "triage": "System Triage (live)",
    # ── Dead-box / ForensicHarvester categories ───────────────────────────────
    "execution": "Execution Evidence (SRUM, Amcache, Prefetch)",
    "persistence": "Persistence (Tasks, WMI)",
    "network_cfg": "Network Config (Hosts, WLAN, Firewall)",
    "usb_devices": "USB Device History",
    "credentials": "Credentials (DPAPI, Credential Manager)",
    "antivirus": "Antivirus / EDR (logs, quarantine, detections)",
    "sysmon": "Sysmon (events, config, archive)",
    "file_search": "File Search (regex / glob / filename fetch)",
    "wer_crashes": "WER Crash Dumps & Reports",
    "filesystem": "NTFS Metadata ($MFT, $LogFile, $Boot)",
    "browser_chrome": "Chrome Browser Artifacts",
    "browser_firefox": "Firefox Browser Artifacts",
    "browser_edge": "Edge Browser Artifacts",
    "browser_ie": "Internet Explorer WebCache",
    "email_outlook": "Outlook Email (.pst / .ost)",
    "email_thunderbird": "Thunderbird Email",
    "teams": "Microsoft Teams",
    "slack": "Slack",
    "discord": "Discord",
    "signal": "Signal Desktop",
    "whatsapp": "WhatsApp Desktop",
    "telegram": "Telegram Desktop",
    "cloud_onedrive": "OneDrive Sync Artifacts",
    "cloud_google_drive": "Google Drive Sync Artifacts",
    "cloud_dropbox": "Dropbox Sync Artifacts",
    "remote_access": "Remote Access (AnyDesk, TeamViewer)",
    "rdp": "RDP / Terminal Services",
    "ssh_ftp": "SSH / FTP Clients (PuTTY, WinSCP)",
    "office": "Office MRU / Trusted Documents",
    "iis_web": "IIS Web Server Logs",
    "active_directory": "Active Directory (NTDS.dit, SYSVOL)",
    "dev_tools": "Dev Tools (.gitconfig, PS history, .aws)",
    "password_managers": "Password Managers (KeePass)",
    "vpn": "VPN Config (OpenVPN, WireGuard)",
    "encryption": "Encryption Metadata (BitLocker / EFS)",
    "boot_uefi": "Boot Config (BCD, EFI)",
    "win_logs": "Windows Logs (CBS, DISM, WU)",
    "memory_artifacts": "Memory Artifacts (pagefile, hiberfil)",
    "etw_diagnostics": "ETW Diagnostic Traces",
    "windows_apps": "Windows UWP / Modern Apps",
    "wsl": "WSL Filesystem & Config",
    "virtualization": "Virtualization (Hyper-V, Docker)",
    "recovery": "Recovery (VSS, Windows.old)",
    "database_clients": "Database Clients (SSMS, DBeaver)",
    "gaming": "Gaming Platforms (Steam, Epic)",
    "printing": "Print Spool Files",
    # ── Linux / macOS ────────────────────────────────────────────────────────
    "logs": "System Logs",
    "history": "Shell Histories",
    "config": "System Configuration",
    "cron": "Cron Jobs",
    "ssh": "SSH Artifacts",
    "launchagents": "Launch Agents / Daemons",
    "plist": "macOS Preference Plists",
    "network": "PCAP / Network Captures",
    "suricata": "Suricata IDS Logs (EVE JSON)",
    "zeek": "Zeek / Bro Network Logs",
    "memory": "Physical Memory Dump (live acquisition)",
    "external_disk": "External / BitLocker Disk Triage",
}

# ── Priority EVTX channels (shared by live + dead-box collection) ─────────────
# Collected first, before the *.evtx glob fills up the per-run cap.
EVTX_PRIORITY = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-WinRM%4Operational.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
    # Antivirus / Defender (correct channel name contains a space)
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4WHC.evtx",
    "Microsoft-Windows-WindowsDefender%4Operational.evtx",  # legacy/typo fallback
    "Symantec Endpoint Protection Client.evtx",
    # Execution / lateral movement / tampering
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-AppLocker%4EXE and DLL.evtx",
    "Microsoft-Windows-AppLocker%4MSI and Script.evtx",
    "Microsoft-Windows-CodeIntegrity%4Operational.evtx",
    "Microsoft-Windows-Shell-Core%4Operational.evtx",
    "Microsoft-Windows-NTLM%4Operational.evtx",
    "Microsoft-Windows-SMBServer%4Security.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx",
    "Microsoft-Windows-GroupPolicy%4Operational.evtx",
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
    "Microsoft-Windows-DNS-Client%4Operational.evtx",
    "Microsoft-Windows-PrintService%4Operational.evtx",
    "OpenSSH%4Operational.evtx",
]


# ─────────────────────────────────────────────────────────────────────────────
# Base Collector
# ─────────────────────────────────────────────────────────────────────────────


class Collector:
    def __init__(
        self,
        output: Path,
        collect: set[str],
        verbose: bool = False,
        dry_run: bool = False,
        skip_problematic: bool = False,
        fetch_patterns: list[str] | None = None,
        fetch_roots: list[str] | None = None,
        fetch_max_files: int = 200,
        fetch_max_mb: int = 100,
    ):
        self.output = output
        self.collect = collect
        self.verbose = verbose
        self.dry_run = dry_run
        self.skip_problematic = skip_problematic
        self.fetch_patterns = fetch_patterns or []
        self.fetch_roots = fetch_roots or []
        self.fetch_max_files = fetch_max_files
        self.fetch_max_mb = fetch_max_mb
        self.staging = Path(tempfile.mkdtemp(prefix="fo_collect_"))
        self._items: list[tuple[str, Path]] = []
        self._errors: list[str] = []
        self._seen_arcnames: set[str] = set()  # duplicate path guard
        # Progress / results tracking
        self._results: list[dict] = []
        self._total_cats: int = 0
        self._current_cat: int = 0

    def _want(self, key: str) -> bool:
        return key in self.collect

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"      {msg}")

    def _warn(self, msg: str) -> None:
        self._errors.append(msg)
        # Buffered during _timed(); written directly otherwise.
        print(f"  [!] {msg}", file=sys.stderr)

    def _check_deadbox_mode(self) -> dict:
        """
        Check if running in dead-box directory mode and warn about limitations.
        Returns a dict of problematic categories and reasons.
        """
        warnings = {}

        # Check if we're accessing a mounted filesystem (not live OS)
        is_deadbox = False
        if hasattr(self, "disk") and getattr(self, "disk", None):
            is_deadbox = True
        elif IS_WINDOWS:
            # Check if SystemDrive is different from C: or path looks like mount
            sys_drive = os.environ.get("SystemDrive", "C:")
            if sys_drive != "C:" or (
                hasattr(self, "_ntfs_dir") and getattr(self, "_ntfs_dir", None)
            ):
                is_deadbox = True

        if not is_deadbox:
            return warnings

        # Categories that typically fail in dead-box directory mode
        DEADBOX_LIMITATIONS = {
            "mft": "$MFT requires raw volume access (\\\\.\\C:) - not available in directory mount mode",
            "filesystem": "NTFS metadata ($MFT, $Boot, $LogFile) requires raw volume handle",
            "prefetch": "Prefetch files may be WOF-compressed (Win10+) or have reparse points",
            "tasks": "C:\\Windows\\System32\\Tasks often contains reparse points",
            "browser_ie": "WebCache directories frequently use reparse points",
            "memory_artifacts": "pagefile.sys and hiberfil.sys are locked by the OS",
        }

        for cat, reason in DEADBOX_LIMITATIONS.items():
            if cat in self.collect:
                warnings[cat] = reason

        return warnings

    def _add(self, src: Path, arcname: str) -> bool:
        arcname = arcname.replace("\\", "/")
        if not src.exists() or not src.is_file():
            self._log(f"missing  {src}")
            return False
        try:
            size = src.stat().st_size
        except OSError as exc:
            self._warn(f"stat failed {src.name}: {exc}")
            return False
        if size == 0:
            self._log(f"empty    {src.name}")
            return False
        # Deduplicate arcnames — same relative path can appear for multiple users
        if arcname in self._seen_arcnames:
            if "." in arcname.split("/")[-1]:
                stem, ext = arcname.rsplit(".", 1)
            else:
                stem, ext = arcname, ""
            n = 2
            while True:
                candidate = f"{stem}_{n}.{ext}" if ext else f"{stem}_{n}"
                if candidate not in self._seen_arcnames:
                    arcname = candidate
                    break
                n += 1
        self._seen_arcnames.add(arcname)
        self._items.append((arcname, src))
        self._log(f"ok  ({size:>11,} B)  {arcname}")
        return True

    # ── Per-category progress tracking ───────────────────────────────────────

    @contextmanager
    def _timed(self, key: str, label: str):
        """
        Context manager that wraps a single artifact-category collection call.
        • Prints a live 'collecting…' placeholder on stdout.
        • Suppresses the [*] section-header that _from() methods print.
        • Buffers stderr (warnings) so they don't interleave with the status line.
        • On exit: overwrites the placeholder with a result line (files / time / ✓✗).
        • Appends a result dict to self._results for the final summary.
        """
        self._current_cat += 1
        idx = self._current_cat
        total = self._total_cats or "?"
        pad = f"{label:<44}"
        pfx = f"  [{idx:>2}/{total}]  {pad}"

        items_before = len(self._items)
        errors_before = len(self._errors)
        t0 = time.monotonic()

        # Live placeholder — overwritten by the result line on exit
        sys.stdout.write(f"{pfx}  collecting…\r")
        sys.stdout.flush()

        # ── stdout filter: swallow "  [*] …" lines emitted by _from() methods ──
        class _FilterOut:
            def __init__(self, w):
                self._w = w
                self._skip_nl = False

            def write(self, txt):
                if "  [*]" in txt:
                    self._skip_nl = True
                    return
                if self._skip_nl and txt in ("\n", "\r\n", "\r"):
                    self._skip_nl = False
                    return
                self._skip_nl = False
                self._w.write(txt)

            def flush(self):
                self._w.flush()

            def __getattr__(self, n):
                return getattr(self._w, n)

        # ── stderr capture: keep warnings from interleaving with status lines ──
        class _BufErr:
            def __init__(self):
                self._buf = io.StringIO()

            def write(self, txt):
                self._buf.write(txt)

            def flush(self):
                pass

            def getvalue(self):
                return self._buf.getvalue()

            def __getattr__(self, n):
                return getattr(sys.__stderr__, n)

        orig_out = sys.stdout
        orig_err = sys.stderr
        ferr = _BufErr()
        sys.stdout = _FilterOut(orig_out)
        sys.stderr = ferr
        try:
            yield
        finally:
            sys.stdout = orig_out
            sys.stderr = orig_err

            elapsed = time.monotonic() - t0
            added = len(self._items) - items_before
            new_errs = self._errors[errors_before:]
            ok = added > 0
            mark = "✓" if ok else "✗"
            stat = f"  {added:>5} files  {elapsed:>5.1f}s  {mark}"
            if not ok and new_errs:
                stat += f"  ({new_errs[0][:36]})"
            print(f"{pfx}{stat}")

            # Flush captured warnings in verbose mode only
            if self.verbose:
                captured = ferr.getvalue()
                if captured:
                    sys.stderr.write(captured)

            self._results.append(
                {
                    "label": label,
                    "files": added,
                    "duration": elapsed,
                    "ok": ok,
                    "errors": list(new_errs),
                }
            )

    def _run_cat(self, key: str, fn, *args) -> None:
        """Run fn(*args) inside a _timed() context if the category is wanted."""
        if self._want(key):
            label = ARTIFACT_LABELS.get(key, key)
            with self._timed(key, label):
                try:
                    fn(*args)
                except Exception as exc:
                    self._warn(f"Collection error in '{key}': {exc}")

    def _copy_locked(self, src: Path, dest: Path) -> bool:
        """
        Copy a file that may be locked (browser databases, Event Logs).

        Cross-platform: works on Windows, Linux, macOS.
        On live Windows: uses robocopy for WOF compression.
        On mounted drives: uses binary I/O to avoid timeouts.
        """
        if not src.exists() or not src.is_file():
            return False

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Method 1: Binary read/write (most reliable, cross-platform)
        try:
            with open(src, "rb") as fsrc:
                with open(dest, "wb") as fdst:
                    shutil.copyfileobj(fsrc, fdst, length=1024 * 1024)
            if dest.exists() and dest.stat().st_size > 0:
                return True
        except Exception:
            pass

        # Clean up
        try:
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
        except Exception:
            pass

        # Windows: try robocopy for WOF (live Windows only, not mounted)
        if IS_WINDOWS and not self._is_mounted_drive(src):
            if self._copy_with_robocopy(src, dest):
                return True
            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass

        # Windows: cmd copy fallback
        if IS_WINDOWS:
            try:
                r = subprocess.run(
                    ["cmd", "/c", "copy", "/B", "/Y", str(src), str(dest)],
                    capture_output=True,
                    timeout=10,
                )
                if r.returncode == 0 and dest.exists() and dest.stat().st_size > 0:
                    return True
            except Exception:
                pass

            try:
                dest.unlink(missing_ok=True)
            except Exception:
                pass

            # Final fallback: robocopy /B (backup semantics, bypasses ACL restrictions).
            # Requires SeBackupPrivilege — enabled at startup when running as Administrator.
            if self._copy_with_backup_robocopy(src, dest):
                return True

        return False

    def _is_mounted_drive(self, path: Path) -> bool:
        """
        Detect if path is a mounted drive (dead-box) vs live Windows.
        Returns True for mounted drives where robocopy causes timeouts.
        """
        if not IS_WINDOWS:
            return True  # Non-Windows is always mounted

        # Extract drive letter
        drive = str(path)[:2].upper()
        if len(drive) != 2 or drive[1] != ":":
            return True  # Not a drive letter path

        # C: is always live (system drive)
        if drive == "C:":
            return False

        # Check drive type - NETWORK/UNKNOWN = mounted
        try:
            import ctypes

            drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\")
            # DRIVE_REMOTE = 4 (network), DRIVE_NO_ROOT_DIR = 0 (invalid)
            # DRIVE_FIXED = 3 (local hard drive)
            if drive_type in (0, 4):
                return True  # Network/invalid = mounted
        except Exception:
            # If we can't check, assume non-C: drives are mounted
            return True

        # For fixed drives other than C:, check if it's the system drive
        sys_drive = os.environ.get("SystemDrive", "C:").upper()
        return drive != sys_drive

    def _copy_with_robocopy(self, src: Path, dest: Path) -> bool:
        """
        Use robocopy for WOF-compressed files (Windows 10+ Prefetch).
        ONLY used on live Windows - skipped for mounted drives (causes timeouts).
        """
        if not IS_WINDOWS or not src.exists():
            return False

        # Skip robocopy for mounted drives (causes semaphore timeouts)
        if self._is_mounted_drive(src):
            self._log(f"Skipping robocopy for mounted drive: {src.name}")
            return False

        try:
            r = subprocess.run(
                [
                    "robocopy",
                    str(src.parent),
                    str(dest.parent),
                    str(src.name),
                    "/NJH",
                    "/NJS",
                    "/NDL",
                    "/NFL",
                    "/BYTES",
                    "/R:0",
                    "/W:0",
                ],
                capture_output=True,
                timeout=30,
            )
            # robocopy returns 0-7 for success, 8+ for errors
            return r.returncode <= 7 and dest.exists() and dest.stat().st_size > 0
        except Exception:
            return False

    def _copy_with_backup_robocopy(self, src: Path, dest: Path) -> bool:
        """
        Copy using robocopy /B (backup semantics) — bypasses ACL restrictions.
        Works on any Windows path including dead-box mounted drives.
        Requires SeBackupPrivilege (enabled at startup when running as Administrator).
        """
        if not IS_WINDOWS or not src.exists():
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run(
                [
                    "robocopy",
                    str(src.parent),
                    str(dest.parent),
                    str(src.name),
                    "/B",
                    "/NJH",
                    "/NJS",
                    "/NDL",
                    "/NFL",
                    "/BYTES",
                    "/R:0",
                    "/W:0",
                ],
                capture_output=True,
                timeout=30,
            )
            return r.returncode <= 7 and dest.exists() and dest.stat().st_size > 0
        except Exception:
            return False

    def _stage_file(self, src: Path, dest: Path) -> bool:
        """
        Copy src to dest for staging with smart fallback strategy.

        Cross-platform: works on Windows, Linux, macOS.
        Handles WOF compression on live Windows, avoids timeouts on mounted drives.
        """
        if not src.exists() or not src.is_file():
            return False

        try:
            src_size = src.stat().st_size
            if src_size == 0:
                return False
        except OSError:
            return False

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Method 1: Simple binary read/write (cross-platform, most reliable)
        try:
            with open(src, "rb") as fsrc:
                with open(dest, "wb") as fdst:
                    shutil.copyfileobj(fsrc, fdst, length=1024 * 1024)  # 1MB chunks
            if dest.exists() and dest.stat().st_size > 0:
                return True
        except (PermissionError, OSError) as exc:
            self._log(
                f"read/write failed: {src.name} - {exc.errno if hasattr(exc, 'errno') else exc}"
            )
        except Exception as exc:
            self._log(f"read/write failed: {src.name} - {exc}")

        # Clean up partial copy
        try:
            if dest.exists() and dest.stat().st_size == 0:
                dest.unlink()
        except Exception:
            pass

        # Windows-only: try robocopy for WOF compression (live Windows only)
        if IS_WINDOWS and not self._is_mounted_drive(src):
            if self._copy_with_robocopy(src, dest):
                return True
            # Clean up failed robocopy attempt
            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass

        # Windows-only: cmd /c copy fallback for locked files
        if IS_WINDOWS:
            try:
                r = subprocess.run(
                    ["cmd", "/c", "copy", "/B", "/Y", str(src), str(dest)],
                    capture_output=True,
                    timeout=10,
                )
                if r.returncode == 0 and dest.exists() and dest.stat().st_size > 0:
                    return True
            except Exception:
                pass

            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass

            # Final fallback: robocopy /B (backup semantics, bypasses ACL restrictions).
            # Requires SeBackupPrivilege — enabled at startup when running as Administrator.
            if self._copy_with_backup_robocopy(src, dest):
                return True

            try:
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()
            except Exception:
                pass

        return False

    def _run_cmd(self, cmd: list[str], timeout: int = 30) -> str:
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            return r.stdout
        except Exception as exc:
            self._log(f"cmd failed {cmd[0]}: {exc}")
            return ""

    def _write_text(self, filename: str, content: str, arcname: str) -> None:
        dest = self.staging / filename
        try:
            dest.write_text(content, encoding="utf-8", errors="replace")
            self._add(dest, arcname)
        except Exception as exc:
            self._warn(f"Could not write {filename}: {exc}")

    # ── Generic file fetch (regex / glob / filename) ──────────────────────────

    # Directory fragments never worth walking during an IOC sweep — huge and
    # noisy. Matched as case-insensitive substrings of the normalized dir path.
    _FETCH_EXCLUDES = (
        "/proc/",
        "/sys/",
        "/dev/",
        "/run/",
        "/snap/",
        "/windows/winsxs/",
        "/windows/servicing/",
        "/windows/installer/",
        "/windows/softwaredistribution/",
        "/program files/windowsapps/",
    )

    def _file_search(self, roots: list[Path] | None = None) -> None:
        """
        Fetch arbitrary files matched by filename, glob, or regex.

        Pattern syntax (per entry in --fetch / fetch_patterns):
          • "re:<regex>"     — Python regex (case-insensitive). Matched against
                               the full path (forward slashes) when the regex
                               contains "/", otherwise against the filename.
          • glob ("*", "?")  — fnmatch against the filename (case-insensitive).
          • plain string     — exact filename match (case-insensitive).
        """
        print("  [*] File Search (regex / filename)")
        if not self.fetch_patterns:
            self._warn("file_search enabled but no patterns given (--fetch)")
            return

        compiled: list[tuple[str, object]] = []
        for raw in self.fetch_patterns:
            raw = raw.strip()
            if not raw:
                continue
            if raw.startswith("re:"):
                expr = raw[3:]
                try:
                    rx = re.compile(expr, re.IGNORECASE)
                except re.error as exc:
                    self._warn(f"Bad regex '{expr}': {exc}")
                    continue
                compiled.append(("re_path" if "/" in expr else "re_name", rx))
            elif any(ch in raw for ch in "*?["):
                compiled.append(("glob", raw.lower()))
            else:
                compiled.append(("exact", raw.lower()))
        if not compiled:
            return

        if self.fetch_roots:
            roots = [Path(r) for r in self.fetch_roots]
        elif roots is None:
            if IS_WINDOWS:
                roots = [Path(os.environ.get("SystemDrive", "C:") + "\\")]
            else:
                roots = [Path("/")]

        max_files = self.fetch_max_files
        max_size = self.fetch_max_mb * 1024 * 1024
        deadline = time.monotonic() + 600  # hard wall: 10 min sweep
        staging_norm = str(self.staging.resolve()).replace("\\", "/").lower()
        count = 0
        timed_out = False

        for root in roots:
            if count >= max_files or timed_out:
                break
            if not root.exists():
                self._log(f"fetch root missing: {root}")
                continue
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if time.monotonic() > deadline:
                    timed_out = True
                if count >= max_files or timed_out:
                    dirnames[:] = []
                    break
                norm_dir = dirpath.replace("\\", "/").rstrip("/").lower() + "/"
                if norm_dir.startswith(staging_norm) or any(
                    ex in norm_dir for ex in self._FETCH_EXCLUDES
                ):
                    dirnames[:] = []
                    continue
                for fname in filenames:
                    if count >= max_files:
                        break
                    low = fname.lower()
                    hit = False
                    for kind, pat in compiled:
                        if kind == "exact":
                            hit = low == pat
                        elif kind == "glob":
                            hit = fnmatch.fnmatchcase(low, pat)
                        elif kind == "re_name":
                            hit = bool(pat.search(fname))
                        else:  # re_path
                            hit = bool(pat.search(norm_dir + fname))
                        if hit:
                            break
                    if not hit:
                        continue
                    src = Path(dirpath) / fname
                    try:
                        if src.is_symlink():
                            continue
                        size = src.stat().st_size
                    except OSError:
                        continue
                    if size == 0:
                        continue
                    if size > max_size:
                        self._log(f"skip (> {self.fetch_max_mb} MB)  {src}")
                        continue
                    rel = (norm_dir + fname).replace(":", "").lstrip("/")
                    tmp = self.staging / f"fsr_{count}_{fname}"
                    if self._stage_file(src, tmp) and self._add(tmp, f"file_search/{rel}"):
                        count += 1
        if timed_out:
            self._warn(f"file_search hit the 10-minute wall after {count} file(s)")
        print(f"      matched {count} file(s)")

    # ── Antivirus / EDR (Windows paths — shared by live + dead-box) ──────────

    # vendor → glob (relative to drive root). Logs, quarantine, detections.
    _WIN_AV_DIRS: list[tuple[str, str]] = [
        # Microsoft Defender
        ("defender", "ProgramData/Microsoft/Windows Defender/Quarantine"),
        ("defender", "ProgramData/Microsoft/Windows Defender/Support"),
        (
            "defender",
            "ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory",
        ),
        # Trend Micro — Apex One / OfficeScan / Worry-Free agent + Deep Security
        ("trendmicro", "ProgramData/Trend Micro"),
        ("trendmicro", "Program Files*/Trend Micro/Security Agent/Logs"),
        ("trendmicro", "Program Files*/Trend Micro/Security Agent/ConnLog"),
        ("trendmicro", "Program Files*/Trend Micro/Security Agent/Misc"),
        ("trendmicro", "Program Files*/Trend Micro/Security Agent/SUSPECT"),
        ("trendmicro", "Program Files*/Trend Micro/Security Agent/Report"),
        ("trendmicro", "Program Files*/Trend Micro/OfficeScan Client/Logs"),
        ("trendmicro", "Program Files*/Trend Micro/Deep Security Agent/diag"),
        # Symantec / Broadcom SEP (version dir varies)
        ("symantec", "ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Logs"),
        ("symantec", "ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Quarantine"),
        # McAfee / Trellix
        ("mcafee", "ProgramData/McAfee/Endpoint Security/Logs"),
        ("mcafee", "ProgramData/McAfee/DesktopProtection"),
        ("mcafee", "ProgramData/Trellix/Endpoint Security/Logs"),
        # Sophos
        ("sophos", "ProgramData/Sophos/Sophos Anti-Virus/logs"),
        ("sophos", "ProgramData/Sophos/Endpoint Defense/Logs"),
        ("sophos", "ProgramData/Sophos/Sophos File Scanner/Logs"),
        # ESET
        ("eset", "ProgramData/ESET/ESET Security/Logs"),
        ("eset", "ProgramData/ESET/ESET NOD32 Antivirus/Logs"),
        # Kaspersky
        ("kaspersky", "ProgramData/Kaspersky Lab/*/Logs"),
        # Bitdefender
        ("bitdefender", "ProgramData/Bitdefender/Endpoint Security/Logs"),
        ("bitdefender", "Program Files/Bitdefender/Endpoint Security/Logs"),
        # Avast / AVG
        ("avast", "ProgramData/Avast Software/Avast/log"),
        ("avg", "ProgramData/AVG/Antivirus/log"),
        # Malwarebytes
        ("malwarebytes", "ProgramData/Malwarebytes/MBAMService/logs"),
        ("malwarebytes", "ProgramData/Malwarebytes/MBAMService/ScanResults"),
        # EDR agents — local logs only (telemetry lives cloud-side)
        ("crowdstrike", "ProgramData/CrowdStrike"),
        ("sentinelone", "ProgramData/Sentinel/logs"),
        ("carbonblack", "ProgramData/CarbonBlack/Logs"),
        ("cylance", "ProgramData/Cylance/Desktop"),
        ("cybereason", "ProgramData/crs1/Logs"),
        ("webroot", "ProgramData/WRData"),
    ]

    # Skip definition/update payloads inside vendor dirs — huge, zero forensic value.
    _AV_SKIP_HINTS = (
        "definition",
        "\\bases\\",
        "/bases/",
        "signature",
        "lpc_pattern",
        "icrc$",
        "_update",
        "engine_cache",
    )
    _AV_MAX_PER_VENDOR = 250
    _AV_MAX_FILE_MB = 50

    def _antivirus_windows(self, root: Path) -> None:
        print("  [*] Antivirus / EDR")
        max_size = self._AV_MAX_FILE_MB * 1024 * 1024
        per_vendor: dict[str, int] = {}
        for vendor, rel in self._WIN_AV_DIRS:
            try:
                matches = list(root.glob(rel))
            except Exception as exc:
                self._warn(f"AV glob {rel}: {exc}")
                continue
            for base in matches:
                if per_vendor.get(vendor, 0) >= self._AV_MAX_PER_VENDOR:
                    break
                try:
                    items = sorted(base.rglob("*")) if base.is_dir() else [base]
                except Exception:
                    continue
                for p in items:
                    n = per_vendor.get(vendor, 0)
                    if n >= self._AV_MAX_PER_VENDOR:
                        break
                    try:
                        if not p.is_file():
                            continue
                        low = str(p).lower()
                        if any(h in low for h in self._AV_SKIP_HINTS):
                            continue
                        size = p.stat().st_size
                        if size == 0 or size > max_size:
                            continue
                        sub = p.relative_to(base) if base.is_dir() else p.name
                        arc = f"antivirus/{vendor}/{base.name}/{sub}".replace("\\", "/")
                        tmp = self.staging / f"av_{vendor}_{n}_{p.name}"
                        if self._stage_file(p, tmp) and self._add(tmp, arc):
                            per_vendor[vendor] = n + 1
                    except Exception:
                        pass
        for vendor, n in sorted(per_vendor.items()):
            self._log(f"{vendor}: {n} file(s)")

    # ── Sysmon (Windows — shared by live + dead-box) ──────────────────────────

    def _sysmon_windows(self, root: Path, win_dir: Path) -> None:
        print("  [*] Sysmon (events, config, archive)")
        # Operational channel — also part of evtx, but guaranteed here even
        # when the evtx category is disabled.
        evtx = (
            win_dir / "System32" / "winevt" / "Logs" / "Microsoft-Windows-Sysmon%4Operational.evtx"
        )
        tmp = self.staging / "sysmon_operational.evtx"
        if self._stage_file(evtx, tmp):
            self._add(tmp, "sysmon/Microsoft-Windows-Sysmon%4Operational.evtx")
        # Config XMLs commonly dropped next to the binary or at the drive root
        for d in (win_dir, root, root / "Program Files" / "Sysmon", root / "Tools"):
            for pat in ("sysmon*.xml", "*sysmonconfig*.xml"):
                try:
                    for p in d.glob(pat):
                        if p.is_file():
                            self._add(p, f"sysmon/config/{p.name}")
                except Exception:
                    pass
        # FileDelete / ClipboardChange archive directory (default: <drive>\Sysmon)
        arch = root / "Sysmon"
        if arch.is_dir():
            count = 0
            try:
                entries = sorted(arch.iterdir())
            except Exception:
                entries = []
            for p in entries:
                if count >= 200:
                    break
                try:
                    if p.is_file() and self._add(p, f"sysmon/archive/{p.name}"):
                        count += 1
                except Exception:
                    pass
        # Live system only: dump driver rules + service state. Never query the
        # host registry when the target is a mounted dead-box image.
        sysdrive = os.environ.get("SystemDrive", "C:").rstrip("\\").lower()
        is_live = IS_WINDOWS and str(root).rstrip("\\/").lower() == sysdrive
        if is_live:
            dest = self.staging / "SysmonDrv.hiv"
            try:
                r = subprocess.run(
                    [
                        "reg.exe",
                        "save",
                        r"HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv",
                        str(dest),
                        "/y",
                    ],
                    capture_output=True,
                    timeout=30,
                )
                if r.returncode == 0:
                    self._add(dest, "sysmon/SysmonDrv.hiv")
            except Exception as exc:
                self._log(f"SysmonDrv reg save: {exc}")
            state = []
            for cmd in (
                ["sc.exe", "query", "Sysmon64"],
                ["sc.exe", "query", "Sysmon"],
                ["sc.exe", "qc", "Sysmon64"],
                ["sc.exe", "qc", "Sysmon"],
            ):
                out = self._run_cmd(cmd, timeout=15)
                if out.strip():
                    state.append("> " + " ".join(cmd) + "\n" + out)
            if state:
                self._write_text(
                    "sysmon_service.txt", "\n".join(state), "sysmon/sysmon_service.txt"
                )

    def collect_all(self) -> None:
        raise NotImplementedError

    def package(self) -> None:
        n = len(self._items)
        BAR_W = 44
        t0 = time.monotonic()

        print(f"\n{_HR}")
        print("  Packaging")
        print(_HR)
        print(f"\n  {n} file{'s' if n != 1 else ''} → {self.output.name}\n")

        self.output.parent.mkdir(parents=True, exist_ok=True)

        # Pre-flight: do we plausibly have room? Sum the staged sizes (worst case,
        # uncompressed) and compare to free space on the output volume. The ZIP
        # is compressed so this is conservative — but a warning here beats a
        # silently truncated archive.
        try:
            needed = sum(p.stat().st_size for _, p in self._items if p.exists())
        except Exception:
            needed = 0
        free_info = _disk_free(self.output.parent)
        if free_info and needed and free_info[0] < needed:
            self._warn(
                f"Output volume has {_fmt_bytes(free_info[0])} free but up to "
                f"{_fmt_bytes(needed)} may be written — archive may be truncated."
            )

        self._disk_full = False
        last_bar = ""
        with zipfile.ZipFile(str(self.output), "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for i, (arcname, path) in enumerate(self._items, 1):
                try:
                    zf.write(str(path), arcname)
                except (PermissionError, OSError) as exc:
                    # Disk full is fatal to packaging — stop now and report it
                    # clearly rather than emitting dozens of misleading per-file
                    # "permission denied" warnings and a truncated ZIP.
                    if getattr(exc, "errno", None) == errno.ENOSPC:
                        self._disk_full = True
                        self._warn(
                            "DISK FULL while writing the archive — out of space on the "
                            f"output volume ({self.output.parent}). Archive is incomplete."
                        )
                        break
                    # File was registered via direct _add() without staging.
                    # Try backup-semantics copy to a temp location first.
                    tmp_pkg = self.staging / f"_pkg_{i}_{path.name}"
                    if self._stage_file(path, tmp_pkg):
                        try:
                            zf.write(str(tmp_pkg), arcname)
                        except Exception as exc2:
                            self._warn(f"Archive failed for {arcname}: {exc2}")
                        finally:
                            tmp_pkg.unlink(missing_ok=True)
                    else:
                        tcc_hint = (
                            " — macOS TCC: grant Full Disk Access to your Terminal in"
                            " System Settings → Privacy & Security → Full Disk Access"
                            if IS_MACOS
                            and any(
                                p in str(path)
                                for p in (
                                    "Safari",
                                    "Chrome",
                                    "Chromium",
                                    "Firefox",
                                    "BraveSoftware",
                                    "Microsoft Edge",
                                    "Library/Cookies",
                                    "Library/Mail",
                                )
                            )
                            else ""
                        )
                        self._warn(f"Archive failed for {arcname}: permission denied{tcc_hint}")
                except Exception as exc:
                    self._warn(f"Archive failed for {arcname}: {exc}")
                filled = int(BAR_W * i / n) if n else BAR_W
                last_bar = "█" * filled + "░" * (BAR_W - filled)
                sys.stdout.write(f"\r  [{last_bar}] {i}/{n}  ")
                sys.stdout.flush()

        elapsed = time.monotonic() - t0
        size_mb = self.output.stat().st_size / (1024 * 1024)
        print(f"\r  [{'█' * BAR_W}] {n}/{n}  done          ")
        print(f"\n  Archive  : {self.output}")
        print(f"  Size     : {size_mb:.1f} MB")
        print(f"  Packed   : {elapsed:.1f}s")

    def cleanup(self) -> None:
        shutil.rmtree(self.staging, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Collector
# ─────────────────────────────────────────────────────────────────────────────


class WindowsCollector(Collector):
    def collect_all(self) -> None:
        self._total_cats = len(self.collect)
        self._run_cat("evtx", self._evtx)
        self._run_cat("registry", self._registry)
        self._run_cat("prefetch", self._prefetch)
        self._run_cat("lnk", self._lnk)
        self._run_cat("browser", self._browser)
        self._run_cat("tasks", self._scheduled_tasks)
        self._run_cat("mft", self._mft)
        self._run_cat("sysmon", self._sysmon)
        self._run_cat("antivirus", self._antivirus)
        self._run_cat("pe", self._pe_binaries)
        self._run_cat("documents", self._documents)
        self._run_cat("downloads", self._downloads)
        self._run_cat("triage", self._system_triage)
        self._run_cat("file_search", self._file_search)
        # "memory" removed: winpmem requires elevation; System Volume Information
        # access is denied on live systems. Use --collect memory explicitly.

    def _sysmon(self) -> None:
        root = Path(os.environ.get("SystemDrive", "C:") + "\\")
        win_dir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        self._sysmon_windows(root, win_dir)

    def _antivirus(self) -> None:
        self._antivirus_windows(Path(os.environ.get("SystemDrive", "C:") + "\\"))

    def _evtx(self) -> None:
        print("  [*] Event Logs (EVTX)")
        evtx_dir = (
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "winevt" / "Logs"
        )
        if not evtx_dir.exists():
            self._warn(f"EVTX directory not found: {evtx_dir}")
            return
        seen: set[str] = set()
        for name in EVTX_PRIORITY:
            src = evtx_dir / name
            try:
                if not src.is_file() or src.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{name}"
                if self._stage_file(src, tmp) and self._add(tmp, f"evtx/{name}"):
                    seen.add(name)
            except Exception as exc:
                self._warn(f"EVTX {name}: {exc}")
        count = 0
        try:
            all_evtx = sorted(evtx_dir.glob("*.evtx"))
        except Exception as exc:
            self._warn(f"EVTX glob error: {exc}")
            return
        for p in all_evtx:
            if count >= 200:
                break
            if p.name in seen:
                continue
            try:
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"evtx/{p.name}"):
                    count += 1
            except Exception as exc:
                self._warn(f"EVTX {p.name}: {exc}")

    def _registry(self) -> None:
        print("  [*] Registry Hives")
        staging_reg = self.staging / "registry"
        staging_reg.mkdir(exist_ok=True)
        hklm_hives = {
            "SYSTEM": "HKLM\\SYSTEM",
            "SOFTWARE": "HKLM\\SOFTWARE",
            "SAM": "HKLM\\SAM",
            "SECURITY": "HKLM\\SECURITY",
        }
        for name, hive_path in hklm_hives.items():
            dest = staging_reg / name
            try:
                r = subprocess.run(
                    ["reg.exe", "SAVE", hive_path, str(dest), "/y"],
                    capture_output=True,
                    timeout=60,
                )
                if r.returncode == 0:
                    self._add(dest, f"registry/{name}")
                else:
                    self._warn(f"reg.exe SAVE {name} failed (run as Administrator?)")
            except Exception as exc:
                self._warn(f"reg.exe SAVE {name}: {exc}")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        try:
            user_dirs = sorted(users_dir.iterdir()) if users_dir.exists() else []
        except Exception as exc:
            self._warn(f"Registry users scan error: {exc}")
            user_dirs = []
        for user_dir in user_dirs:
            if not user_dir.is_dir():
                continue
            for rel, suffix in [
                ("NTUSER.DAT", "NTUSER.DAT"),
                (r"AppData\Local\Microsoft\Windows\UsrClass.dat", "USRCLASS.DAT"),
            ]:
                try:
                    src = user_dir / rel
                    tmp = staging_reg / f"{user_dir.name}_{suffix}"
                    if self._stage_file(src, tmp):
                        self._add(tmp, f"registry/users/{user_dir.name}/{suffix}")
                except Exception as exc:
                    self._warn(f"Registry {user_dir.name}/{suffix}: {exc}")

    def _prefetch(self) -> None:
        print("  [*] Prefetch Files")
        pf_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
        if not pf_dir.exists():
            self._warn("Prefetch directory not found (may be disabled)")
            return
        count = 0
        try:
            pf_files = sorted(pf_dir.glob("*.pf"))
        except Exception as exc:
            self._warn(f"Prefetch glob error: {exc}")
            return
        for p in pf_files:
            if count >= 500:
                break
            try:
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"pf_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"prefetch/{p.name}"):
                    count += 1
            except Exception as exc:
                self._warn(f"Prefetch {p.name}: {exc}")

    def _lnk(self) -> None:
        print("  [*] LNK / Recent Items")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        count = 0
        try:
            user_dirs = sorted(users_dir.iterdir()) if users_dir.exists() else []
        except Exception as exc:
            self._warn(f"LNK users scan error: {exc}")
            return
        for user_dir in user_dirs:
            if not user_dir.is_dir():
                continue
            recent = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            try:
                lnk_files = list(recent.rglob("*.lnk")) if recent.exists() else []
            except Exception:
                lnk_files = []
            for p in lnk_files:
                if count >= 2000:
                    break
                try:
                    if self._add(p, f"lnk/{user_dir.name}/{p.name}"):
                        count += 1
                except Exception:
                    pass

    def _browser(self) -> None:
        print("  [*] Browser Artifacts")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        # Chromium-family browsers keep one directory PER PROFILE under their
        # "User Data" root (Default, Profile 1, Profile 2, Guest Profile). Only
        # collecting "Default" silently missed every secondary profile — the
        # common case for real users. Enumerate all profile dirs instead.
        CHROMIUM = [
            ("chrome",  r"AppData\Local\Google\Chrome\User Data"),
            ("edge",    r"AppData\Local\Microsoft\Edge\User Data"),
            ("brave",   r"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
            ("vivaldi", r"AppData\Local\Vivaldi\User Data"),
        ]
        # Cookies moved to Network\Cookies in newer Chromium — grab both.
        CHROMIUM_FILES = [
            "History", "Web Data", "Cookies", "Login Data", "Bookmarks",
            r"Network\Cookies", "Shortcuts", "Top Sites",
        ]

        def _is_profile(name: str) -> bool:
            return name == "Default" or name.startswith("Profile ") or name == "Guest Profile"

        try:
            user_dirs = sorted(users_dir.iterdir()) if users_dir.exists() else []
        except Exception as exc:
            self._warn(f"Browser users scan error: {exc}")
            return
        for user_dir in user_dirs:
            if not user_dir.is_dir():
                continue
            # ── Chromium browsers: every profile ──────────────────────────────
            for browser, base_rel in CHROMIUM:
                base = user_dir / base_rel
                if not base.exists():
                    continue
                try:
                    profiles = [p for p in base.iterdir() if p.is_dir() and _is_profile(p.name)]
                except Exception:
                    profiles = []
                for prof in profiles:
                    for rel in CHROMIUM_FILES:
                        try:
                            src = prof / rel
                            safe = f"{user_dir.name}_{browser}_{prof.name}_{Path(rel).name}".replace(" ", "_")
                            tmp = self.staging / safe
                            if self._copy_locked(src, tmp):
                                self._add(tmp, f"browser/{browser}/{user_dir.name}/{prof.name}/{Path(rel).name}")
                        except Exception:
                            pass
            # ── Opera: single profile directly under "Opera Stable" ───────────
            opera_base = user_dir / r"AppData\Roaming\Opera Software\Opera Stable"
            for rel in ("History", "Cookies", "Web Data", "Login Data", "Bookmarks"):
                try:
                    src = opera_base / rel
                    tmp = self.staging / f"{user_dir.name}_opera_{Path(rel).name}".replace(" ", "_")
                    if self._copy_locked(src, tmp):
                        self._add(tmp, f"browser/opera/{user_dir.name}/{Path(rel).name}")
                except Exception:
                    pass
            ff_base = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            try:
                ff_profiles = list(ff_base.iterdir()) if ff_base.exists() else []
            except Exception:
                ff_profiles = []
            for profile_dir in ff_profiles:
                if not profile_dir.is_dir():
                    continue
                for db in ("places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite"):
                    try:
                        src = profile_dir / db
                        tmp = self.staging / f"{user_dir.name}_ff_{profile_dir.name}_{db}"
                        if self._copy_locked(src, tmp):
                            self._add(
                                tmp, f"browser/firefox/{user_dir.name}/{profile_dir.name}/{db}"
                            )
                    except Exception:
                        pass

    def _scheduled_tasks(self) -> None:
        print("  [*] Scheduled Tasks")
        tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        if not tasks_dir.exists():
            self._warn("Tasks directory not found")
            return
        count = 0
        try:
            task_files = list(tasks_dir.rglob("*"))
        except Exception as exc:
            self._warn(f"Scheduled tasks scan error: {exc}")
            return
        for p in task_files:
            if count >= 500:
                break
            try:
                if p.is_file() and not p.suffix:
                    rel = str(p.relative_to(tasks_dir)).replace("\\", "/")
                    if self._add(p, f"scheduled_tasks/{rel}"):
                        count += 1
            except Exception as exc:
                self._warn(f"Task {p.name}: {exc}")

    def _mft(self) -> None:
        """Raw-copy $MFT from all NTFS volumes via Windows kernel API (requires Admin)."""
        print("  [*] Master File Table ($MFT)")
        try:
            import ctypes
            import ctypes.wintypes
            import struct
        except ImportError:
            self._warn("$MFT: ctypes not available")
            return

        # Detect lettered NTFS drives
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        drives = [chr(65 + i) for i in range(26) if bitmask & (1 << i)]

        for drive in drives:
            dest = self.staging / f"{drive}_MFT"
            try:
                h = ctypes.windll.kernel32.CreateFileW(
                    f"\\\\.\\{drive}:",
                    0x80000000,  # GENERIC_READ
                    0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
                    None,
                    3,
                    0,
                    None,  # OPEN_EXISTING, no flags
                )
                INVALID = ctypes.c_void_p(-1).value
                if h == INVALID or h == 0:
                    self._warn(f"$MFT ({drive}:): cannot open volume — run as Administrator")
                    continue

                try:
                    # ── Read NTFS boot sector ────────────────────────────────
                    buf = ctypes.create_string_buffer(512)
                    n = ctypes.wintypes.DWORD(0)
                    ctypes.windll.kernel32.ReadFile(h, buf, 512, ctypes.byref(n), None)
                    bs = buf.raw

                    if bs[3:7] != b"NTFS":
                        self._log(f"{drive}: not NTFS — skipping")
                        continue

                    bps = struct.unpack_from("<H", bs, 11)[0]  # bytes/sector
                    spc = struct.unpack_from("<B", bs, 13)[0]  # sectors/cluster
                    mft_lcn = struct.unpack_from("<Q", bs, 48)[0]  # MFT first LCN
                    cls_sz = bps * spc

                    # MFT record size (boot sector offset 64)
                    rs_raw = struct.unpack_from("<b", bs, 64)[0]
                    mft_rs = cls_sz * (2**rs_raw) if rs_raw >= 0 else 2 ** (-rs_raw)
                    mft_rs = max(512, min(int(mft_rs), 65536))

                    # ── Seek to MFT start, read first FILE record ────────────
                    mft_off = mft_lcn * cls_sz
                    ctypes.windll.kernel32.SetFilePointerEx(
                        h,
                        ctypes.c_longlong(mft_off),
                        None,
                        0,  # FILE_BEGIN
                    )
                    rec0 = ctypes.create_string_buffer(mft_rs)
                    ctypes.windll.kernel32.ReadFile(h, rec0, mft_rs, ctypes.byref(n), None)

                    if rec0.raw[:4] != b"FILE":
                        self._warn(f"$MFT ({drive}:): first record has no FILE signature")
                        continue

                    # ── Parse attributes to find $DATA total size ────────────
                    attr_p = struct.unpack_from("<H", rec0.raw, 20)[0]
                    total_size = 0
                    while attr_p + 8 < mft_rs:
                        at = struct.unpack_from("<I", rec0.raw, attr_p)[0]
                        al = struct.unpack_from("<I", rec0.raw, attr_p + 4)[0]
                        if at == 0xFFFFFFFF or al == 0:
                            break
                        if at == 0x80 and rec0.raw[attr_p + 8]:  # non-resident $DATA
                            total_size = struct.unpack_from("<Q", rec0.raw, attr_p + 0x30)[0]
                            break
                        attr_p += al

                    if total_size == 0 or total_size > 30 * 1024**3:
                        total_size = 512 * 1024 * 1024  # 512 MB safety cap
                        self._log(f"$MFT ({drive}:): size unknown, capping at 512 MB")

                    # ── Re-seek and stream out the full MFT ──────────────────
                    ctypes.windll.kernel32.SetFilePointerEx(
                        h,
                        ctypes.c_longlong(mft_off),
                        None,
                        0,
                    )
                    CHUNK = 4 * 1024 * 1024  # 4 MB
                    remaining = total_size
                    with open(dest, "wb") as out_f:
                        while remaining > 0:
                            to_read = min(CHUNK, remaining)
                            cbuf = ctypes.create_string_buffer(to_read)
                            ok = ctypes.windll.kernel32.ReadFile(
                                h,
                                cbuf,
                                to_read,
                                ctypes.byref(n),
                                None,
                            )
                            if not ok or n.value == 0:
                                break
                            out_f.write(cbuf.raw[: n.value])
                            remaining -= n.value

                    self._add(dest, f"mft/{drive}_$MFT")
                    sz_mb = dest.stat().st_size / 1024 / 1024
                    print(f"      {drive}:\\$MFT  ({sz_mb:.1f} MB)")

                finally:
                    ctypes.windll.kernel32.CloseHandle(h)

            except Exception as exc:
                self._warn(f"$MFT ({drive}:): {exc}")

    def _pe_binaries(self) -> None:
        """Collect PE executables from high-risk staging locations."""
        print("  [*] PE / Executable Binaries")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        system_tmp = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"
        PE_EXTS = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".msi", ".hta"}
        MAX_FILE = 200 * 1024 * 1024  # 200 MB
        MAX_TOTAL = 2 * 1024**3  # 2 GB total
        MAX_FILES = 1000

        dirs: list[Path] = [system_tmp]
        if users_dir.exists():
            for ud in sorted(users_dir.iterdir()):
                if not ud.is_dir():
                    continue
                for rel in [
                    r"AppData\Local\Temp",
                    r"AppData\Roaming",
                    r"Downloads",
                    r"Desktop",
                    r"AppData\Local\Microsoft\Windows\INetCache",
                ]:
                    dirs.append(ud / rel)

        count = 0
        total = 0
        for d in dirs:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES or total >= MAX_TOTAL:
                    break
                if not p.is_file() or p.suffix.lower() not in PE_EXTS:
                    continue
                sz = p.stat().st_size
                if sz == 0 or sz > MAX_FILE:
                    continue
                rel = p.relative_to(d.parent) if d.parent in p.parents else Path(d.name) / p.name
                if self._add(p, f"pe/{rel}"):
                    count += 1
                    total += sz

    def _documents(self) -> None:
        """Collect Office documents and PDFs from user directories."""
        print("  [*] Office Documents & PDFs")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        DOC_EXTS = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".rtf",
            ".pdf",
            ".odt",
            ".ods",
        }
        MAX_FILE = 100 * 1024 * 1024  # 100 MB
        MAX_FILES = 500

        count = 0
        for ud in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not ud.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = ud / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{ud.name}/{rel}/{p.name}"):
                        count += 1

    def _downloads(self) -> None:
        """Collect every user's Downloads folder (all file types).

        `pe` and `documents` only pull executables / Office files FROM Downloads;
        this grabs the folder wholesale (installers, archives, scripts, images,
        anything a user pulled down) — size-capped so a giant ISO can't blow the
        acquisition. Skips zero-byte and over-cap files.
        """
        print("  [*] Downloads Folders")
        users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        MAX_FILE = 500 * 1024 * 1024  # 500 MB per file
        MAX_TOTAL = 5 * 1024**3       # 5 GB total
        MAX_FILES = 2000

        count = 0
        total = 0
        for ud in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not ud.is_dir():
                continue
            d = ud / "Downloads"
            if not d.exists():
                continue
            try:
                entries = sorted(d.rglob("*"))
            except Exception as exc:
                self._warn(f"Downloads scan error ({ud.name}): {exc}")
                continue
            for p in entries:
                if count >= MAX_FILES or total >= MAX_TOTAL:
                    self._warn(f"Downloads cap reached for {ud.name} — some files skipped")
                    break
                try:
                    if not p.is_file():
                        continue
                    sz = p.stat().st_size
                    if sz == 0 or sz > MAX_FILE:
                        continue
                    rel = p.relative_to(d)
                    if self._add(p, f"downloads/{ud.name}/{rel}"):
                        count += 1
                        total += sz
                except Exception:
                    pass

    def _system_triage(self) -> None:
        print("  [*] System Triage (live commands)")
        lines: list[str] = []
        for header, cmd in [
            ("SYSTEM INFO", ["systeminfo"]),
            ("NETWORK CONFIG", ["ipconfig", "/all"]),
            ("NETWORK CONNECTIONS", ["netstat", "-ano"]),
            ("ARP CACHE", ["arp", "-a"]),
            ("DNS CACHE", ["ipconfig", "/displaydns"]),
            ("RUNNING PROCESSES", ["tasklist", "/v", "/fo", "list"]),
            ("LOCAL USERS", ["net", "user"]),
            ("ADMINISTRATORS", ["net", "localgroup", "administrators"]),
            ("SERVICES", ["sc", "query", "state=", "all"]),
            ("STARTUP ITEMS", ["wmic", "startup", "list", "full"]),
            ("SCHEDULED TASKS", ["schtasks", "/query", "/fo", "list", "/v"]),
            ("SHARES", ["net", "share"]),
            (
                "INSTALLED SOFTWARE",
                ["wmic", "product", "get", "Name,Version,InstallDate", "/format:list"],
            ),
            ("ENVIRONMENT", ["set"]),
        ]:
            lines.append(f"\n{'=' * 60}\n{header}\n{'=' * 60}")
            lines.append(self._run_cmd(cmd, timeout=45))
        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")

    def _memory(self) -> None:
        print("  [*] Physical Memory Dump (live acquisition)")
        print("  [!] Note: Memory dumps are typically 4–64 GB — this may take a while")

        dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.dmp"

        # Locate WinPmem — check PATH, then script directory, then CWD
        winpmem: str | None = shutil.which("winpmem") or shutil.which("winpmem_mini_x64_rc2")
        if not winpmem:
            script_dir = Path(sys.argv[0]).resolve().parent
            for name in [
                "winpmem_mini_x64_rc2.exe",
                "winpmem.exe",
                "winpmem_x64.exe",
                "winpmem_mini_x64.exe",
            ]:
                for search_dir in (script_dir, Path.cwd()):
                    candidate = search_dir / name
                    if candidate.exists():
                        winpmem = str(candidate)
                        break
                if winpmem:
                    break

        if not winpmem:
            self._warn(
                "winpmem not found. Download the latest release from:\n"
                "      https://github.com/Velocidex/WinPmem/releases\n"
                "      Then place winpmem_mini_x64_rc2.exe next to this collector and re-run."
            )
            return

        self._log(f"Using: {winpmem}")
        print(f"      winpmem: {winpmem}")
        print(f"      Output : {dump_path}")

        try:
            r = subprocess.run(
                [winpmem, str(dump_path)],
                capture_output=True,
                timeout=7200,  # 2 hours
            )
            if r.returncode == 0:
                self._add(dump_path, f"memory/{dump_path.name}")
                size_gb = dump_path.stat().st_size / (1024**3)
                print(f"  [+] Memory dump complete ({size_gb:.1f} GB)")
            else:
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:400]
                self._warn(
                    f"winpmem failed (code {r.returncode}) — run as Administrator?\n      {err}"
                )
        except subprocess.TimeoutExpired:
            self._warn("Memory acquisition timed out (>2 hours)")
        except FileNotFoundError:
            self._warn(f"winpmem binary not executable: {winpmem}")
        except Exception as exc:
            self._warn(f"Memory acquisition error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Linux Collector
# ─────────────────────────────────────────────────────────────────────────────


class LinuxCollector(Collector):
    def collect_all(self) -> None:
        self._total_cats = len(self.collect)
        # Core system state
        self._run_cat("logs", self._logs)
        self._run_cat("config", self._system_config)
        self._run_cat("triage", self._system_triage)
        # User activity
        self._run_cat("history", self._shell_history)
        self._run_cat("user_artifacts", self._user_artifacts)
        # Persistence
        self._run_cat("persistence", self._persistence)
        self._run_cat("cron", self._cron)
        # Network
        self._run_cat("network_config", self._network_config)
        self._run_cat("ssh", self._ssh_artifacts)
        self._run_cat("network", self._network_captures)
        self._run_cat("suricata", self._suricata_logs)
        self._run_cat("zeek", self._zeek_logs)
        # Security / audit
        self._run_cat("audit_logs", self._audit_logs)
        self._run_cat("antivirus", self._antivirus)
        self._run_cat("sysmon", self._sysmon)
        # Software inventory
        self._run_cat("packages", self._packages_and_tools)
        self._run_cat("containers", self._containers)
        # Heavy / opt-in
        self._run_cat("pe", self._pe_binaries)
        self._run_cat("documents", self._documents)
        self._run_cat("memory", self._memory)
        # On-demand file fetch (--fetch)
        self._run_cat("file_search", self._file_search)

    def _logs(self) -> None:
        print("  [*] System Logs")
        log_dir = Path("/var/log")
        for name in [
            "auth.log",
            "syslog",
            "messages",
            "secure",
            "kern.log",
            "daemon.log",
            "audit/audit.log",
            "apache2/access.log",
            "nginx/access.log",
            "dpkg.log",
            "apt/history.log",
            # Binary login records — parsed post-ingest (last/lastb format)
            "wtmp",
            "btmp",
            "lastlog",
            "faillog",
        ]:
            self._add(log_dir / name, f"logs/{name}")
        self._add(Path("/var/run/utmp"), "logs/utmp")
        for p in sorted(log_dir.rglob("*.gz"))[:80]:
            self._add(p, f"logs/{p.relative_to(log_dir)}")
        out = self._run_cmd(
            ["journalctl", "--no-pager", "-o", "short-iso", "-n", "100000"], timeout=120
        )
        if out:
            tmp = self.staging / "journal.log"
            tmp.write_text(out, encoding="utf-8", errors="replace")
            self._add(tmp, "logs/journal.log")

    def _shell_history(self) -> None:
        print("  [*] Shell Histories")
        HIST = [".bash_history", ".zsh_history", ".sh_history", ".python_history", ".mysql_history"]
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())
        for user_dir in candidates:
            if user_dir.is_dir():
                for h in HIST:
                    self._add(user_dir / h, f"history/{user_dir.name}/{h}")

    def _system_config(self) -> None:
        print("  [*] System Configuration")
        # Core identity / access control
        for p in [
            "/etc/passwd",
            "/etc/group",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/sudoers",
            "/etc/hostname",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/os-release",
            "/etc/issue",
            "/etc/motd",
            "/etc/crontab",
            "/etc/ssh/sshd_config",
            "/proc/version",
            "/proc/cmdline",
            "/etc/profile",
            "/etc/environment",
            "/etc/sysctl.conf",
            "/etc/ld.so.conf",
            "/etc/fstab",
            "/etc/security/limits.conf",
            "/etc/login.defs",
        ]:
            self._add(Path(p), f"config/{Path(p).name}")
        # Sudoers drop-in
        if Path("/etc/sudoers.d").exists():
            for f in sorted(Path("/etc/sudoers.d").iterdir()):
                if f.is_file():
                    self._add(f, f"config/sudoers.d/{f.name}")
        # PAM — abused for persistence (e.g. pam_exec / custom modules)
        if Path("/etc/pam.d").exists():
            for f in sorted(Path("/etc/pam.d").iterdir()):
                if f.is_file():
                    self._add(f, f"config/pam.d/{f.name}")
        # sysctl.d overrides
        if Path("/etc/sysctl.d").exists():
            for f in sorted(Path("/etc/sysctl.d").iterdir()):
                if f.is_file():
                    self._add(f, f"config/sysctl.d/{f.name}")
        # Module loading
        for d in ["/etc/modules-load.d", "/etc/modprobe.d"]:
            if Path(d).exists():
                for f in sorted(Path(d).iterdir()):
                    if f.is_file():
                        self._add(f, f"config/{Path(d).name}/{f.name}")
        # Proc runtime info
        for pf in ["cpuinfo", "meminfo", "modules", "mounts", "net/arp"]:
            self._add(Path(f"/proc/{pf}"), f"config/proc/{pf.replace('/', '_')}")

    def _cron(self) -> None:
        print("  [*] Cron Jobs")
        for d in [
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ]:
            if Path(d).exists():
                for f in sorted(Path(d).iterdir()):
                    if f.is_file():
                        self._add(f, f"cron/{Path(d).name}/{f.name}")
        spool = Path("/var/spool/cron/crontabs")
        if spool.exists():
            for ct in sorted(spool.iterdir()):
                self._add(ct, f"cron/crontabs/{ct.name}")
        out = self._run_cmd(["systemctl", "list-timers", "--all", "--no-pager"])
        if out:
            self._write_text("systemd_timers.txt", out, "cron/systemd_timers.txt")

    def _ssh_artifacts(self) -> None:
        print("  [*] SSH Artifacts")
        PRIVATE = {"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())
        for user_dir in candidates:
            ssh = user_dir / ".ssh"
            if ssh.exists():
                for f in sorted(ssh.iterdir()):
                    if f.is_file() and f.name not in PRIVATE:
                        self._add(f, f"ssh/{user_dir.name}/{f.name}")

    def _network_captures(self) -> None:
        """Collect PCAP/PCAPNG files from common locations (max 10 files, 500 MB each)."""
        print("  [*] PCAP / Network Captures")
        SEARCH_DIRS = [
            Path("/var/log"),
            Path("/tmp"),
            Path("/var/capture"),
            Path("/opt/pcap"),
            Path("/data"),
            Path("/captures"),
        ]
        MAX_SIZE = 500 * 1024 * 1024  # 500 MB per file
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in (
                sorted(d.rglob("*.pcap")) + sorted(d.rglob("*.pcapng")) + sorted(d.rglob("*.cap"))
            ):
                if count >= 10:
                    break
                if p.stat().st_size <= MAX_SIZE:
                    if self._add(p, f"network/{p.name}"):
                        count += 1
            if count >= 10:
                break
        # Live capture — only if tcpdump is available and no pcaps found
        if count == 0 and shutil.which("tcpdump"):
            cap_path = self.staging / f"live-{HOSTNAME}-{TS_NOW}.pcap"
            print("      Live capture: 30 s via tcpdump")
            try:
                subprocess.run(
                    ["tcpdump", "-i", "any", "-w", str(cap_path), "-G", "30", "-W", "1"],
                    timeout=35,
                    capture_output=True,
                )
                self._add(cap_path, f"network/{cap_path.name}")
            except Exception as exc:
                self._log(f"tcpdump: {exc}")

    def _suricata_logs(self) -> None:
        """Collect Suricata EVE JSON logs."""
        print("  [*] Suricata IDS Logs (EVE JSON)")
        SEARCH_DIRS = [
            Path("/var/log/suricata"),
            Path("/var/log/suricata/"),
            Path("/opt/suricata/log"),
            Path("/etc/suricata"),
        ]
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.glob("eve*.json")) + sorted(d.glob("*.json")):
                if count >= 20:
                    break
                if self._add(p, f"suricata/{p.name}"):
                    count += 1
            for p in sorted(d.glob("*.log")):
                if count >= 20:
                    break
                if self._add(p, f"suricata/{p.name}"):
                    count += 1

    def _zeek_logs(self) -> None:
        """Collect Zeek (formerly Bro) network analysis logs."""
        print("  [*] Zeek Network Logs")
        SEARCH_DIRS = [
            Path("/var/log/zeek"),
            Path("/var/log/bro"),
            Path("/opt/zeek/logs"),
            Path("/opt/bro/logs"),
            Path("/nsm/zeek/logs"),
        ]
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            # Priority logs
            for name in [
                "conn.log",
                "dns.log",
                "http.log",
                "ssl.log",
                "x509.log",
                "files.log",
                "weird.log",
                "notice.log",
                "alarm.log",
            ]:
                p = d / name
                if self._add(p, f"zeek/{p.name}"):
                    count += 1
            # Remaining logs (up to 50 total)
            for p in sorted(d.rglob("*.log")):
                if count >= 50:
                    break
                if self._add(p, f"zeek/{p.relative_to(d)}"):
                    count += 1
            if count > 0:
                break  # Found logs in this dir, no need to check others

    def _pe_binaries(self) -> None:
        """Collect suspicious ELF/PE binaries dropped in volatile locations."""
        print("  [*] PE / Executable Binaries")
        SEARCH_DIRS = [
            Path("/tmp"),
            Path("/var/tmp"),
            Path("/dev/shm"),
            Path("/var/www"),
            Path("/opt"),
            Path("/root"),
        ]
        ELF_MAGIC = b"\x7fELF"
        PE_MAGIC = b"MZ"
        MAX_FILE = 50 * 1024 * 1024  # 50 MB
        MAX_FILES = 500

        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES:
                    break
                if not p.is_file():
                    continue
                sz = p.stat().st_size
                if sz < 4 or sz > MAX_FILE:
                    continue
                try:
                    magic = p.read_bytes()[:4]
                except (PermissionError, OSError):
                    continue
                if not (magic[:4] == ELF_MAGIC or magic[:2] == PE_MAGIC):
                    continue
                rel = p.relative_to(d.parent) if d.parent in p.parents else Path(d.name) / p.name
                if self._add(p, f"pe/{rel}"):
                    count += 1

    def _documents(self) -> None:
        """Collect Office documents and PDFs from home directories."""
        print("  [*] Office Documents & PDFs")
        DOC_EXTS = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".rtf",
            ".pdf",
            ".odt",
            ".ods",
        }
        MAX_FILE = 100 * 1024 * 1024
        MAX_FILES = 500
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())

        count = 0
        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = user_dir / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{user_dir.name}/{rel}/{p.name}"):
                        count += 1

    def _system_triage(self) -> None:
        print("  [*] System Triage (live commands)")
        lines: list[str] = []
        for header, cmd, timeout in [
            # Identity
            ("UNAME", ["uname", "-a"], 5),
            ("HOSTNAME", ["hostname", "-f"], 5),
            ("DATE / TIMEZONE", ["timedatectl", "status"], 5),
            ("CURRENT USER", ["id"], 5),
            # Processes
            ("PROCESSES", ["ps", "auxf"], 15),
            ("OPEN FILES (lsof)", ["lsof", "-n", "-P", "-l"], 30),
            (
                "PROCESS CMDLINES",
                [
                    "bash",
                    "-c",
                    "for f in /proc/[0-9]*/cmdline; do "
                    "pid=${f%/cmdline}; pid=${pid##*/}; "
                    "cmd=$(tr '\\0' ' ' < $f 2>/dev/null); "
                    '[ -n "$cmd" ] && echo "$pid $cmd"; done',
                ],
                20,
            ),
            # Network
            ("NETWORK INTERFACES", ["ip", "addr"], 10),
            ("ROUTING TABLE", ["ip", "route"], 10),
            ("ARP TABLE", ["ip", "neigh"], 10),
            ("SOCKETS (ss)", ["ss", "-tulpan"], 10),
            ("ALL CONNECTIONS", ["ss", "-anptu"], 10),
            # Sessions & logins
            ("LOGGED IN USERS", ["who", "-a"], 5),
            ("LAST LOGINS", ["last", "-F", "-n", "200"], 10),
            ("FAILED LOGINS", ["lastb", "-n", "100"], 10),
            ("ACTIVE SESSIONS", ["loginctl", "list-sessions", "--no-pager"], 5),
            # Filesystem
            ("MOUNTS", ["mount"], 10),
            ("DISK USAGE", ["df", "-h"], 10),
            (
                "TMP / VOLATILE DIRS",
                ["find", "/tmp", "/var/tmp", "/dev/shm", "-maxdepth", "3", "-ls"],
                15,
            ),
            (
                "RECENTLY MODIFIED /etc",
                ["find", "/etc", "-maxdepth", "3", "-newer", "/etc/passwd", "-ls"],
                10,
            ),
            # Kernel
            ("LOADED MODULES", ["lsmod"], 10),
            ("KERNEL MESSAGES", ["dmesg", "-T", "--level=warn,err,crit"], 20),
            # Services
            ("SYSTEMD UNITS", ["systemctl", "list-units", "--all", "--no-pager"], 15),
            ("FAILED UNITS", ["systemctl", "--failed", "--no-pager"], 5),
            # SUID/SGID — common escalation vector
            (
                "SUID FILES",
                ["find", "/", "-perm", "-4000", "-type", "f", "-not", "-path", "/proc/*", "-ls"],
                30,
            ),
            (
                "SGID FILES",
                ["find", "/", "-perm", "-2000", "-type", "f", "-not", "-path", "/proc/*", "-ls"],
                30,
            ),
            (
                "WORLD-WRITABLE DIRS",
                [
                    "find",
                    "/",
                    "-xdev",
                    "-type",
                    "d",
                    "-perm",
                    "-0002",
                    "-not",
                    "-path",
                    "/proc/*",
                    "-not",
                    "-path",
                    "/sys/*",
                    "-ls",
                ],
                20,
            ),
            # Environment & capabilities
            ("ENVIRONMENT", ["env"], 5),
            (
                "CAPABILITIES (files)",
                ["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local/bin"],
                10,
            ),
        ]:
            lines.append(f"\n{'=' * 60}\n{header}\n{'=' * 60}")
            lines.append(self._run_cmd(cmd, timeout=timeout))
        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")

    def _memory(self) -> None:
        print("  [*] Physical Memory Dump (live acquisition)")
        print("  [!] Note: Memory dumps are typically 4–64 GB — this may take a while")
        print("  [!] Root privileges are required for memory acquisition")

        dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.lime"

        # 1. Try avml (Microsoft's user-space memory acquisition tool)
        avml = shutil.which("avml")
        if avml:
            self._log(f"Using avml: {avml}")
            print(f"      avml : {avml}")
            print(f"      Output: {dump_path}")
            try:
                r = subprocess.run(
                    [avml, str(dump_path)],
                    capture_output=True,
                    timeout=7200,
                )
                if r.returncode == 0 and dump_path.exists() and dump_path.stat().st_size > 0:
                    self._add(dump_path, f"memory/{dump_path.name}")
                    size_gb = dump_path.stat().st_size / (1024**3)
                    print(f"  [+] Memory dump complete ({size_gb:.1f} GB)")
                    return
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:400]
                self._warn(f"avml failed (code {r.returncode}): {err}")
            except subprocess.TimeoutExpired:
                self._warn("avml timed out (>2 hours)")
            except Exception as exc:
                self._warn(f"avml error: {exc}")

        # 2. Try fmem / dd /dev/fmem
        for mem_dev in ("/dev/fmem", "/dev/mem"):
            if Path(mem_dev).exists():
                raw_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.raw"
                print(f"      Trying {mem_dev} → {raw_path}")
                try:
                    r = subprocess.run(
                        ["dd", f"if={mem_dev}", f"of={raw_path}", "bs=1M"],
                        capture_output=True,
                        timeout=7200,
                    )
                    if r.returncode == 0 and raw_path.stat().st_size > 0:
                        self._add(raw_path, f"memory/{raw_path.name}")
                        size_gb = raw_path.stat().st_size / (1024**3)
                        print(f"  [+] Memory image via {mem_dev} ({size_gb:.1f} GB)")
                        return
                except Exception as exc:
                    self._log(f"{mem_dev} dd error: {exc}")

        self._warn(
            "No memory acquisition tool found.\n"
            "      Install avml for user-space acquisition:\n"
            "        https://github.com/microsoft/avml/releases\n"
            "      Or load the LiME kernel module for full physical memory."
        )

    def _persistence(self) -> None:
        """Systemd units, init.d, at jobs, profile.d, XDG autostart — key IR category."""
        print("  [*] Persistence Mechanisms")

        # systemd system-wide units (installed + override)
        for sd_dir in [
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/etc/systemd/system",
            "/run/systemd/system",
        ]:
            d = Path(sd_dir)
            if not d.exists():
                continue
            for f in sorted(d.rglob("*.service")) + sorted(d.rglob("*.timer")):
                self._add(f, f"persistence/systemd/{d.name}/{f.name}")

        # systemd user units per user
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())
        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            for sub in [".config/systemd/user", ".local/share/systemd/user"]:
                ud = user_dir / sub
                if ud.exists():
                    for f in sorted(ud.rglob("*.service")) + sorted(ud.rglob("*.timer")):
                        self._add(f, f"persistence/systemd_user/{user_dir.name}/{f.name}")

        # Traditional init / SysV
        for init_dir in ["/etc/init.d", "/etc/rc.d/init.d"]:
            d = Path(init_dir)
            if d.exists():
                for f in sorted(d.iterdir()):
                    if f.is_file():
                        self._add(f, f"persistence/init.d/{f.name}")
        for rc in ["/etc/rc.local", "/etc/rc.d/rc.local"]:
            self._add(Path(rc), f"persistence/{Path(rc).name}")

        # /etc/profile.d — shell startup scripts
        if Path("/etc/profile.d").exists():
            for f in sorted(Path("/etc/profile.d").iterdir()):
                if f.is_file():
                    self._add(f, f"persistence/profile.d/{f.name}")

        # at / batch jobs
        for at_dir in ["/var/spool/at", "/var/spool/cron/atjobs", "/var/spool/atjobs"]:
            d = Path(at_dir)
            if d.exists():
                for f in sorted(d.iterdir()):
                    if f.is_file():
                        self._add(f, f"persistence/atjobs/{f.name}")

        # XDG autostart (system + per user)
        for xdg in [Path("/etc/xdg/autostart")] + [
            ud / ".config/autostart" for ud in candidates if ud.is_dir()
        ]:
            if xdg.exists():
                for f in sorted(xdg.iterdir()):
                    if f.is_file():
                        self._add(f, f"persistence/xdg_autostart/{f.name}")

        # Enabled services / timers snapshot (quick static list)
        for kind in ("service", "timer"):
            out = self._run_cmd(
                ["systemctl", "list-unit-files", f"--type={kind}", "--state=enabled", "--no-pager"],
                timeout=15,
            )
            if out:
                self._write_text(f"enabled_{kind}s.txt", out, f"persistence/enabled_{kind}s.txt")

        # LD_PRELOAD / ld.so.preload — classic rootkit vector
        self._add(Path("/etc/ld.so.preload"), "persistence/ld.so.preload")

        # /etc/inetd.conf / xinetd — legacy network service persistence
        for p in ["/etc/inetd.conf"]:
            self._add(Path(p), f"persistence/{Path(p).name}")
        if Path("/etc/xinetd.d").exists():
            for f in sorted(Path("/etc/xinetd.d").iterdir()):
                if f.is_file():
                    self._add(f, f"persistence/xinetd.d/{f.name}")

    def _user_artifacts(self) -> None:
        """Shell configs, browser history (Firefox/Chromium), GPG public keys."""
        print("  [*] User Artifacts")
        RC_FILES = [
            ".bashrc",
            ".bash_profile",
            ".bash_logout",
            ".bash_aliases",
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".profile",
            ".xprofile",
            ".xinitrc",
            ".config/fish/config.fish",
            ".local/bin",  # user-installed binaries
        ]
        candidates = [Path("/root")]
        if Path("/home").exists():
            candidates += sorted(Path("/home").iterdir())

        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            un = user_dir.name

            # Shell init files
            for rc in RC_FILES:
                p = user_dir / rc
                if p.is_file():
                    self._add(p, f"user/{un}/{Path(rc).name}")
                elif p.is_dir() and rc == ".local/bin":
                    for b in sorted(p.iterdir()):
                        if b.is_file():
                            self._add(b, f"user/{un}/local_bin/{b.name}")

            # GPG public keys only — no private keys
            gnupg = user_dir / ".gnupg"
            if gnupg.exists():
                for f in sorted(gnupg.iterdir()):
                    if (
                        f.is_file()
                        and f.suffix in (".pub",)
                        or f.name in ("pubring.gpg", "trustdb.gpg")
                    ):
                        self._add(f, f"user/{un}/.gnupg/{f.name}")

            # Firefox history
            ff_base = user_dir / ".mozilla/firefox"
            if ff_base.exists():
                for profile in sorted(ff_base.iterdir()):
                    if not profile.is_dir():
                        continue
                    for db in [
                        "places.sqlite",
                        "cookies.sqlite",
                        "formhistory.sqlite",
                        "logins.json",
                        "downloads.sqlite",
                        "sessionstore-backups",
                    ]:
                        p = profile / db
                        if p.is_file():
                            self._add(p, f"user/{un}/firefox/{profile.name}/{db}")

            # Chromium / Chrome / Brave / Edge (Linux XDG paths)
            for browser, rel in [
                ("chromium", ".config/chromium/Default"),
                ("chrome", ".config/google-chrome/Default"),
                ("brave", ".config/BraveSoftware/Brave-Browser/Default"),
                ("edge", ".config/microsoft-edge/Default"),
            ]:
                cb = user_dir / rel
                if not cb.exists():
                    continue
                for art in [
                    "History",
                    "Cookies",
                    "Login Data",
                    "Web Data",
                    "Bookmarks",
                    "Preferences",
                    "Network Action Predictor",
                ]:
                    p = cb / art
                    if p.is_file():
                        self._add(p, f"user/{un}/{browser}/{art}")

            # SSH known_hosts and authorized_keys (not private keys)
            ssh_dir = user_dir / ".ssh"
            if ssh_dir.exists():
                for f in ["known_hosts", "authorized_keys", "config"]:
                    self._add(ssh_dir / f, f"user/{un}/ssh/{f}")

            # Recent file listings
            for sub in ["Downloads", "Desktop"]:
                d = user_dir / sub
                if not d.exists():
                    continue
                out = self._run_cmd(
                    ["find", str(d), "-maxdepth", "3", "-mtime", "-30", "-type", "f", "-ls"],
                    timeout=15,
                )
                if out:
                    self._write_text(
                        f"recent_{sub.lower()}.txt", out, f"user/{un}/recent_{sub.lower()}.txt"
                    )

    def _network_config(self) -> None:
        """iptables/nftables rules, NetworkManager, netplan, /proc/net snapshots."""
        print("  [*] Network Configuration")

        # Firewall rule snapshots
        for cmd, fname in [
            (["iptables-save"], "iptables.rules"),
            (["ip6tables-save"], "ip6tables.rules"),
            (["nft", "list", "ruleset"], "nftables.rules"),
            (["ufw", "status", "verbose"], "ufw_status.txt"),
            (["firewall-cmd", "--list-all-zones"], "firewalld_zones.txt"),
        ]:
            out = self._run_cmd(cmd, timeout=10)
            if out:
                self._write_text(fname, out, f"network_config/{fname}")

        # NetworkManager saved connections (may contain PSKs / VPN secrets)
        for nm_dir in [
            Path("/etc/NetworkManager/system-connections"),
            Path("/etc/NetworkManager/dispatcher.d"),
        ]:
            if nm_dir.exists():
                for f in sorted(nm_dir.iterdir()):
                    if f.is_file():
                        self._add(f, f"network_config/NetworkManager/{nm_dir.name}/{f.name}")

        # netplan
        netplan_dir = Path("/etc/netplan")
        if netplan_dir.exists():
            for f in sorted(netplan_dir.iterdir()):
                if f.is_file():
                    self._add(f, f"network_config/netplan/{f.name}")

        # Debian ifupdown
        net_dir = Path("/etc/network")
        if net_dir.exists():
            for f in sorted(net_dir.rglob("*")):
                if f.is_file():
                    self._add(f, f"network_config/network/{f.relative_to(net_dir)}")

        # /proc/net: raw socket tables and ARP
        for pf in ["arp", "tcp", "tcp6", "udp", "udp6", "if_inet6", "dev", "route"]:
            self._add(Path(f"/proc/net/{pf}"), f"network_config/proc_net/{pf}")

        # Hosts / DNS
        for p in [
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/hosts.allow",
            "/etc/hosts.deny",
        ]:
            self._add(Path(p), f"network_config/{Path(p).name}")

        # Live interface + routing snapshot
        for cmd, fname in [
            (["ip", "-j", "addr"], "ip_addr.json"),
            (["ip", "-j", "route"], "ip_route.json"),
            (["ip", "-j", "neigh"], "ip_neigh.json"),
            (["ss", "-tulpan"], "ss_listening.txt"),
        ]:
            out = self._run_cmd(cmd, timeout=10)
            if out:
                self._write_text(fname, out, f"network_config/{fname}")

    def _audit_logs(self) -> None:
        """auditd logs, rules, and aureport summary."""
        print("  [*] Audit Logs (auditd)")

        # Raw audit logs
        for d in [Path("/var/log/audit"), Path("/var/log")]:
            if not d.exists():
                continue
            for f in sorted(d.glob("audit*")):
                if f.is_file():
                    self._add(f, f"audit/{f.name}")

        # Audit rules (what's being watched)
        for p in ["/etc/audit/audit.rules", "/etc/audit/auditd.conf"]:
            self._add(Path(p), f"audit/{Path(p).name}")
        rules_d = Path("/etc/audit/rules.d")
        if rules_d.exists():
            for f in sorted(rules_d.iterdir()):
                if f.is_file():
                    self._add(f, f"audit/rules.d/{f.name}")

        # aureport summaries (if auditd is present)
        for args, fname in [
            (["--summary"], "aureport_summary.txt"),
            (["--login", "--summary"], "aureport_logins.txt"),
            (["--user", "--summary"], "aureport_users.txt"),
            (["--failed", "--summary"], "aureport_failures.txt"),
            (["--executable", "--summary"], "aureport_exec.txt"),
        ]:
            out = self._run_cmd(["aureport"] + args, timeout=20)
            if out:
                self._write_text(fname, out, f"audit/{fname}")

        # Recent auth failures and EXECVE events via ausearch
        for label, extra, fname in [
            (
                "auth_failures",
                ["-m", "USER_AUTH", "--success", "no", "--start", "yesterday"],
                "ausearch_auth_failures.txt",
            ),
            ("execve_recent", ["-m", "EXECVE", "--start", "yesterday"], "ausearch_execve.txt"),
            ("setuid", ["-m", "SYSCALL", "-sc", "setuid,setgid,fchown"], "ausearch_setuid.txt"),
        ]:
            out = self._run_cmd(["ausearch"] + extra + ["-i"], timeout=20)
            if out:
                self._write_text(fname, out, f"audit/{fname}")

        # /var/log/auth.log and /var/log/secure (if not already in logs/)
        for p in ["/var/log/auth.log", "/var/log/secure", "/var/log/faillog"]:
            self._add(Path(p), f"audit/{Path(p).name}")

        # lastlog
        out = self._run_cmd(["lastlog"], timeout=10)
        if out:
            self._write_text("lastlog.txt", out, "audit/lastlog.txt")
        out = self._run_cmd(["faillock", "--user", "root"], timeout=5)
        if out:
            self._write_text("faillock_root.txt", out, "audit/faillock_root.txt")

    # vendor → log/quarantine dir or file. Whole tree collected (capped).
    _LINUX_AV_PATHS: list[tuple[str, str]] = [
        ("clamav", "/var/log/clamav"),
        # Trend Micro Deep Security / Cloud One Workload Security agent
        ("trendmicro", "/var/opt/ds_agent/diag"),
        ("trendmicro", "/opt/TrendMicro"),
        # Microsoft Defender for Endpoint
        ("mdatp", "/var/log/microsoft/mdatp"),
        # CrowdStrike Falcon
        ("crowdstrike", "/var/log/falcon-sensor.log"),
        ("crowdstrike", "/var/log/crowdstrike"),
        # SentinelOne
        ("sentinelone", "/opt/sentinelone/log"),
        # Sophos (SPL)
        ("sophos", "/var/log/sophos-spl"),
        ("sophos", "/opt/sophos-spl/logs"),
        # ESET
        ("eset", "/var/log/eset"),
        # Kaspersky
        ("kaspersky", "/var/log/kaspersky"),
        # Rootkit scanners
        ("rkhunter", "/var/log/rkhunter.log"),
        ("chkrootkit", "/var/log/chkrootkit"),
    ]

    def _antivirus(self) -> None:
        print("  [*] Antivirus / EDR")
        MAX_PER_VENDOR = 250
        MAX_SIZE = 50 * 1024 * 1024
        per_vendor: dict[str, int] = {}
        for vendor, raw in self._LINUX_AV_PATHS:
            base = Path(raw)
            if not base.exists():
                continue
            items = [base] if base.is_file() else sorted(base.rglob("*"))
            for p in items:
                n = per_vendor.get(vendor, 0)
                if n >= MAX_PER_VENDOR:
                    break
                try:
                    if not p.is_file() or p.is_symlink():
                        continue
                    size = p.stat().st_size
                    if size == 0 or size > MAX_SIZE:
                        continue
                    sub = p.relative_to(base) if base.is_dir() else p.name
                    if self._add(p, f"antivirus/{vendor}/{base.name}/{sub}"):
                        per_vendor[vendor] = n + 1
                except Exception:
                    pass
        # mdatp CLI state (live systems with Defender for Endpoint)
        if shutil.which("mdatp"):
            out = self._run_cmd(["mdatp", "health"], timeout=20)
            if out:
                self._write_text("mdatp_health.txt", out, "antivirus/mdatp/mdatp_health.txt")
            out = self._run_cmd(["mdatp", "threat", "list"], timeout=20)
            if out:
                self._write_text("mdatp_threats.txt", out, "antivirus/mdatp/mdatp_threats.txt")

    def _sysmon(self) -> None:
        """Sysmon For Linux: config + state under /opt/sysmon, events via syslog ident."""
        print("  [*] Sysmon For Linux")
        for raw in ["/opt/sysmon/config.xml", "/etc/sysmon/sysmon.xml"]:
            self._add(Path(raw), f"sysmon/config/{Path(raw).name}")
        d = Path("/opt/sysmon")
        if d.is_dir():
            for f in sorted(d.iterdir()):
                try:
                    if f.is_file() and f.stat().st_size <= 5 * 1024 * 1024:
                        self._add(f, f"sysmon/opt_sysmon/{f.name}")
                except Exception:
                    pass
        # Events land in syslog with ident "sysmon" — pull them from the journal
        out = self._run_cmd(
            ["journalctl", "-t", "sysmon", "--no-pager", "-o", "short-iso", "-n", "200000"],
            timeout=120,
        )
        if out and "-- No entries --" not in out:
            tmp = self.staging / "sysmon_events.log"
            tmp.write_text(out, encoding="utf-8", errors="replace")
            self._add(tmp, "sysmon/sysmon_events.log")

    def _containers(self) -> None:
        """Docker and Podman: running containers, images, logs, compose files."""
        print("  [*] Container Artifacts")

        for runtime in ("docker", "podman"):
            if not shutil.which(runtime):
                continue
            for cmd, fname in [
                ([runtime, "ps", "-a", "--no-trunc", "--format", "json"], f"{runtime}_ps.json"),
                ([runtime, "images", "--no-trunc", "--format", "json"], f"{runtime}_images.json"),
                (
                    [runtime, "network", "ls", "--no-trunc", "--format", "json"],
                    f"{runtime}_networks.json",
                ),
                ([runtime, "volume", "ls", "--format", "json"], f"{runtime}_volumes.json"),
                ([runtime, "info"], f"{runtime}_info.txt"),
                ([runtime, "system", "df"], f"{runtime}_disk.txt"),
            ]:
                out = self._run_cmd(cmd, timeout=30)
                if out:
                    self._write_text(fname, out, f"containers/{fname}")

            # Per-container: inspect + last 2000 log lines
            ids_out = self._run_cmd([runtime, "ps", "-aq"], timeout=10)
            if ids_out:
                for cid in ids_out.strip().splitlines()[:100]:
                    cid = cid.strip()
                    if not cid:
                        continue
                    inspect = self._run_cmd([runtime, "inspect", cid], timeout=15)
                    if inspect:
                        self._write_text(
                            f"inspect_{cid[:12]}.json",
                            inspect,
                            f"containers/inspect/{runtime}_{cid[:12]}.json",
                        )
                    logs = self._run_cmd([runtime, "logs", "--tail", "2000", cid], timeout=30)
                    if logs:
                        self._write_text(
                            f"logs_{cid[:12]}.txt",
                            logs,
                            f"containers/logs/{runtime}_{cid[:12]}.txt",
                        )

        # docker-compose / compose.yml files
        SEARCH_DIRS = [
            Path("/opt"),
            Path("/srv"),
            Path("/var/lib"),
            Path("/home"),
            Path("/root"),
            Path("/app"),
        ]
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            patterns = (
                sorted(d.rglob("docker-compose*.yml"))
                + sorted(d.rglob("docker-compose*.yaml"))
                + sorted(d.rglob("compose.yml"))
                + sorted(d.rglob("compose.yaml"))
            )
            for f in patterns:
                if count >= 100:
                    break
                self._add(f, f"containers/compose/{f.parent.name}/{f.name}")
                count += 1

        # Docker daemon config
        for p in ["/etc/docker/daemon.json", "/etc/docker/key.json", "/var/lib/docker/containers"]:
            pp = Path(p)
            if pp.is_file():
                self._add(pp, f"containers/docker/{pp.name}")

        # Container runtime socket (metadata only)
        for sock in [
            "/var/run/docker.sock",
            "/run/podman/podman.sock",
            "/run/containerd/containerd.sock",
        ]:
            if Path(sock).exists():
                self._write_text(
                    "container_sockets.txt", f"Found: {sock}\n", "containers/container_sockets.txt"
                )

    def _packages_and_tools(self) -> None:
        """Package inventory: dpkg, rpm, pip, npm, snap, flatpak, go, cargo."""
        print("  [*] Packages & Installed Tools")

        for cmd, fname in [
            (["dpkg", "-l"], "dpkg_list.txt"),
            (["rpm", "-qa", "--qf", r"%{NAME}\t%{VERSION}\t%{ARCH}\n"], "rpm_list.txt"),
            (["snap", "list"], "snap_list.txt"),
            (["flatpak", "list", "--app"], "flatpak_list.txt"),
            (["pip3", "list", "--format=columns"], "pip3_list.txt"),
            (["pip", "list", "--format=columns"], "pip_list.txt"),
            (["npm", "list", "-g", "--depth=0"], "npm_global.txt"),
            (["gem", "list"], "gem_list.txt"),
            (["cargo", "install", "--list"], "cargo_list.txt"),
            (["go", "env"], "go_env.txt"),
            # Runtime versions
            (["python3", "--version"], "python3_version.txt"),
            (["ruby", "--version"], "ruby_version.txt"),
            (["node", "--version"], "node_version.txt"),
            (["java", "-version"], "java_version.txt"),
            (["php", "--version"], "php_version.txt"),
            # Recently installed (Debian/Ubuntu)
            (
                ["bash", "-c", "grep 'install\\|upgrade' /var/log/dpkg.log | tail -500"],
                "recent_installs.txt",
            ),
            # Recently installed (RHEL)
            (
                [
                    "bash",
                    "-c",
                    "rpm -qa --qf '%{INSTALLTIME:date} %{NAME}\\n' | sort -r | head -200",
                ],
                "recent_rpm_installs.txt",
            ),
        ]:
            out = self._run_cmd(cmd, timeout=20)
            if out:
                self._write_text(fname, out, f"packages/{fname}")


# ─────────────────────────────────────────────────────────────────────────────
# macOS Collector
# ─────────────────────────────────────────────────────────────────────────────


class MacOSCollector(Collector):
    def collect_all(self) -> None:
        self._total_cats = len(self.collect)
        self._run_cat("logs", self._logs)
        self._run_cat("history", self._shell_history)
        self._run_cat("config", self._system_config)
        self._run_cat("launchagents", self._launch_agents)
        self._run_cat("browser", self._browser)
        self._run_cat("plist", self._plist_preferences)
        self._run_cat("network", self._network_captures)
        self._run_cat("pe", self._pe_binaries)
        self._run_cat("documents", self._documents)
        self._run_cat("triage", self._system_triage)
        self._run_cat("memory", self._memory)
        self._run_cat("file_search", self._file_search)

    # ── Logs ──────────────────────────────────────────────────────────────────

    def _logs(self) -> None:
        print("  [*] System Logs")
        # Traditional syslog-style files
        for name in ["system.log", "install.log", "fsck_apfs.log", "wifi.log"]:
            self._add(Path("/var/log") / name, f"logs/{name}")
        # Compress rotated logs
        for p in sorted(Path("/var/log").glob("*.gz"))[:30]:
            self._add(p, f"logs/{p.name}")
        # Unified Logging System — export last 7 days as JSON
        out = self._run_cmd(
            ["log", "show", "--style", "json", "--last", "7d", "--info"],
            timeout=120,
        )
        if out:
            tmp = self.staging / "unified_logs.ndjson"
            # 'log show --style json' returns a JSON array; save as-is
            tmp.write_text(out, encoding="utf-8", errors="replace")
            self._add(tmp, "logs/unified_logs.ndjson")
        else:
            # Fallback: human-readable text
            out_text = self._run_cmd(
                ["log", "show", "--last", "7d", "--info"],
                timeout=120,
            )
            if out_text:
                tmp = self.staging / "unified_logs.log"
                tmp.write_text(out_text, encoding="utf-8", errors="replace")
                self._add(tmp, "logs/unified_logs.log")

    # ── Shell history (same as Linux) ─────────────────────────────────────────

    def _shell_history(self) -> None:
        print("  [*] Shell Histories")
        HIST = [".bash_history", ".zsh_history", ".sh_history", ".python_history"]
        home = Path.home().parent  # /Users
        candidates = [Path("/var/root")]
        if home.exists():
            candidates += sorted(home.iterdir())
        for user_dir in candidates:
            if user_dir.is_dir():
                for h in HIST:
                    self._add(user_dir / h, f"history/{user_dir.name}/{h}")

    # ── System config ─────────────────────────────────────────────────────────

    def _system_config(self) -> None:
        print("  [*] System Configuration")
        for p in [
            "/etc/passwd",
            "/etc/group",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/ssh/sshd_config",
            "/private/etc/sudoers",
            "/System/Library/CoreServices/SystemVersion.plist",
        ]:
            self._add(Path(p), f"config/{Path(p).name}")
        # sudoers.d
        for d in ["/etc/sudoers.d", "/private/etc/sudoers.d"]:
            if Path(d).exists():
                for f in sorted(Path(d).iterdir()):
                    if f.is_file():
                        self._add(f, f"config/sudoers.d/{f.name}")

    # ── LaunchAgents / LaunchDaemons (macOS persistence) ─────────────────────

    def _launch_agents(self) -> None:
        print("  [*] Launch Agents / Daemons")
        dirs = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ]
        # Per-user LaunchAgents
        home = Path.home().parent
        if home.exists():
            for user_dir in sorted(home.iterdir()):
                dirs.append(str(user_dir / "Library" / "LaunchAgents"))

        for d in dirs:
            dp = Path(d)
            if dp.exists():
                for f in sorted(dp.glob("*.plist"))[:200]:
                    rel = f.relative_to(dp.parent)
                    self._add(f, f"launchagents/{dp.name}/{f.name}")

    # ── Browser artifacts ─────────────────────────────────────────────────────

    @staticmethod
    def _check_tcc() -> bool:
        """Return True if Safari data is readable (Full Disk Access granted)."""
        import os

        try:
            test = Path("/Users")
            for ud in sorted(test.iterdir()):
                sf = ud / "Library" / "Safari" / "History.db"
                if sf.exists():
                    os.access(str(sf), os.R_OK)
                    with open(sf, "rb") as fh:
                        fh.read(4)
                    return True
            return True  # no Safari dir found — not a TCC issue
        except PermissionError:
            return False
        except Exception:
            return True

    def _browser(self) -> None:
        print("  [*] Browser Artifacts")
        if not self._check_tcc():
            print(
                "\n  ⚠  TCC RESTRICTION — Safari and browser data are protected by macOS privacy controls.\n"
                "     Even root cannot read these files without Full Disk Access.\n"
                "     Fix: System Settings → Privacy & Security → Full Disk Access\n"
                "          → add your Terminal app (Terminal.app / iTerm2 / etc.)\n"
                "     Then re-run this script.\n"
            )
        home = Path.home().parent
        candidates = sorted(home.iterdir()) if home.exists() else []
        for user_dir in candidates:
            if not user_dir.is_dir():
                continue
            lib = user_dir / "Library"
            # Chromium-based browsers (Chrome, Brave, Edge, Opera, Vivaldi)
            chromium_browsers = [
                ("chrome", "Google/Chrome"),
                ("brave", "BraveSoftware/Brave-Browser"),
                ("edge", "Microsoft Edge"),
                ("opera", "com.operasoftware.Opera"),
                ("vivaldi", "Vivaldi"),
            ]
            for bname, subpath in chromium_browsers:
                profile = lib / "Application Support" / subpath / "Default"
                for db in ["History", "Cookies", "Web Data", "Login Data", "Bookmarks"]:
                    self._add(profile / db, f"browser/{user_dir.name}/{bname}/{db}")
            # Safari
            safari_dir = lib / "Safari"
            for sf in [
                "History.db",
                "Downloads.plist",
                "Bookmarks.plist",
                "RecentlyClosedTabs.plist",
                "LastSession.plist",
            ]:
                self._add(safari_dir / sf, f"browser/{user_dir.name}/safari/{sf}")
            # Firefox
            ff_profiles = lib / "Application Support" / "Firefox" / "Profiles"
            if ff_profiles.exists():
                for profile in sorted(ff_profiles.iterdir()):
                    for db in [
                        "places.sqlite",
                        "cookies.sqlite",
                        "logins.json",
                        "formhistory.sqlite",
                    ]:
                        self._add(
                            profile / db, f"browser/{user_dir.name}/firefox/{profile.name}/{db}"
                        )
            # Quarantine database (file download history)
            quarantine = lib / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"
            self._add(quarantine, f"browser/{user_dir.name}/quarantine_events.sqlite")

    # ── Plist preferences ─────────────────────────────────────────────────────

    def _plist_preferences(self) -> None:
        """Collect plist files from system and per-user preference directories."""
        print("  [*] macOS Preference Plists")
        PREF_DIRS = [
            Path("/Library/Preferences"),
            Path("/Library/Application Support"),
            Path("/System/Library/Preferences"),
        ]
        home = Path.home().parent  # /Users
        if home.exists():
            for user_dir in sorted(home.iterdir()):
                if user_dir.is_dir():
                    PREF_DIRS.append(user_dir / "Library" / "Preferences")
                    PREF_DIRS.append(user_dir / "Library" / "Application Support")

        MAX_FILES = 5000
        count = 0
        for d in PREF_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*.plist"))[: MAX_FILES - count]:
                if count >= MAX_FILES:
                    break
                try:
                    rel = p.relative_to(d.parent)
                except ValueError:
                    rel = Path(d.name) / p.name
                if self._add(p, f"plist/{rel}"):
                    count += 1

    # ── Network captures ──────────────────────────────────────────────────────

    def _network_captures(self) -> None:
        """Collect PCAP/PCAPNG files or run a short live capture via tcpdump."""
        print("  [*] PCAP / Network Captures")
        SEARCH_DIRS = [
            Path("/var/log"),
            Path("/tmp"),
            Path.home().parent,
            Path("/Library/Logs"),
            Path("/var/capture"),
        ]
        MAX_SIZE = 500 * 1024 * 1024  # 500 MB per file
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in (
                sorted(d.rglob("*.pcap")) + sorted(d.rglob("*.pcapng")) + sorted(d.rglob("*.cap"))
            ):
                if count >= 10:
                    break
                if p.stat().st_size <= MAX_SIZE:
                    if self._add(p, f"network/{p.name}"):
                        count += 1
            if count >= 10:
                break

        if count == 0 and shutil.which("tcpdump"):
            cap_path = self.staging / f"live-{HOSTNAME}-{TS_NOW}.pcap"
            print("      Live capture: 30 s via tcpdump (requires sudo)")
            try:
                subprocess.run(
                    ["tcpdump", "-i", "any", "-w", str(cap_path), "-G", "30", "-W", "1"],
                    timeout=35,
                    capture_output=True,
                )
                self._add(cap_path, f"network/{cap_path.name}")
            except Exception as exc:
                self._log(f"tcpdump: {exc}")

    # ── PE binaries ───────────────────────────────────────────────────────────

    def _pe_binaries(self) -> None:
        """Collect suspicious binaries from temp/download locations."""
        print("  [*] PE / Executable Binaries")
        home = Path.home().parent
        SEARCH_DIRS = [Path("/tmp"), Path("/var/tmp")]
        if home.exists():
            for user_dir in sorted(home.iterdir()):
                if user_dir.is_dir():
                    SEARCH_DIRS += [
                        user_dir / "Downloads",
                        user_dir / "Desktop",
                    ]

        ELF_MAGIC = b"\x7fELF"
        PE_MAGIC = b"MZ"
        MAX_FILE = 50 * 1024 * 1024
        MAX_FILES = 500
        count = 0
        for d in SEARCH_DIRS:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES:
                    break
                if not p.is_file():
                    continue
                sz = p.stat().st_size
                if sz < 4 or sz > MAX_FILE:
                    continue
                try:
                    magic = p.read_bytes()[:4]
                except (PermissionError, OSError):
                    continue
                if not (magic[:4] == ELF_MAGIC or magic[:2] == PE_MAGIC):
                    continue
                if self._add(p, f"pe/{d.name}/{p.name}"):
                    count += 1

    # ── Office documents ──────────────────────────────────────────────────────

    def _documents(self) -> None:
        """Collect Office documents and PDFs from user directories."""
        print("  [*] Office Documents & PDFs")
        DOC_EXTS = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".rtf",
            ".pdf",
            ".odt",
            ".ods",
            ".pages",
            ".numbers",
            ".key",
        }
        MAX_FILE = 100 * 1024 * 1024
        MAX_FILES = 500
        home = Path.home().parent
        count = 0
        for user_dir in sorted(home.iterdir()) if home.exists() else []:
            if not user_dir.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = user_dir / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{user_dir.name}/{rel}/{p.name}"):
                        count += 1

    # ── System triage ─────────────────────────────────────────────────────────

    def _system_triage(self) -> None:
        print("  [*] System Triage (live commands)")
        lines: list[str] = []
        for header, cmd in [
            ("OS VERSION", ["sw_vers"]),
            ("UNAME", ["uname", "-a"]),
            ("PROCESSES", ["ps", "auxww"]),
            ("NETWORK SOCKETS", ["netstat", "-anv"]),
            ("NETWORK IFACEs", ["ifconfig"]),
            ("ROUTING TABLE", ["netstat", "-rn"]),
            ("ARP CACHE", ["arp", "-an"]),
            ("CURRENT USERS", ["who"]),
            ("LAST LOGINS", ["last", "-n", "200"]),
            ("MOUNTS", ["mount"]),
            ("DISK USAGE", ["df", "-h"]),
            ("LOADED KEXTS", ["kextstat"]),
            ("LAUNCH DAEMONS", ["launchctl", "list"]),
            ("INSTALLED APPS", ["system_profiler", "SPApplicationsDataType"]),
            ("NETWORK SERVICES", ["networksetup", "-listallnetworkservices"]),
            ("FIREWALL", ["socketfilterfw", "--getglobalstate"]),
            ("SUID FILES", ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]),
            ("ENVIRONMENT", ["env"]),
        ]:
            lines.append(f"\n{'=' * 60}\n{header}\n{'=' * 60}")
            lines.append(self._run_cmd(cmd, timeout=60))
        self._write_text("system_triage.txt", "\n".join(lines), "system_triage.txt")

    # ── Memory acquisition ────────────────────────────────────────────────────

    def _memory(self) -> None:
        print("  [*] Physical Memory Dump (live acquisition)")
        print("  [!] Note: Memory dumps are typically 4–64 GB — this may take a while")
        print("  [!] Root privileges are required for memory acquisition")

        dump_path = self.staging / f"memory-{HOSTNAME}-{TS_NOW}.raw"

        # osxpmem (most reliable tool for macOS)
        osxpmem = shutil.which("osxpmem")
        if not osxpmem:
            # Check common locations
            for loc in [
                "/usr/local/bin/osxpmem",
                Path.cwd() / "osxpmem",
                Path(__file__).parent / "osxpmem",
            ]:
                if Path(loc).exists():
                    osxpmem = str(loc)
                    break

        if osxpmem:
            self._log(f"Using osxpmem: {osxpmem}")
            print(f"      Output: {dump_path}")
            try:
                r = subprocess.run(
                    [osxpmem, str(dump_path)],
                    capture_output=True,
                    timeout=7200,
                )
                if r.returncode == 0 and dump_path.exists() and dump_path.stat().st_size > 0:
                    self._add(dump_path, f"memory/{dump_path.name}")
                    size_gb = dump_path.stat().st_size / (1024**3)
                    print(f"  [+] Memory dump complete ({size_gb:.1f} GB)")
                    return
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:400]
                self._warn(f"osxpmem failed (code {r.returncode}): {err}")
            except subprocess.TimeoutExpired:
                self._warn("osxpmem timed out (>2 hours)")
            except Exception as exc:
                self._warn(f"osxpmem error: {exc}")

        self._warn(
            "No memory acquisition tool found.\n"
            "      Download osxpmem for macOS memory acquisition:\n"
            "        https://github.com/google/rekall/releases\n"
            "      Run: sudo osxpmem memory.raw"
        )


# ─────────────────────────────────────────────────────────────────────────────
# External Disk Collector (BitLocker support via dislocker-fuse)
# ─────────────────────────────────────────────────────────────────────────────


class ExternalDiskCollector(Collector):
    """
    Collect forensic artifacts from an external Windows disk (NTFS).

    Works on Linux with dislocker-fuse for BitLocker-encrypted partitions,
    or with a plain ntfs-3g/mount for unencrypted NTFS disks.
    Also accepts a path to an already-mounted directory.

    Usage
    -----
      # Unencrypted NTFS partition:
      talon --disk /dev/sdb1

      # BitLocker-encrypted partition (recovery key):
      talon --disk /dev/sdb1 --bitlocker-key "123456-789012-345678-901234-567890-123456-789012-345678"

      # Already-mounted directory (no root needed):
      talon --disk /mnt/external

    Requirements (Linux)
    --------------------
      apt-get install dislocker ntfs-3g
    """

    # Mirrors harvest_task LEVEL_CATEGORIES["small"] — safe defaults for dead-box triage.
    # Heavy categories (memory_artifacts, pe, documents, printing) are opt-in only.
    DEFAULT_COLLECT = {
        "evtx",
        "registry",
        "prefetch",
        "mft",
        "execution",
        "persistence",
        "network_cfg",
        "usb_devices",
        "credentials",
        "antivirus",
        "sysmon",
        "wer_crashes",
        "win_logs",
    }

    def __init__(self, disk: str, bitlocker_key: str = "", **kwargs):
        super().__init__(**kwargs)
        self.disk = disk
        self.bitlocker_key = bitlocker_key.strip()
        self._dislocker_dir: Path | None = None
        self._ntfs_dir: Path | None = None
        self._cryptsetup_map: str | None = None

    # ── Mount lifecycle ───────────────────────────────────────────────────────

    def _run_privileged(self, cmd: list, timeout: int = 60) -> bool:
        """Run a command, prepending sudo when not already root."""
        if IS_LINUX and os.getuid() != 0:
            cmd = ["sudo"] + cmd
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            if r.returncode != 0:
                err = (r.stderr or r.stdout or b"").decode(errors="replace")[:300]
                self._warn(f"{cmd[0]} failed: {err}")
                return False
            return True
        except subprocess.TimeoutExpired:
            self._warn(f"{cmd[0]} timed out")
            return False
        except Exception as exc:
            self._warn(f"{cmd[0]} error: {exc}")
            return False

    def _detect_bitlocker(self, device: str) -> bool:
        """Check for BitLocker volume signature at sector offset 3."""
        try:
            with open(device, "rb") as fh:
                header = fh.read(16)
            return header[3:11] == b"-FVE-FS-"
        except (PermissionError, OSError):
            # Cannot read raw device — assume it may be BitLocker if key provided
            return bool(self.bitlocker_key)

    def _unlock_bitlocker(self, device: str, mount_point: Path) -> str | None:
        """
        Unlock a BitLocker partition.

        Tries dislocker-fuse first; falls back to cryptsetup (handles BitLocker v2
        / XTS-AES which dislocker ≤0.7.2 cannot process).

        Returns:
          - path to dislocker-file (dislocker mode), or
          - "/dev/mapper/<name>" string (cryptsetup mode, stored in self._cryptsetup_map)
          - None on failure
        """
        mount_point.mkdir(parents=True, exist_ok=True)

        # ── Try dislocker-fuse first ───────────────────────────────────────────
        dl_bin = shutil.which("dislocker-fuse") or shutil.which("dislocker")
        if dl_bin:
            dl_help = ""
            try:
                r = subprocess.run([dl_bin, "--help"], capture_output=True, text=True, timeout=5)
                dl_help = r.stderr + r.stdout
            except Exception:
                pass
            use_v_flag = "-V" in dl_help

            if use_v_flag:
                cmd = [dl_bin, "-V", device]
            else:
                cmd = [dl_bin, device]

            if self.bitlocker_key:
                if re.match(r"^[\d\-]+$", self.bitlocker_key):
                    cmd += ["-p", self.bitlocker_key]
                else:
                    cmd += ["-u", self.bitlocker_key]

            cmd += ["--", str(mount_point)]
            print(f"      dislocker-fuse: unlocking {device} → {mount_point}")

            if self._run_privileged(cmd, timeout=120):
                dl_file = mount_point / "dislocker-file"
                if dl_file.exists():
                    return str(dl_file)
                self._warn(f"dislocker-fuse succeeded but dislocker-file absent in {mount_point}")
            else:
                print("      dislocker-fuse failed — trying cryptsetup fallback")
        else:
            print("      dislocker-fuse not found — trying cryptsetup")

        # ── Fallback: cryptsetup bitlk (Ubuntu 20.04+, handles BitLocker v2) ──
        cs_bin = shutil.which("cryptsetup")
        if not cs_bin:
            self._warn(
                "Neither dislocker-fuse nor cryptsetup found.\n"
                "Install with: apt-get install dislocker cryptsetup"
            )
            return None

        if not self.bitlocker_key:
            self._warn("No BitLocker key supplied — cryptsetup requires a key for BITLK")
            return None

        map_name = f"fo_bitlk_{os.path.basename(device).replace('/', '_')}"
        mapper_path = f"/dev/mapper/{map_name}"
        print(f"      cryptsetup: unlocking {device} → {mapper_path}")

        # Close any stale mapper entry from a previous failed run
        if Path(mapper_path).exists():
            print("      cryptsetup: stale mapper found — closing before retry")
            subprocess.run(["sudo", cs_bin, "close", map_name], capture_output=True, timeout=15)

        # Warn if device already has dm-crypt holders (e.g. a previous manual test_map)
        holders_dir = Path(f"/sys/class/block/{os.path.basename(device)}/holders")
        if holders_dir.exists():
            holders = list(holders_dir.iterdir())
            if holders:
                holder_names = [h.name for h in holders]
                print(
                    f"      cryptsetup: WARNING — {device} already open as {holder_names} — "
                    f"run: sudo cryptsetup close {holder_names[0]}"
                )

        key_with_dash = self.bitlocker_key.strip()
        key_without_dash = re.sub(r"[-\s]", "", key_with_dash)

        # Detect recovery key format (48 digits + 7 dashes = 55 chars)
        is_recovery_fmt = bool(re.fullmatch(r"(\d{6}-){7}\d{6}", key_with_dash))
        print(
            f"      cryptsetup: key len={len(key_with_dash)} recovery_fmt={is_recovery_fmt} "
            f"preview={key_with_dash[:6]}...{key_with_dash[-6:]}"
        )
        try:
            _ver = subprocess.run(
                [cs_bin, "--version"], capture_output=True, text=True, timeout=10
            ).stdout.strip()
        except Exception as _vexc:
            _ver = f"<version probe failed: {_vexc}>"
        print(f"      cryptsetup: version = {_ver}")

        # cryptsetup reads passphrases from /dev/tty, ignoring piped stdin.
        # Use bash process substitution <(printf KEY) → /dev/fd/N.
        # Sudo strips inherited fds, so run the ENTIRE bash (incl. process
        # sub + cryptsetup) under one sudo invocation.
        import shlex

        def _try_cs(key: str, label: str) -> subprocess.CompletedProcess[bytes]:
            qkey = shlex.quote(key)
            qdev = shlex.quote(device)
            qmap = shlex.quote(map_name)
            qcs = shlex.quote(cs_bin)
            shell_cmd = (
                f"{qcs} open --type bitlk --verbose --key-file <(printf '%s' {qkey}) {qdev} {qmap}"
            )
            argv = ["sudo", "bash", "-c", shell_cmd]
            print(
                f"      cryptsetup [{label}]: sudo bash -c '{cs_bin} open "
                f"--type bitlk --key-file <(printf KEY) {device} {map_name}'"
            )
            r = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            out = (r.stderr + r.stdout).decode(errors="replace").strip()
            print(f"      cryptsetup [{label}]: rc={r.returncode} out={repr(out)}")
            return r

        try:
            proc = _try_cs(key_with_dash, "with-dashes")
            if proc.returncode != 0:
                err = (proc.stderr + proc.stdout).decode(errors="replace").strip()
                if key_without_dash != key_with_dash:
                    proc2 = _try_cs(key_without_dash, "no-dashes")
                    if proc2.returncode == 0:
                        proc = proc2
                    else:
                        err2 = (proc2.stderr + proc2.stdout).decode(errors="replace").strip()
                        self._warn(f"cryptsetup bitlk failed: {err} | no-dash attempt: {err2}")
                        return None
                else:
                    self._warn(f"cryptsetup bitlk failed: {err}")
                    return None
        except Exception as exc:
            self._warn(f"cryptsetup error: {exc}")
            return None

        if not Path(mapper_path).exists():
            self._warn(f"cryptsetup succeeded but {mapper_path} not found")
            return None

        self._cryptsetup_map = map_name
        return mapper_path

    def _mount_ntfs(self, source: str, mount_point: Path) -> bool:
        """Mount an NTFS image or partition read-only at mount_point."""
        mount_point.mkdir(parents=True, exist_ok=True)

        # Prefer ntfs-3g (handles advanced NTFS features and compressed files)
        ntfs3g = shutil.which("ntfs-3g") or shutil.which("mount.ntfs-3g")
        if ntfs3g:
            ok = self._run_privileged(
                [
                    ntfs3g,
                    source,
                    str(mount_point),
                    "-o",
                    "ro,noatime,streams_interface=none,nodev,nosuid",
                ],
                timeout=30,
            )
            if ok:
                return True

        # Generic mount fallback (kernel NTFS module)
        ok = self._run_privileged(
            ["mount", "-t", "ntfs", "-o", "ro,noatime", source, str(mount_point)],
            timeout=30,
        )
        return ok

    def _umount(self, path: Path) -> None:
        self._run_privileged(["umount", "-l", str(path)], timeout=30)

    def unlock_and_mount(self) -> Path | None:
        """
        Full pipeline: detect → BitLocker unlock → NTFS mount.
        Returns the filesystem root Path, or None on any failure.
        """
        disk_path = Path(self.disk)

        # Normalize bare drive letter: Path("E:") on Windows is a *relative* path
        # (it refers to the CWD of drive E:), so "E:" / "Windows" → "E:Windows".
        # Appending os.sep makes it absolute: "E:\" / "Windows" → "E:\Windows".
        if IS_WINDOWS:
            s = str(disk_path)
            if len(s) == 2 and s[1] == ":":
                disk_path = Path(s + os.sep)

        # Already a mounted directory
        if disk_path.is_dir():
            print(f"      Using existing mount: {disk_path}")
            return disk_path

        device = str(disk_path)

        # ── BitLocker unlock ───────────────────────────────────────────────────
        is_bitlocker = self.bitlocker_key or self._detect_bitlocker(device)
        if is_bitlocker:
            print(f"  [*] BitLocker volume detected — unlocking {device}")
            self._dislocker_dir = Path(tempfile.mkdtemp(prefix="fo_dislocker_"))
            dl_file = self._unlock_bitlocker(device, self._dislocker_dir)
            if dl_file is None:
                return None
            ntfs_source = dl_file
        else:
            ntfs_source = device

        # ── NTFS mount ─────────────────────────────────────────────────────────
        self._ntfs_dir = Path(tempfile.mkdtemp(prefix="fo_ntfs_"))
        print(f"  [*] Mounting NTFS → {self._ntfs_dir}")
        if not self._mount_ntfs(ntfs_source, self._ntfs_dir):
            self._warn(f"Failed to mount NTFS from {ntfs_source}")
            return None

        return self._ntfs_dir

    def cleanup(self) -> None:
        """Unmount filesystems before removing the staging directory."""
        if self._ntfs_dir and self._ntfs_dir.exists():
            self._umount(self._ntfs_dir)
            try:
                self._ntfs_dir.rmdir()
            except OSError:
                pass

        if self._dislocker_dir and self._dislocker_dir.exists():
            self._umount(self._dislocker_dir)
            try:
                self._dislocker_dir.rmdir()
            except OSError:
                pass

        if self._cryptsetup_map:
            cs_bin = shutil.which("cryptsetup")
            if cs_bin:
                subprocess.run(
                    ["sudo", cs_bin, "close", self._cryptsetup_map], capture_output=True, timeout=30
                )
            self._cryptsetup_map = None

        super().cleanup()

    # ── Artifact collection from filesystem root ──────────────────────────────

    def collect_all(self) -> None:
        root = self.unlock_and_mount()
        if root is None:
            self._warn("Could not access the disk — no artifacts collected")
            return

        win_dir = root / "Windows"
        users_dir = root / "Users"

        print(f"  Filesystem root : {root}")
        print(f"  Windows dir     : {'found' if win_dir.exists() else 'not found'}")
        print(f"  Users dir       : {'found' if users_dir.exists() else 'not found'}")
        print()

        self._total_cats = len(self.collect)

        # ── Core ─────────────────────────────────────────────────────────────
        self._run_cat("evtx", self._evtx_from, win_dir)
        self._run_cat("sysmon", self._sysmon_from, root, win_dir)
        self._run_cat("registry", self._registry_from, win_dir, users_dir)
        self._run_cat("prefetch", self._prefetch_from, win_dir)
        self._run_cat("mft", self._mft_from, root)
        self._run_cat("execution", self._execution_from, win_dir)
        self._run_cat("persistence", self._persistence_from, win_dir)
        self._run_cat("filesystem", self._filesystem_from, root)
        # ── Network & USB ────────────────────────────────────────────────────
        self._run_cat("network_cfg", self._network_cfg_from, root, win_dir)
        self._run_cat("usb_devices", self._usb_devices_from, win_dir)
        # ── Credentials & Security ───────────────────────────────────────────
        self._run_cat("credentials", self._credentials_from, win_dir, users_dir)
        self._run_cat("antivirus", self._antivirus_from, root)
        self._run_cat("wer_crashes", self._wer_crashes_from, root)
        self._run_cat("win_logs", self._win_logs_from, win_dir)
        self._run_cat("boot_uefi", self._boot_uefi_from, win_dir)
        self._run_cat("encryption", self._encryption_from, win_dir)
        self._run_cat("etw_diagnostics", self._etw_diagnostics_from, win_dir)
        # ── Browsers ─────────────────────────────────────────────────────────
        self._run_cat("browser", self._browser_from, users_dir)
        self._run_cat("browser_chrome", self._browser_chrome_from, users_dir)
        self._run_cat("browser_edge", self._browser_edge_from, users_dir)
        self._run_cat("browser_ie", self._browser_ie_from, users_dir)
        # ── Email ────────────────────────────────────────────────────────────
        self._run_cat("email_outlook", self._email_outlook_from, users_dir)
        self._run_cat("email_thunderbird", self._email_thunderbird_from, users_dir)
        # ── Messaging ────────────────────────────────────────────────────────
        self._run_cat("teams", self._teams_from, users_dir)
        self._run_cat("slack", self._slack_from, users_dir)
        self._run_cat("discord", self._discord_from, users_dir)
        self._run_cat("signal", self._signal_from, users_dir)
        self._run_cat("whatsapp", self._whatsapp_from, users_dir)
        self._run_cat("telegram", self._telegram_from, users_dir)
        # ── Cloud ────────────────────────────────────────────────────────────
        self._run_cat("cloud_onedrive", self._cloud_onedrive_from, users_dir)
        self._run_cat("cloud_google_drive", self._cloud_google_drive_from, users_dir)
        self._run_cat("cloud_dropbox", self._cloud_dropbox_from, users_dir)
        # ── Remote access ────────────────────────────────────────────────────
        self._run_cat("remote_access", self._remote_access_from, root, users_dir)
        self._run_cat("rdp", self._rdp_from, users_dir)
        self._run_cat("ssh_ftp", self._ssh_ftp_from, users_dir)
        # ── Apps & user data ─────────────────────────────────────────────────
        self._run_cat("lnk", self._lnk_from, users_dir)
        self._run_cat("tasks", self._tasks_from, win_dir)
        self._run_cat("office", self._office_from, users_dir)
        self._run_cat("dev_tools", self._dev_tools_from, users_dir)
        self._run_cat("password_managers", self._password_managers_from, users_dir)
        self._run_cat("database_clients", self._database_clients_from, users_dir)
        self._run_cat("gaming", self._gaming_from, root, users_dir)
        self._run_cat("windows_apps", self._windows_apps_from, users_dir)
        self._run_cat("wsl", self._wsl_from, users_dir)
        # ── Infrastructure ───────────────────────────────────────────────────
        self._run_cat("vpn", self._vpn_from, root)
        self._run_cat("iis_web", self._iis_web_from, root)
        self._run_cat("active_directory", self._active_directory_from, win_dir)
        self._run_cat("virtualization", self._virtualization_from, root)
        self._run_cat("recovery", self._recovery_from, root)
        self._run_cat("printing", self._printing_from, win_dir)
        # ── Heavy / opt-in ───────────────────────────────────────────────────
        self._run_cat("pe", self._pe_from, win_dir, users_dir)
        self._run_cat("documents", self._documents_from, users_dir)
        self._run_cat("memory_artifacts", self._memory_artifacts_from, root)
        # ── On-demand file fetch (--fetch) ───────────────────────────────────
        self._run_cat("file_search", self._file_search, [root])

    def _evtx_from(self, win_dir: Path) -> None:
        print("  [*] Event Logs (EVTX)")
        evtx_dir = win_dir / "System32" / "winevt" / "Logs"
        if not evtx_dir.exists():
            self._warn(f"EVTX directory not found: {evtx_dir}")
            return
        seen: set = set()
        for name in EVTX_PRIORITY:
            src = evtx_dir / name
            try:
                if not src.is_file() or src.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{name}"
                if self._stage_file(src, tmp) and self._add(tmp, f"evtx/{name}"):
                    seen.add(name)
            except Exception as exc:
                self._warn(f"EVTX {name}: {exc}")
        count = 0
        try:
            all_evtx = sorted(evtx_dir.glob("*.evtx"))
        except Exception as exc:
            self._warn(f"EVTX glob error: {exc}")
            return
        for p in all_evtx:
            if count >= 200:
                break
            try:
                if p.name in seen:
                    continue
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"evtx_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"evtx/{p.name}"):
                    count += 1
            except Exception as exc:
                self._warn(f"EVTX {p.name}: {exc}")

    def _registry_from(self, win_dir: Path, users_dir: Path) -> None:
        print("  [*] Registry Hives")
        config_dir = win_dir / "System32" / "config"
        for name in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]:
            src = config_dir / name
            try:
                if not src.is_file():
                    continue
                tmp = self.staging / f"reg_{name}"
                if self._stage_file(src, tmp):
                    self._add(tmp, f"registry/{name}")
            except Exception as exc:
                self._warn(f"Registry {name}: {exc}")
        if users_dir.exists():
            for user_dir in sorted(users_dir.iterdir()):
                if not user_dir.is_dir():
                    continue
                safe = user_dir.name.replace(" ", "_").replace("/", "_")
                for src, fname, arcname in [
                    (
                        user_dir / "NTUSER.DAT",
                        "NTUSER.DAT",
                        f"registry/users/{user_dir.name}/NTUSER.DAT",
                    ),
                    (
                        user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat",
                        "USRCLASS.DAT",
                        f"registry/users/{user_dir.name}/USRCLASS.DAT",
                    ),
                ]:
                    try:
                        if not src.is_file():
                            continue
                        tmp = self.staging / f"reg_{safe}_{fname}"
                        if self._stage_file(src, tmp):
                            self._add(tmp, arcname)
                    except Exception as exc:
                        self._warn(f"Registry {user_dir.name}/{fname}: {exc}")

    def _prefetch_from(self, win_dir: Path) -> None:
        print("  [*] Prefetch Files")
        pf_dir = win_dir / "Prefetch"
        count = 0
        success_count = 0
        error_count = 0
        try:
            pf_files = sorted(pf_dir.glob("*.pf")) if pf_dir.exists() else []
        except Exception as exc:
            self._warn(f"Prefetch glob error: {exc}")
            return
        for p in pf_files:
            if count >= 500:
                break
            count += 1
            try:
                if p.stat().st_size == 0:
                    continue
                tmp = self.staging / f"pf_{p.name}"
                if self._stage_file(p, tmp) and self._add(tmp, f"prefetch/{p.name}"):
                    success_count += 1
                else:
                    error_count += 1
                    if self.verbose and error_count <= 5:
                        self._log(f"Prefetch copy failed: {p.name} (may be WOF-compressed)")
            except PermissionError:
                error_count += 1
                if error_count <= 3:
                    self._warn(f"Prefetch {p.name}: Permission denied")
            except OSError as exc:
                error_count += 1
                if exc.errno == 22 and error_count <= 3:
                    self._log(f"Prefetch {p.name}: Invalid argument (WOF compression)")
            except Exception as exc:
                error_count += 1
                if error_count <= 3:
                    self._warn(f"Prefetch {p.name}: {exc}")

        if error_count > 0 and success_count == 0:
            self._warn(
                f"Prefetch: {error_count} files failed - may be WOF-compressed (Windows 10+)"
            )
        elif error_count > success_count * 2:
            self._log(
                f"Prefetch: {success_count}/{count} succeeded, {error_count} failed (WOF compression likely)"
            )

    def _lnk_from(self, users_dir: Path) -> None:
        print("  [*] LNK / Recent Items")
        count = 0
        for user_dir in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not user_dir.is_dir():
                continue
            recent = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            for p in recent.rglob("*.lnk") if recent.exists() else []:
                if count >= 2000:
                    break
                if self._add(p, f"lnk/{user_dir.name}/{p.name}"):
                    count += 1

    def _browser_from(self, users_dir: Path) -> None:
        print("  [*] Browser Artifacts")
        PROFILES = [
            ("chrome", "AppData/Local/Google/Chrome/User Data/Default"),
            ("edge", "AppData/Local/Microsoft/Edge/User Data/Default"),
            ("brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default"),
            ("opera", "AppData/Roaming/Opera Software/Opera Stable"),
            ("vivaldi", "AppData/Local/Vivaldi/User Data/Default"),
        ]
        DB_FILES = ["History", "Web Data", "Cookies", "Login Data", "Bookmarks"]
        error_count = 0

        for user_dir in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not user_dir.is_dir():
                continue
            for browser, rel in PROFILES:
                profile_dir = user_dir / Path(rel.replace("/", os.sep))
                for db in DB_FILES:
                    src = profile_dir / db
                    try:
                        if not src.exists() or not src.is_file():
                            continue
                        if src.stat().st_size == 0:
                            continue
                        tmp = self.staging / f"browser_{user_dir.name}_{browser}_{db}"
                        if self._copy_locked(src, tmp):
                            self._add(tmp, f"browser/{browser}/{user_dir.name}/{db}")
                        else:
                            error_count += 1
                            if self.verbose and error_count <= 3:
                                self._log(f"Browser {browser}/{db}: copy failed (file locked?)")
                    except Exception:
                        error_count += 1
            # Firefox
            ff_profiles = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            if ff_profiles.exists():
                for prof in ff_profiles.iterdir():
                    if not prof.is_dir():
                        continue
                    for db in (
                        "places.sqlite",
                        "cookies.sqlite",
                        "logins.json",
                        "formhistory.sqlite",
                    ):
                        src = prof / db
                        try:
                            if not src.exists() or not src.is_file():
                                continue
                            tmp = self.staging / f"ff_{user_dir.name}_{prof.name}_{db}"
                            if self._copy_locked(src, tmp):
                                self._add(tmp, f"browser/firefox/{user_dir.name}/{prof.name}/{db}")
                        except Exception:
                            pass

    def _tasks_from(self, win_dir: Path) -> None:
        print("  [*] Scheduled Tasks")
        tasks_dir = win_dir / "System32" / "Tasks"
        count = 0
        error_count = 0
        try:
            task_files = list(tasks_dir.rglob("*")) if tasks_dir.exists() else []
        except Exception as exc:
            self._warn(f"Tasks scan error: {exc}")
            return
        for p in task_files:
            if count >= 500:
                break
            try:
                if p.is_file() and not p.suffix:
                    rel = str(p.relative_to(tasks_dir)).replace("\\", "/")
                    if self._add(p, f"scheduled_tasks/{rel}"):
                        count += 1
            except PermissionError:
                error_count += 1
                if error_count <= 3:
                    self._log(f"Task {p.name}: Permission denied (reparse point?)")
            except OSError as exc:
                error_count += 1
                if exc.errno == 22 and error_count <= 3:
                    self._log(f"Task {p.name}: Invalid argument (reparse point/junction)")
            except Exception as exc:
                error_count += 1
                if error_count <= 3:
                    self._warn(f"Task {p.name}: {exc}")

        if error_count > 0:
            self._log(
                f"Scheduled tasks: {error_count} files inaccessible (reparse points common in System32\\Tasks)"
            )

    def _mft_from(self, root: Path) -> None:
        """Copy $MFT directly from the NTFS mount point root."""
        print("  [*] Master File Table ($MFT)")
        mft = root / "$MFT"
        if not mft.exists():
            self._warn("$MFT not found - requires raw volume access (\\\\.\\C:) in dead-box mode")
            return
        try:
            if mft.stat().st_size == 0:
                return
            tmp = self.staging / "mft_$MFT"
            if self._stage_file(mft, tmp):
                self._add(tmp, "mft/C_$MFT")
            else:
                self._warn("$MFT copy failed - file may be locked or requires raw volume handle")
        except PermissionError:
            self._warn(
                "$MFT: Permission denied - run as Administrator or use raw device mode (--disk)"
            )
        except OSError as exc:
            if exc.errno == 22:
                self._warn(
                    "$MFT: Invalid argument - NTFS metadata inaccessible in directory mount mode"
                )
            else:
                self._warn(f"$MFT: OSError - {exc}")
        except Exception as exc:
            self._warn(f"$MFT: Error - {exc}")

    def _pe_from(self, win_dir: Path, users_dir: Path) -> None:
        print("  [*] PE / Executable Binaries")
        PE_EXTS = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".msi", ".hta"}
        MAX_FILE = 200 * 1024 * 1024
        MAX_FILES = 1000
        dirs: list = [win_dir / "Temp"]
        if users_dir.exists():
            for ud in sorted(users_dir.iterdir()):
                if not ud.is_dir():
                    continue
                for rel in [
                    "AppData/Local/Temp",
                    "AppData/Roaming",
                    "Downloads",
                    "Desktop",
                    "AppData/Local/Microsoft/Windows/INetCache",
                ]:
                    dirs.append(ud / Path(rel.replace("/", os.sep)))
        count = 0
        total = 0
        for d in dirs:
            if not d.exists():
                continue
            for p in sorted(d.rglob("*")):
                if count >= MAX_FILES or total >= 2 * 1024**3:
                    break
                if not p.is_file() or p.suffix.lower() not in PE_EXTS:
                    continue
                sz = p.stat().st_size
                if sz == 0 or sz > MAX_FILE:
                    continue
                if self._add(p, f"pe/{d.name}/{p.name}"):
                    count += 1
                    total += sz

    def _documents_from(self, users_dir: Path) -> None:
        print("  [*] Office Documents & PDFs")
        DOC_EXTS = {
            ".doc",
            ".docx",
            ".docm",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".rtf",
            ".pdf",
            ".odt",
            ".ods",
        }
        MAX_FILE = 100 * 1024 * 1024
        MAX_FILES = 500
        count = 0
        for ud in sorted(users_dir.iterdir()) if users_dir.exists() else []:
            if not ud.is_dir():
                continue
            for rel in ["Documents", "Downloads", "Desktop"]:
                d = ud / rel
                if not d.exists():
                    continue
                for p in sorted(d.rglob("*")):
                    if count >= MAX_FILES:
                        break
                    if not p.is_file() or p.suffix.lower() not in DOC_EXTS:
                        continue
                    if p.stat().st_size == 0 or p.stat().st_size > MAX_FILE:
                        continue
                    if self._add(p, f"documents/{ud.name}/{rel}/{p.name}"):
                        count += 1

    # ── ForensicHarvester category methods ────────────────────────────────────

    _USER_SKIP = {"Default", "Default User", "Public", "All Users"}

    def _iter_users(self, users_dir: Path):
        """Yield user subdirectories, skipping built-in system accounts."""
        if not users_dir.exists():
            return
        for d in sorted(users_dir.iterdir()):
            if d.is_dir() and d.name not in self._USER_SKIP:
                yield d

    def _execution_from(self, win_dir: Path) -> None:
        print("  [*] Execution Evidence (SRUM, Amcache, Prefetch)")
        for src, arcname in [
            (win_dir / "System32" / "sru" / "SRUDB.dat", "execution/SRUDB.dat"),
            (win_dir / "AppCompat" / "Programs" / "Amcache.hve", "execution/Amcache.hve"),
            (win_dir / "System32" / "Amcache.hve", "execution/Amcache.hve"),
        ]:
            if src.is_file():
                tmp = self.staging / f"exec_{src.name}"
                if self._stage_file(src, tmp):
                    self._add(tmp, arcname)
        pf = win_dir / "Prefetch"
        count = 0
        for p in sorted(pf.glob("*.pf")) if pf.exists() else []:
            if count >= 500:
                break
            if self._add(p, f"execution/prefetch/{p.name}"):
                count += 1

    def _persistence_from(self, win_dir: Path) -> None:
        print("  [*] Persistence (Tasks, WMI)")
        for tasks_dir in [win_dir / "System32" / "Tasks", win_dir / "SysWOW64" / "Tasks"]:
            count = 0
            try:
                task_files = list(tasks_dir.rglob("*")) if tasks_dir.exists() else []
            except Exception as exc:
                self._warn(f"Persistence tasks scan ({tasks_dir.name}): {exc}")
                continue
            for p in task_files:
                if count >= 500:
                    break
                try:
                    if p.is_file() and not p.suffix:
                        rel = str(p.relative_to(tasks_dir)).replace("\\", "/")
                        if self._add(p, f"persistence/tasks/{tasks_dir.name}/{rel}"):
                            count += 1
                except Exception as exc:
                    self._warn(f"Persistence task {p.name}: {exc}")
        wmi_repo = win_dir / "System32" / "wbem" / "Repository"
        for fname, arcname in [
            ("OBJECTS.DATA", "persistence/wmi/OBJECTS.DATA"),
            ("INDEX.BTR", "persistence/wmi/INDEX.BTR"),
        ]:
            src = wmi_repo / fname
            if not src.is_file():
                continue
            tmp = self.staging / f"wmi_{fname}"
            try:
                if self._stage_file(src, tmp):
                    self._add(tmp, arcname)
            except Exception as exc:
                self._warn(f"WMI {fname}: {exc}")

    def _network_cfg_from(self, root: Path, win_dir: Path) -> None:
        print("  [*] Network Config (Hosts, WLAN, Firewall)")
        self._add(win_dir / "System32" / "drivers" / "etc" / "hosts", "network_cfg/hosts")
        self._add(
            win_dir / "System32" / "LogFiles" / "Firewall" / "pfirewall.log",
            "network_cfg/pfirewall.log",
        )
        wlan = root / "ProgramData" / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces"
        if wlan.exists():
            for p in wlan.rglob("*.xml"):
                self._add(p, f"network_cfg/wlan/{p.parent.name}/{p.name}")

    def _usb_devices_from(self, win_dir: Path) -> None:
        print("  [*] USB Device History")
        inf = win_dir / "INF"
        self._add(inf / "setupapi.dev.log", "usb_devices/setupapi.dev.log")
        self._add(inf / "setupapi.setup.log", "usb_devices/setupapi.setup.log")

    def _credentials_from(self, win_dir: Path, users_dir: Path) -> None:
        print("  [*] Credentials (DPAPI, Credential Manager)")
        cfg = win_dir / "System32" / "config"
        for hive in ["SAM", "SECURITY"]:
            src = cfg / hive
            if not src.is_file():
                continue
            tmp = self.staging / f"cred_{hive}"
            try:
                if self._stage_file(src, tmp):
                    self._add(tmp, f"credentials/{hive}")
            except Exception as exc:
                self._warn(f"Credentials {hive}: {exc}")
        for ud in self._iter_users(users_dir):
            for rel in [
                "AppData/Local/Microsoft/Credentials",
                "AppData/Roaming/Microsoft/Credentials",
                "AppData/Local/Microsoft/Protect",
            ]:
                d = ud / Path(rel.replace("/", os.sep))
                try:
                    items = list(d.rglob("*")) if d.exists() else []
                except Exception:
                    continue
                for p in items:
                    try:
                        if p.is_file():
                            self._add(p, f"credentials/{ud.name}/{rel.split('/')[-1]}/{p.name}")
                    except Exception:
                        pass

    def _antivirus_from(self, root: Path) -> None:
        # Defender + Trend Micro + 14 other AV/EDR vendors — see Collector._WIN_AV_DIRS
        self._antivirus_windows(root)

    def _sysmon_from(self, root: Path, win_dir: Path) -> None:
        self._sysmon_windows(root, win_dir)

    def _wer_crashes_from(self, root: Path) -> None:
        print("  [*] WER Crash Dumps & Reports")
        base = root / "ProgramData" / "Microsoft" / "Windows" / "WER"
        count = 0
        for sub in ["ReportQueue", "ReportArchive"]:
            d = base / sub
            try:
                items = list(d.rglob("*")) if d.exists() else []
            except Exception as exc:
                self._warn(f"WER {sub}: {exc}")
                continue
            for p in items:
                if count >= 200:
                    break
                try:
                    if p.is_file():
                        if self._add(p, f"wer_crashes/{sub}/{p.name}"):
                            count += 1
                except Exception:
                    pass

    def _win_logs_from(self, win_dir: Path) -> None:
        print("  [*] Windows Logs (CBS, DISM, WU)")
        self._add(win_dir / "Logs" / "CBS" / "CBS.log", "win_logs/CBS.log")
        self._add(win_dir / "Logs" / "DISM" / "dism.log", "win_logs/dism.log")
        self._add(win_dir / "WindowsUpdate.log", "win_logs/WindowsUpdate.log")
        panther = win_dir / "Panther"
        if panther.exists():
            for p in panther.glob("*.log"):
                self._add(p, f"win_logs/panther/{p.name}")

    def _filesystem_from(self, root: Path) -> None:
        print("  [*] NTFS Metadata ($MFT, $LogFile, $Boot)")
        for name in ["$MFT", "$LogFile", "$Boot"]:
            src = root / name
            if not src.exists():
                self._warn(
                    f"NTFS metadata {name} not accessible in directory mount mode - requires raw volume handle (\\\\.\\C:)"
                )
                continue
            try:
                if src.stat().st_size == 0:
                    continue
                tmp = self.staging / f"fs_{name.replace('$', '')}"
                if self._stage_file(src, tmp):
                    self._add(tmp, f"filesystem/{name}")
            except PermissionError:
                self._warn(
                    f"Permission denied reading {name} - requires Administrator or raw volume access"
                )
            except OSError as exc:
                if exc.errno == 22:
                    self._warn(
                        f"Invalid argument reading {name} - file system limitation in directory mount mode"
                    )
                else:
                    self._warn(f"Error reading {name}: {exc}")
            except Exception as exc:
                self._warn(f"Error reading {name}: {exc}")

    def _boot_uefi_from(self, win_dir: Path) -> None:
        print("  [*] Boot Config (BCD, EFI)")
        cfg = win_dir / "System32" / "config"
        self._add(cfg / "BCD", "boot_uefi/BCD")
        self._add(win_dir / "bootstat.dat", "boot_uefi/bootstat.dat")

    def _encryption_from(self, win_dir: Path) -> None:
        print("  [*] Encryption Metadata (BitLocker / EFS)")
        self._add(win_dir / "System32" / "FVE" / "BDE-Recovery.txt", "encryption/BDE-Recovery.txt")

    def _etw_diagnostics_from(self, win_dir: Path) -> None:
        print("  [*] ETW Diagnostic Traces")
        d = win_dir / "System32" / "LogFiles" / "WMI"
        count = 0
        for p in d.glob("*.etl") if d.exists() else []:
            if count >= 50:
                break
            if self._add(p, f"etw_diagnostics/{p.name}"):
                count += 1

    def _browser_chrome_from(self, users_dir: Path) -> None:
        print("  [*] Chrome Browser Artifacts")
        FILES = ["History", "Cookies", "Web Data", "Login Data", "Bookmarks"]
        for ud in self._iter_users(users_dir):
            profile = ud / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
            for f in FILES:
                self._add(profile / f, f"browser_chrome/{ud.name}/{f}")

    def _browser_edge_from(self, users_dir: Path) -> None:
        print("  [*] Edge Browser Artifacts")
        FILES = ["History", "Cookies", "Web Data", "Login Data"]
        for ud in self._iter_users(users_dir):
            profile = ud / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default"
            for f in FILES:
                self._add(profile / f, f"browser_edge/{ud.name}/{f}")

    def _browser_ie_from(self, users_dir: Path) -> None:
        print("  [*] Internet Explorer WebCache")
        FILES = ["WebCacheV01.dat", "WebCacheV24.dat"]
        for ud in self._iter_users(users_dir):
            wc = ud / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache"
            for f in FILES:
                self._add(wc / f, f"browser_ie/{ud.name}/{f}")

    def _email_outlook_from(self, users_dir: Path) -> None:
        print("  [*] Outlook Email (.pst / .ost)")
        count = 0
        for ud in self._iter_users(users_dir):
            for rel in ["Documents/Outlook Files", "AppData/Local/Microsoft/Outlook"]:
                d = ud / Path(rel.replace("/", os.sep))
                for p in d.rglob("*.pst") if d.exists() else []:
                    if self._add(p, f"email_outlook/{ud.name}/{p.name}"):
                        count += 1
                for p in d.rglob("*.ost") if d.exists() else []:
                    if self._add(p, f"email_outlook/{ud.name}/{p.name}"):
                        count += 1

    def _email_thunderbird_from(self, users_dir: Path) -> None:
        print("  [*] Thunderbird Email")
        for ud in self._iter_users(users_dir):
            tb = ud / "AppData" / "Roaming" / "Thunderbird" / "Profiles"
            if tb.exists():
                for prof in tb.iterdir():
                    if prof.is_dir():
                        for p in prof.rglob("*.sqlite"):
                            self._add(p, f"email_thunderbird/{ud.name}/{prof.name}/{p.name}")
                        for p in prof.rglob("*.msf"):
                            self._add(p, f"email_thunderbird/{ud.name}/{prof.name}/{p.name}")

    def _teams_from(self, users_dir: Path) -> None:
        print("  [*] Microsoft Teams")
        PATHS = [
            "AppData/Roaming/Microsoft/Teams/logs.txt",
            "AppData/Roaming/Microsoft/Teams/IndexedDB",
            "AppData/Roaming/Microsoft/Teams/Local Storage",
        ]
        for ud in self._iter_users(users_dir):
            for rel in PATHS:
                p = ud / Path(rel.replace("/", os.sep))
                if p.is_file():
                    self._add(p, f"teams/{ud.name}/{p.name}")
                elif p.is_dir():
                    for f in p.rglob("*"):
                        if f.is_file():
                            self._add(f, f"teams/{ud.name}/{p.name}/{f.name}")

    def _slack_from(self, users_dir: Path) -> None:
        print("  [*] Slack")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Roaming" / "Slack" / "logs"
            if d.exists():
                for p in d.rglob("*.log"):
                    self._add(p, f"slack/{ud.name}/{p.name}")

    def _discord_from(self, users_dir: Path) -> None:
        print("  [*] Discord")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Roaming" / "discord" / "Local Storage"
            if d.exists():
                for p in d.rglob("*"):
                    if p.is_file():
                        self._add(p, f"discord/{ud.name}/{p.name}")

    def _signal_from(self, users_dir: Path) -> None:
        print("  [*] Signal Desktop")
        for ud in self._iter_users(users_dir):
            db = ud / "AppData" / "Roaming" / "Signal" / "databases" / "db.sqlite"
            self._add(db, f"signal/{ud.name}/db.sqlite")

    def _whatsapp_from(self, users_dir: Path) -> None:
        print("  [*] WhatsApp Desktop")
        for ud in self._iter_users(users_dir):
            base = ud / "AppData" / "Local" / "Packages"
            if base.exists():
                for pkg in base.iterdir():
                    if pkg.is_dir() and "WhatsApp" in pkg.name:
                        for p in pkg.rglob("*.db"):
                            self._add(p, f"whatsapp/{ud.name}/{p.name}")

    def _telegram_from(self, users_dir: Path) -> None:
        print("  [*] Telegram Desktop")
        for ud in self._iter_users(users_dir):
            tdata = ud / "AppData" / "Roaming" / "Telegram Desktop" / "tdata"
            if tdata.exists():
                for p in tdata.iterdir():
                    if p.is_file() and p.suffix not in {".db"}:
                        self._add(p, f"telegram/{ud.name}/{p.name}")

    def _cloud_onedrive_from(self, users_dir: Path) -> None:
        print("  [*] OneDrive Sync Artifacts")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Local" / "Microsoft" / "OneDrive"
            if d.exists():
                for p in d.rglob("*.db"):
                    self._add(p, f"cloud_onedrive/{ud.name}/{p.name}")
                for p in d.rglob("*.log"):
                    self._add(p, f"cloud_onedrive/{ud.name}/{p.name}")

    def _cloud_google_drive_from(self, users_dir: Path) -> None:
        print("  [*] Google Drive Sync Artifacts")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Local" / "Google" / "DriveFS"
            if d.exists():
                for p in d.rglob("*.db"):
                    self._add(p, f"cloud_google_drive/{ud.name}/{p.name}")

    def _cloud_dropbox_from(self, users_dir: Path) -> None:
        print("  [*] Dropbox Sync Artifacts")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Local" / "Dropbox"
            if d.exists():
                for p in d.rglob("*.db"):
                    self._add(p, f"cloud_dropbox/{ud.name}/{p.name}")
                for p in d.rglob("*.json"):
                    self._add(p, f"cloud_dropbox/{ud.name}/{p.name}")

    def _remote_access_from(self, root: Path, users_dir: Path) -> None:
        print("  [*] Remote Access (AnyDesk, TeamViewer)")
        tv_logs = root / "ProgramData" / "TeamViewer" / "Logs"
        if tv_logs.exists():
            for p in tv_logs.glob("*.log"):
                self._add(p, f"remote_access/teamviewer/{p.name}")
        for ud in self._iter_users(users_dir):
            ad = ud / "AppData" / "Roaming" / "AnyDesk"
            if ad.exists():
                for p in ad.rglob("*.trace"):
                    self._add(p, f"remote_access/anydesk/{ud.name}/{p.name}")
                for p in ad.rglob("*.conf"):
                    self._add(p, f"remote_access/anydesk/{ud.name}/{p.name}")

    def _rdp_from(self, users_dir: Path) -> None:
        print("  [*] RDP / Terminal Services")
        for ud in self._iter_users(users_dir):
            cache = ud / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache"
            if cache.exists():
                for p in cache.rglob("*"):
                    if p.is_file():
                        self._add(p, f"rdp/{ud.name}/{p.name}")

    def _ssh_ftp_from(self, users_dir: Path) -> None:
        print("  [*] SSH / FTP Clients (PuTTY, WinSCP)")
        for ud in self._iter_users(users_dir):
            ssh = ud / ".ssh"
            if ssh.exists():
                for p in ssh.iterdir():
                    if p.is_file() and "id_" not in p.name:  # skip private keys
                        self._add(p, f"ssh_ftp/{ud.name}/ssh/{p.name}")
            putty = ud / "AppData" / "Roaming" / "PuTTY"
            if putty.exists():
                for p in putty.rglob("*"):
                    if p.is_file():
                        self._add(p, f"ssh_ftp/{ud.name}/putty/{p.name}")
            winscp = ud / "AppData" / "Roaming" / "WinSCP.ini"
            self._add(winscp, f"ssh_ftp/{ud.name}/WinSCP.ini")

    def _office_from(self, users_dir: Path) -> None:
        print("  [*] Office MRU / Trusted Documents")
        for ud in self._iter_users(users_dir):
            d = ud / "AppData" / "Roaming" / "Microsoft" / "Office"
            if d.exists():
                for p in d.rglob("*.json"):
                    self._add(p, f"office/{ud.name}/{p.name}")
                for p in d.rglob("Recent"):
                    if p.is_dir():
                        for f in p.iterdir():
                            if f.is_file():
                                self._add(f, f"office/{ud.name}/Recent/{f.name}")

    def _iis_web_from(self, root: Path) -> None:
        print("  [*] IIS Web Server Logs")
        d = root / "inetpub" / "logs" / "LogFiles"
        count = 0
        for p in d.rglob("*.log") if d.exists() else []:
            if count >= 200:
                break
            if self._add(p, f"iis_web/{p.parent.name}/{p.name}"):
                count += 1
        self._add(
            root / "Windows" / "System32" / "inetsrv" / "config" / "applicationHost.config",
            "iis_web/applicationHost.config",
        )

    def _active_directory_from(self, win_dir: Path) -> None:
        print("  [*] Active Directory (NTDS.dit, SYSVOL)")
        ntds = win_dir / "NTDS"
        self._add(ntds / "ntds.dit", "active_directory/ntds.dit")
        self._add(ntds / "edb.log", "active_directory/edb.log")

    def _dev_tools_from(self, users_dir: Path) -> None:
        print("  [*] Dev Tools (.gitconfig, PS history, .aws)")
        for ud in self._iter_users(users_dir):
            self._add(ud / ".gitconfig", f"dev_tools/{ud.name}/.gitconfig")
            self._add(ud / ".git-credentials", f"dev_tools/{ud.name}/.git-credentials")
            ps_hist = (
                ud
                / "AppData"
                / "Roaming"
                / "Microsoft"
                / "Windows"
                / "PowerShell"
                / "PSReadLine"
                / "ConsoleHost_history.txt"
            )
            self._add(ps_hist, f"dev_tools/{ud.name}/ConsoleHost_history.txt")
            aws = ud / ".aws" / "credentials"
            self._add(aws, f"dev_tools/{ud.name}/aws_credentials")
            azure = ud / ".azure" / "accessTokens.json"
            self._add(azure, f"dev_tools/{ud.name}/azure_accessTokens.json")

    def _password_managers_from(self, users_dir: Path) -> None:
        print("  [*] Password Managers (KeePass)")
        count = 0
        for ud in self._iter_users(users_dir):
            for p in ud.rglob("*.kdbx"):
                if count >= 20:
                    break
                if self._add(p, f"password_managers/{ud.name}/{p.name}"):
                    count += 1

    def _vpn_from(self, root: Path) -> None:
        print("  [*] VPN Config (OpenVPN, WireGuard)")
        openvpn = root / "ProgramData" / "OpenVPN" / "config"
        if openvpn.exists():
            for p in openvpn.rglob("*.ovpn"):
                self._add(p, f"vpn/openvpn/{p.name}")
        wg = root / "ProgramData" / "WireGuard"
        if wg.exists():
            for p in wg.rglob("*.conf"):
                self._add(p, f"vpn/wireguard/{p.name}")

    def _windows_apps_from(self, users_dir: Path) -> None:
        print("  [*] Windows UWP / Modern Apps")
        APPS = ["Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"]
        for ud in self._iter_users(users_dir):
            pkg_base = ud / "AppData" / "Local" / "Packages"
            for app in APPS:
                d = pkg_base / app
                if d.exists():
                    for p in d.rglob("*.sqlite"):
                        self._add(p, f"windows_apps/{ud.name}/{app}/{p.name}")

    def _wsl_from(self, users_dir: Path) -> None:
        print("  [*] WSL Filesystem & Config")
        for ud in self._iter_users(users_dir):
            pkg_base = ud / "AppData" / "Local" / "Packages"
            if pkg_base.exists():
                for pkg in pkg_base.iterdir():
                    if pkg.is_dir() and "CanonicalGroupLimited" in pkg.name:
                        cfg = pkg / "LocalState" / "rootfs" / "etc"
                        if cfg.exists():
                            for p in ["passwd", "shadow", "bash.bashrc"]:
                                self._add(cfg / p, f"wsl/{ud.name}/{p}")

    def _virtualization_from(self, root: Path) -> None:
        print("  [*] Virtualization (Hyper-V, Docker)")
        hv = root / "ProgramData" / "Microsoft" / "Windows" / "Hyper-V"
        if hv.exists():
            for p in hv.rglob("*.vhd"):
                self._add(p, f"virtualization/hyperv/{p.name}")
            for p in hv.rglob("*.vhdx"):
                self._add(p, f"virtualization/hyperv/{p.name}")

    def _recovery_from(self, root: Path) -> None:
        print("  [*] Recovery (VSS, Windows.old)")
        svi = root / "System Volume Information"
        if svi.exists():
            for p in svi.iterdir():
                if p.is_file():
                    self._add(p, f"recovery/svi/{p.name}")

    def _database_clients_from(self, users_dir: Path) -> None:
        print("  [*] Database Clients (SSMS, DBeaver)")
        for ud in self._iter_users(users_dir):
            for rel in [
                "AppData/Roaming/Microsoft SQL Server Management Studio",
                "AppData/Roaming/DBeaverData",
            ]:
                d = ud / Path(rel.replace("/", os.sep))
                if d.exists():
                    for p in d.rglob("*.xml"):
                        self._add(p, f"database_clients/{ud.name}/{rel.split('/')[-1]}/{p.name}")
                    for p in d.rglob("*.ini"):
                        self._add(p, f"database_clients/{ud.name}/{rel.split('/')[-1]}/{p.name}")

    def _gaming_from(self, root: Path, users_dir: Path) -> None:
        print("  [*] Gaming Platforms (Steam, Epic)")
        epic = root / "ProgramData" / "Epic" / "EpicGamesLauncher" / "Data" / "Logs"
        if epic.exists():
            for p in epic.glob("*.log"):
                self._add(p, f"gaming/epic/{p.name}")
        for ud in self._iter_users(users_dir):
            steam = ud / "AppData" / "Local" / "Steam"
            if steam.exists():
                for p in steam.rglob("*.vdf"):
                    self._add(p, f"gaming/steam/{ud.name}/{p.name}")

    def _printing_from(self, win_dir: Path) -> None:
        print("  [*] Print Spool Files")
        spool = win_dir / "System32" / "spool" / "PRINTERS"
        count = 0
        for p in spool.iterdir() if spool.exists() else []:
            if count >= 100:
                break
            if p.is_file() and self._add(p, f"printing/{p.name}"):
                count += 1

    def _memory_artifacts_from(self, root: Path) -> None:
        print("  [*] Memory Artifacts (pagefile, hiberfil)")
        for name in ["pagefile.sys", "hiberfil.sys", "swapfile.sys"]:
            self._add(root / name, f"memory_artifacts/{name}")


# ─────────────────────────────────────────────────────────────────────────────
# Upload helper
# ─────────────────────────────────────────────────────────────────────────────


def upload_via_presigned(zip_path: Path, presigned_url: str) -> None:
    """HTTP PUT to a pre-signed S3/MinIO URL — no credentials needed at runtime."""
    import ssl
    import urllib.error
    import urllib.request

    print(f"\n  [*] Uploading {zip_path.name} → S3 (presigned URL)")

    with open(zip_path, "rb") as fh:
        file_data = fh.read()

    req = urllib.request.Request(
        presigned_url,
        data=file_data,
        headers={"Content-Type": "application/zip"},
        method="PUT",
    )
    # MinIO is typically deployed with a self-signed cert on internal networks.
    _ssl_ctx = ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=600, context=_ssl_ctx) as resp:
            print(f"  [+] Upload successful  (HTTP {resp.status})")
    except urllib.error.HTTPError as exc:
        body_preview = exc.read(256).decode(errors="replace")
        print(f"  [!] Upload failed: HTTP {exc.code} — {body_preview}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"  [!] Upload error: {exc}", file=sys.stderr)
        sys.exit(1)


def upload_log_via_presigned(log_path: Path, presigned_url: str) -> bool:
    """Best-effort PUT of the execution log to its own presigned S3 object.
    Returns True on success. Never raises — log upload must not mask the real
    collection outcome or crash the finally block."""
    import ssl
    import urllib.error
    import urllib.request

    if not log_path or not log_path.exists():
        return False
    try:
        data = log_path.read_bytes()
    except Exception as exc:
        print(f"  [!] Could not read execution log for upload: {exc}", file=sys.stderr)
        return False

    print(f"  [*] Uploading execution log {log_path.name} → S3")
    req = urllib.request.Request(
        presigned_url,
        data=data,
        headers={"Content-Type": "text/plain; charset=utf-8"},
        method="PUT",
    )
    _ssl_ctx = ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=120, context=_ssl_ctx) as resp:
            print(f"  [+] Execution log uploaded  (HTTP {resp.status})")
            return True
    except Exception as exc:
        print(f"  [!] Execution-log upload failed: {exc}", file=sys.stderr)
        return False


def upload_to_fo(zip_path: Path, api_url: str, case_id: str, api_token: str = "") -> None:
    import urllib.error
    import urllib.request

    url = f"{api_url.rstrip('/')}/cases/{case_id}/ingest"
    boundary = f"fo_boundary_{TS_NOW}"

    print(f"\n  [*] Uploading {zip_path.name} → {url}")

    with open(zip_path, "rb") as fh:
        file_data = fh.read()

    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files"; filename="{zip_path.name}"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode()
        + file_data
        + f"\r\n--{boundary}--\r\n".encode()
    )

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            print(f"  [+] Upload successful  (HTTP {resp.status})")
    except urllib.error.HTTPError as exc:
        body_preview = exc.read(256).decode(errors="replace")
        if exc.code == 401:
            print(
                "  [!] Upload failed: HTTP 401 Unauthorized — "
                "pass --api-token <your JWT token> or embed it at download time.",
                file=sys.stderr,
            )
        else:
            print(f"  [!] Upload failed: HTTP {exc.code} — {body_preview}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"  [!] Upload error: {exc}", file=sys.stderr)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fo-harvester",
        description="ForensicsOperator Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Full path for the output ZIP (overrides config.json output_dir)",
    )
    parser.add_argument("--api-url", type=str, default=None)
    parser.add_argument("--case-id", type=str, default=None)
    parser.add_argument("--api-token", type=str, default=None)
    parser.add_argument(
        "--collect",
        type=str,
        default=None,
        help="Override categories: comma-separated keys (e.g. evtx,registry)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--skip-problematic",
        action="store_true",
        help="Skip artifact categories known to fail in dead-box directory mode",
    )
    parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Already-mounted Windows filesystem root (e.g. /mnt/evidence or E:\\)",
    )
    parser.add_argument(
        "--disk",
        type=str,
        default=None,
        help="Raw block device to mount — Linux only (requires ntfs-3g / dislocker)",
    )
    parser.add_argument(
        "--bitlocker-key",
        type=str,
        default=None,
        dest="bitlocker_key",
        help="BitLocker recovery key — stays local, never stored in config.json",
    )
    parser.add_argument(
        "--fetch",
        action="append",
        default=None,
        metavar="PATTERN",
        help="Fetch files by name, glob, or regex (re:...). Repeatable, "
        "comma-separated. e.g. --fetch 'mimikatz*' --fetch 're:\\.(ps1|hta)$'",
    )
    parser.add_argument(
        "--fetch-root",
        action="append",
        default=None,
        dest="fetch_roots",
        metavar="DIR",
        help="Restrict --fetch sweep to these directories (repeatable)",
    )
    parser.add_argument(
        "--fetch-max-files",
        type=int,
        default=None,
        help="Max files fetched by --fetch (default 200)",
    )
    parser.add_argument(
        "--fetch-max-mb",
        type=int,
        default=None,
        help="Max size per fetched file in MB (default 100)",
    )
    parser.add_argument(
        "--bundle-manifest",
        type=Path,
        default=None,
        metavar="PATH",
        help="Also write a Citadel bundle manifest.json (contract: "
        "bundle_manifest.schema.json) describing the collected artifacts",
    )
    args = parser.parse_args()

    t_start = time.monotonic()

    # Merge: config.json (EMBEDDED_CONFIG) < CLI args (CLI always wins)
    cfg = {**EMBEDDED_CONFIG}
    if args.api_url:
        cfg["api_url"] = args.api_url
    if args.case_id:
        cfg["case_id"] = args.case_id
    if args.api_token:
        cfg["api_token"] = args.api_token
    if args.collect:
        cfg["collect"] = args.collect.split(",")
    if args.path:
        cfg["path"] = args.path
    if args.disk:
        cfg["disk"] = args.disk
    if args.skip_problematic:
        cfg["skip_problematic"] = True
    if args.verbose:
        cfg["verbose"] = True
    if args.fetch:
        cfg["fetch_patterns"] = [p for chunk in args.fetch for p in chunk.split(",") if p.strip()]
    if args.fetch_roots:
        cfg["fetch_roots"] = list(args.fetch_roots)
    if args.fetch_max_files:
        cfg["fetch_max_files"] = args.fetch_max_files
    if args.fetch_max_mb:
        cfg["fetch_max_mb"] = args.fetch_max_mb

    fetch_kwargs = {
        "fetch_patterns": cfg.get("fetch_patterns") or [],
        "fetch_roots": cfg.get("fetch_roots") or [],
    }
    if cfg.get("fetch_max_files"):
        fetch_kwargs["fetch_max_files"] = int(cfg["fetch_max_files"])
    if cfg.get("fetch_max_mb"):
        fetch_kwargs["fetch_max_mb"] = int(cfg["fetch_max_mb"])

    api_url = cfg.get("api_url", "")
    case_id = cfg.get("case_id", "")
    api_token = cfg.get("api_token", "")
    presigned_url = cfg.get("presigned_url", "")
    presigned_log_url = cfg.get("presigned_log_url", "")
    case_name = cfg.get("case_name", "") or ""

    # Build output path — case_name, hostname, date, OS type in filename
    if args.output:
        output = Path(args.output)
    else:
        out_dir = Path(cfg.get("output_dir", "./output"))
        os_type = platform.system()
        if os_type == "Darwin":
            os_type = "macOS"
        # Dead-box mode: we can't auto-detect target OS
        if cfg.get("path") or cfg.get("disk") or args.path if hasattr(args, "path") else False:
            os_type = "deadbox"
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        name_parts = ["fo-artifacts"]
        if case_name:
            name_parts.append(re.sub(r"[^\w]", "_", case_name)[:40])
        name_parts += [HOSTNAME, date_str, os_type]
        filename = "-".join(name_parts) + ".zip"
        output = out_dir / filename

    # Tee everything to <output>.collector.log from here on, and arrange for a
    # SIGTERM/SIGINT/OOM-kill to unwind cleanly so the log still gets uploaded.
    log_path = _setup_execution_log(output)
    _install_signal_handlers()

    # Input source — config.json defaults, CLI overrides.
    path_arg = cfg.get("path", "") or ""
    disk = cfg.get("disk", "") or ""
    bitlocker_key = args.bitlocker_key or cfg.get("bitlocker_key", "") or ""
    skip_problematic = cfg.get("skip_problematic", False)

    # Live Windows: use ExternalDiskCollector(C:\) to get all 52 _from() methods
    _live_windows = IS_WINDOWS and not path_arg and not disk
    if _live_windows:
        path_arg = os.environ.get("SystemDrive", "C:") + "\\"

    # Collect set
    raw_collect = cfg.get("collect", [])
    if raw_collect:
        collect_set = set(raw_collect)
    elif path_arg or disk:
        collect_set = ExternalDiskCollector.DEFAULT_COLLECT
    elif IS_WINDOWS:
        collect_set = DEFAULT_WINDOWS
    elif IS_MACOS:
        collect_set = DEFAULT_MACOS
    else:
        collect_set = DEFAULT_LINUX

    # --fetch implies the file_search category (copy: never mutate the defaults)
    if fetch_kwargs["fetch_patterns"]:
        collect_set = set(collect_set) | {"file_search"}

    # ── Header ───────────────────────────────────────────────────────────────
    print(BANNER)
    print(f"  Host      : {HOSTNAME}")
    print(f"  OS        : {platform.system()} {platform.release()} {platform.machine()}")
    if case_name:
        print(f"  Case      : {case_name}")
    print(f"  Output    : {output}")
    if presigned_url:
        print("  Upload    : S3 presigned URL")
    elif api_url and case_id:
        print(f"  Upload    : {api_url}  →  case {case_id}")
    print(f"  Categories: {len(collect_set)}")
    if _live_windows:
        print(f"  Mode      : live Windows  ({path_arg})")
    elif path_arg:
        print(f"  Mode      : dead-box directory  ({path_arg})")
    elif disk:
        print(f"  Mode      : dead-box raw device  ({disk})")
    else:
        print(f"  Mode      : live {platform.system()}")
    if bitlocker_key:
        print(f"  BitLocker : key provided ({len(bitlocker_key)} chars)")

    # ── Collection ───────────────────────────────────────────────────────────
    print(f"\n{_HR}")
    print("  Collecting forensic artifacts")
    print(f"{_HR}\n")

    # Check for dead-box limitations and warn user
    if path_arg or disk:
        temp_coll = Collector.__new__(Collector)
        temp_coll.collect = collect_set
        temp_coll.verbose = args.verbose
        limitations = temp_coll._check_deadbox_mode()
        if limitations:
            print("  ⚠  Dead-box directory mode detected")
            print("     The following categories may fail or produce limited results:")
            for cat, reason in limitations.items():
                if skip_problematic and cat in collect_set:
                    print(f"       • {cat:<20} - SKIPPED ({reason[:50]}...)")
                else:
                    print(f"       • {cat:<20} ({reason[:50]}...)")
            print()

            if skip_problematic:
                collect_set = collect_set - set(limitations.keys())
                print(f"     Adjusted collection set: {len(collect_set)} categories\n")

    verbose = cfg.get("verbose", False)
    external_root = path_arg or disk or ""

    if external_root:
        ext_path = Path(external_root)
        if disk and not ext_path.is_dir() and not IS_LINUX:
            print(
                "  Raw block-device collection requires Linux (ntfs-3g + dislocker).",
                file=sys.stderr,
            )
            sys.exit(1)
        # Enable backup privilege before dead-box collection so _stage_file can bypass ACLs
        if IS_WINDOWS and not _enable_backup_privilege():
            print(
                "  [!] SeBackupPrivilege not granted — some ACL-protected files may be skipped.\n"
                "      Run as Administrator for full dead-box collection.",
                file=sys.stderr,
            )
        collector: Collector = ExternalDiskCollector(
            external_root,
            bitlocker_key=bitlocker_key,
            output=output,
            collect=collect_set,
            verbose=verbose,
            dry_run=args.dry_run,
            skip_problematic=skip_problematic,
            **fetch_kwargs,
        )
    elif IS_WINDOWS:
        if not _enable_backup_privilege():
            print(
                "  [!] SeBackupPrivilege not granted — ACL-protected files may be skipped.\n"
                "      Run as Administrator for full dead-box collection.",
                file=sys.stderr,
            )
        collector = WindowsCollector(
            output, collect_set, verbose, args.dry_run, skip_problematic, **fetch_kwargs
        )
    elif IS_MACOS:
        collector = MacOSCollector(
            output, collect_set, verbose, args.dry_run, skip_problematic, **fetch_kwargs
        )
    elif IS_LINUX:
        collector = LinuxCollector(
            output, collect_set, verbose, args.dry_run, skip_problematic, **fetch_kwargs
        )
    else:
        print(f"  Unsupported OS: {platform.system()}", file=sys.stderr)
        sys.exit(1)

    # Everything from collection onward is wrapped so that a crash, an
    # exception, or a SIGTERM/SIGINT (→ _Killed) still runs the finally block:
    # flush the execution log and upload it to S3. The log is the post-mortem
    # when the archive is empty or the process is killed mid-run.
    # Record free space on both volumes before we start writing — a full disk
    # is the usual cause of truncated archives and mid-run kills.
    _log_disk_space(output, collector.staging)

    rc = 0
    try:
        collector.collect_all()
        t_collect = time.monotonic() - t_start

        # ── Dry-run report ─────────────────────────────────────────────────────
        if args.dry_run:
            print(f"\n{_HR}")
            print(f"  Dry run — {len(collector._items)} files would be archived")
            print(_HR)
            for arcname, _ in collector._items:
                print(f"    {arcname}")
            return

        # ── Package ────────────────────────────────────────────────────────────
        collector.package()
        t_total = time.monotonic() - t_start
        n_files = len(collector._items)
        disk_full = getattr(collector, "_disk_full", False)
        if disk_full:
            # Archive is incomplete but may still hold useful artifacts — ship it
            # AND flag it. The execution log records the disk-full event.
            print(
                "\n  [!] Archive is INCOMPLETE — ran out of disk space during packaging.",
                file=sys.stderr,
            )
            rc = 3

        # ── Bundle manifest (opt-in, Citadel contract) ──────────────────────────
        # Routes the legacy collector through the pluggable ArtifactCollector
        # interface to emit a contract-conformant manifest. Off by default so the
        # standalone CLI / ForensicsOperator flow is unchanged.
        if args.bundle_manifest and n_files:
            try:
                from artifact_collector import CollectorAdapter

                adapter = CollectorAdapter(
                    collector,
                    session_id=HOSTNAME
                    + "-"
                    + datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ"),
                )
                adapter.start()
                adapter.finalize()  # legacy already collected/packaged; hash staged items
                written = adapter.write_bundle_manifest(Path(args.bundle_manifest))
                print(f"  Manifest  : {written}")
            except Exception as exc:
                print(f"  [!] bundle manifest failed: {exc}", file=sys.stderr)

        # ── Upload ───────────────────────────────────────────────────────────────
        # Never ship an empty archive. Zero collected files means the ZIP is a
        # ~22-byte stub (end-of-central-directory record only); uploading it just
        # hides the real failure. Skip the archive and let the finally block ship
        # the execution log so the analyst can see *why* nothing was collected.
        if n_files == 0:
            print(
                "\n  [!] No files were collected — refusing to upload an empty archive.",
                file=sys.stderr,
            )
            print(
                "      The execution log will be uploaded instead so the failure is visible.",
                file=sys.stderr,
            )
            rc = 2
        elif presigned_url:
            upload_via_presigned(output, presigned_url)
        elif api_url and case_id:
            upload_to_fo(output, api_url, case_id, api_token=api_token)
        elif api_url or case_id:
            print("  Both --api-url and --case-id are required for upload.", file=sys.stderr)

        # ── Results summary ───────────────────────────────────────────────────────
        results = collector._results
        n_ok = sum(1 for r in results if r["ok"])
        n_fail = len(results) - n_ok
        n_warns = len(collector._errors)

        print(f"\n{_HR}")
        print("  Results")
        print(_HR)
        print()

        if n_files == 0:
            print("  ✗  NOTHING COLLECTED — archive not uploaded (see execution log).")
        elif n_fail == 0:
            print(f"  ✓  All {n_ok} categories collected")
        else:
            print(f"  ✓  {n_ok} categor{'y' if n_ok == 1 else 'ies'} collected")
            print(f"  ✗  {n_fail} categor{'y' if n_fail == 1 else 'ies'} found no files:")
            for r in results:
                if not r["ok"]:
                    hint = f"  ({r['errors'][0][:50]})" if r["errors"] else ""
                    print(f"       · {r['label']}{hint}")

        print()
        print(f"  Files     : {n_files}")
        print(f"  Collection: {t_collect:.1f}s")
        print(f"  Total     : {t_total:.1f}s")

        if n_warns:
            print(f"\n  ⚠  {n_warns} warning(s):")
            for msg in collector._errors[:8]:
                print(f"       · {msg[:72]}")
            if n_warns > 8:
                print(f"       · … and {n_warns - 8} more")

        print(f"\n{_HR}\n")

    except _Killed as exc:
        rc = exc.code if isinstance(exc.code, int) else 143
        print(f"\n  [!] Collection aborted by signal — partial results. Exit {rc}.", file=sys.stderr)
    except BaseException as exc:  # noqa: BLE001 — last-resort: log then propagate intent
        rc = 1
        import traceback

        print(f"\n  [!] FATAL: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
    finally:
        try:
            collector.cleanup()
        except Exception:
            pass
        # Always flush + ship the execution log (success, empty, crash, or kill).
        if not args.dry_run and presigned_log_url and _LOG_PATH:
            upload_log_via_presigned(_LOG_PATH, presigned_log_url)
        elif not args.dry_run and _LOG_PATH:
            print(f"  Execution log: {_LOG_PATH}")
        _close_execution_log()

    sys.exit(rc)


if __name__ == "__main__":
    main()
