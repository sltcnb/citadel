"""
Shared enrichment helpers for forensics plugins.

Provides: SID resolution, registry key classification, trigger formatting,
and service type/start-type decoding.
"""

from __future__ import annotations

import re

# ── Well-known Windows SIDs ──────────────────────────────────────────────────

_WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-5-80-0": "All Services",
    "S-1-16-4096": "Low IL",
    "S-1-16-8192": "Medium IL",
    "S-1-16-12288": "High IL",
    "S-1-16-16384": "System IL",
}


def resolve_sid(sid: str) -> str:
    """Return a human-readable label for a well-known Windows SID, or sid itself."""
    if not sid:
        return ""
    return _WELL_KNOWN_SIDS.get(sid.upper(), sid)


# ── Registry key significance map ────────────────────────────────────────────
# Ordered list of (lowercase_fragment, short_label, artifact_type, mitre_id)
# Checked in order; first match wins.

_REGISTRY_SIGNIFICANCE: list[tuple[str, str, str, str]] = [
    # AutoRun persistence (HKLM/HKCU)
    ("\\currentversion\\run\\", "AutoRun", "persistence", "T1547.001"),
    ("\\currentversion\\runonce\\", "AutoRun Once", "persistence", "T1547.001"),
    ("\\currentversion\\runservices\\", "AutoRun Services", "persistence", "T1547.001"),
    ("\\currentversion\\runservicesonce\\", "AutoRun Svc Once", "persistence", "T1547.001"),
    # Winlogon — Shell / Userinit hijack
    ("\\winlogon", "Winlogon", "persistence", "T1547.004"),
    # Services
    ("\\currentcontrolset\\services\\", "Service", "persistence", "T1543.003"),
    # Image File Execution Options — debugger hijack
    ("\\image file execution options\\", "IFEO", "persistence", "T1546.012"),
    # SilentProcessExit (AppVerifier persistence)
    ("\\silentprocessexit\\", "SilentProcessExit", "persistence", "T1546.012"),
    # AppInit DLLs — loaded into every GUI process
    ("appinit_dlls", "AppInit DLL", "persistence", "T1546.010"),
    # Boot execute
    ("\\session manager\\bootexecute", "Boot Execute", "persistence", "T1542.003"),
    # AppCertDLLs
    ("appcertdlls", "AppCertDLL", "persistence", "T1546.009"),
    # COM servers (potential hijack)
    ("\\inprocserver32", "COM Server", "persistence", "T1546.015"),
    ("\\localserver32", "COM Server", "persistence", "T1546.015"),
    # Shell extensions
    ("\\shellex\\contextmenuhandlers\\", "Shell Extension", "persistence", "T1546"),
    # Command Processor AutoRun (cmd.exe persistence)
    ("\\command processor", "CMD AutoRun", "persistence", "T1059.003"),
    # LSA packages / providers
    ("\\currentcontrolset\\control\\lsa", "LSA Config", "config", "T1556.002"),
    # TCP/IP config (network recon artifact)
    ("tcpip\\parameters", "TCP/IP Config", "config", ""),
    # SAM user accounts
    ("\\sam\\domains\\account\\users", "SAM User", "account", "T1003.002"),
    # Amcache execution evidence
    ("inventoryapplicationfile", "Execution Evidence", "execution", "T1059"),
    ("inventoryapplication", "Installed App", "execution", ""),
    # Recent documents / MRU (user activity)
    ("\\recentdocs", "Recent Doc", "execution", "T1074"),
    ("\\opensavepidlmru", "File Dialog MRU", "execution", "T1074"),
    ("\\lastvisitedpidlmru", "App Open MRU", "execution", "T1074"),
    # Typed URLs (IE/Edge)
    ("typedurls", "Typed URL", "browser", "T1217"),
    # USB storage devices
    ("\\usbstor\\", "USB Device", "execution", "T1091"),
    ("\\enum\\usbstor", "USB Device", "execution", "T1091"),
    # OS version / system info
    ("currentversion\\winlogon", "Winlogon Config", "config", ""),
]


def classify_registry_key(key_path: str) -> tuple[str, str, str]:
    """
    Classify a registry key path.

    Returns (label, artifact_type, mitre_id).
    Returns ("", "registry", "") for unrecognised paths.
    """
    lp = key_path.lower()
    # Append trailing backslash so fragment matches work for both key and value
    if not lp.endswith("\\"):
        lp += "\\"
    for fragment, label, atype, mitre in _REGISTRY_SIGNIFICANCE:
        if fragment in lp:
            return label, atype, mitre
    return "", "registry", ""


# ── Trigger formatting ────────────────────────────────────────────────────────

_TRIGGER_TYPE_MAP: dict[str, str] = {
    "LogonTrigger": "At logon",
    "BootTrigger": "At startup",
    "RegistrationTrigger": "On registration",
    "IdleTrigger": "When idle",
    "TimeTrigger": "One-time",
    "CalendarTrigger": "On schedule",
    "EventTrigger": "On event",
    "SessionStateChangeTrigger": "On session change",
    "WnfStateChangeTrigger": "On WNF state change",
}


def format_trigger(trigger: dict) -> str:
    """Convert a parsed trigger dict to a human-readable string."""
    t = trigger.get("type", "")
    start = trigger.get("start", "")
    interval = trigger.get("repeat_interval", "")

    label = _TRIGGER_TYPE_MAP.get(t, t or "Unknown trigger")
    parts = [label]
    if start:
        try:
            parts.append(f"from {start[:10]}")
        except Exception:
            pass
    if interval:
        s = _format_iso_duration(interval)
        if s:
            parts.append(f"every {s}")
    return ", ".join(parts)


def _format_iso_duration(duration: str) -> str:
    """Convert an ISO 8601 duration string to a compact human label (e.g. PT1H → 1h)."""
    m = re.match(
        r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?",
        duration.upper(),
    )
    if not m:
        return duration
    days, hours, mins, secs = (int(x) if x else 0 for x in m.groups())
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    if secs:
        parts.append(f"{secs}s")
    return "".join(parts)


# ── Service metadata helpers ─────────────────────────────────────────────────

_SERVICE_START_TYPE: dict[str, str] = {
    "0": "Boot",
    "1": "System",
    "2": "Auto",
    "3": "Manual",
    "4": "Disabled",
}
_SERVICE_TYPE: dict[str, str] = {
    "1": "Kernel Driver",
    "2": "File System Driver",
    "16": "Win32 Own Process",
    "32": "Win32 Share Process",
    "256": "Interactive Own Process",
    "272": "Interactive Share Process",
}


def decode_service_start(val: str) -> str:
    return _SERVICE_START_TYPE.get(str(val), val)


def decode_service_type(val: str) -> str:
    return _SERVICE_TYPE.get(str(val), val)
