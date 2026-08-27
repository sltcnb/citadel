"""Closing the loop: turn an analysis gap back into a collection instruction.

The pipeline runs one way. Talon collects, Sluice routes, Babel parses, Pilot
analyses — and when Pilot finds the evidence it needs was never gathered, that
knowledge dies in a report nobody actions. The most common Pilot verdict is
"not enough evidence to reach a decision", and the reason it repeats is that
nothing carries the finding back to the stage that could fix it.

This module is the return path. It maps an artifact type Pilot wanted onto the
Talon collection categories and file paths that would produce it, so a gap
becomes a runnable instruction against a named host instead of a sentence in a
conclusion.

The mapping is per-OS on purpose. "Browser history" is
``~/Library/Safari/History.db`` on macOS, ``AppData/Local/Google/Chrome`` on
Windows and ``~/.mozilla`` on Linux, and a request that does not say which is
not actionable. Where the OS is unknown the request covers all three rather
than guessing, because an over-broad re-collection is recoverable and a wrong
one wastes the only chance to touch the host.

Pure data and pure functions — it emits a request, it does not run anything.
Executing a collection against a production host is an operator's decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# artifact_type -> what produces it, per OS.
#
# `categories` are Talon --collect keys (ARTIFACT_LABELS in tools/talon/
# collect.py). `paths` are --fetch patterns for the cases where a category is
# too coarse and the operator wants exactly one file.
_SOURCES: dict[str, dict] = {
    "browser": {
        "categories": {
            "windows": ("browser", "browser_chrome", "browser_firefox", "browser_edge"),
            "linux": ("browser",),
            "macos": ("browser",),
        },
        "paths": {
            "macos": (
                "~/Library/Safari/History.db",
                "~/Library/Application Support/Google/Chrome/Default/History",
                "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            ),
            "windows": (
                "AppData/Local/Google/Chrome/User Data/Default/History",
                "AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
            ),
            "linux": (
                "~/.mozilla/firefox/*/places.sqlite",
                "~/.config/google-chrome/Default/History",
            ),
        },
        "why": "URL history and download provenance — where a file came from",
    },
    "network_conn": {
        "categories": {"windows": ("triage",), "linux": ("triage",), "macos": ("triage",)},
        "paths": {},
        "why": "live socket table — which process talked to which address",
    },
    "process": {
        "categories": {"windows": ("triage", "sysmon"), "linux": ("triage",), "macos": ("triage",)},
        "paths": {},
        "why": "running process list with command lines and parentage",
    },
    "evtx": {
        "categories": {"windows": ("evtx", "sysmon")},
        "paths": {"windows": ("Windows/System32/winevt/Logs/*.evtx",)},
        "why": "Windows event log — logons, process creation, service installs",
    },
    "prefetch": {
        "categories": {"windows": ("prefetch",)},
        "paths": {"windows": ("Windows/Prefetch/*.pf",)},
        "why": "execution evidence for binaries already deleted",
    },
    "registry": {
        "categories": {"windows": ("registry",)},
        "paths": {"windows": ("Windows/System32/config/*", "Users/*/NTUSER.DAT")},
        "why": "persistence keys, USB history, user configuration",
    },
    "persistence": {
        "categories": {
            "windows": ("persistence", "tasks", "registry"),
            "linux": ("persistence", "cron"),
            "macos": ("launchagents", "plist"),
        },
        "paths": {
            "macos": ("/Library/LaunchDaemons/*.plist", "~/Library/LaunchAgents/*.plist"),
            "linux": ("/etc/systemd/system/*", "/etc/cron*"),
        },
        "why": "what survives a reboot, and its payload",
    },
    "plist": {
        "categories": {"macos": ("plist", "launchagents")},
        "paths": {"macos": ("/Library/Preferences/*.plist", "~/Library/Preferences/*.plist")},
        "why": "macOS configuration and persistence",
    },
    "macos_uls": {
        "categories": {"macos": ("logs",)},
        "paths": {"macos": ("/var/log/system.log", "/var/log/install.log")},
        "why": "unified log — DNS resolutions, process launches, system events",
    },
    "macos_triage": {
        "categories": {"macos": ("triage",)},
        "paths": {},
        "why": "live macOS snapshot: processes, sockets, launchd jobs, logins",
    },
    "shell_history": {
        "categories": {"linux": ("history",), "macos": ("history",)},
        "paths": {
            "linux": ("~/.bash_history", "~/.zsh_history"),
            "macos": ("~/.zsh_history", "~/.bash_history"),
        },
        "why": "hands-on-keyboard activity",
    },
    "auth_log": {
        "categories": {"linux": ("logs",)},
        "paths": {"linux": ("/var/log/auth.log*", "/var/log/secure*")},
        "why": "authentication history and privilege escalation",
    },
    "auditd": {
        "categories": {"linux": ("audit_logs",)},
        "paths": {"linux": ("/var/log/audit/audit.log*",)},
        "why": "syscall-level execution and file access",
    },
    "pcap": {
        "categories": {"windows": ("network",), "linux": ("network",), "macos": ("network",)},
        "paths": {},
        "why": "full packet capture",
    },
    "mft": {
        "categories": {"windows": ("mft",)},
        "paths": {"windows": ("$MFT",)},
        "why": "filesystem timeline including deleted entries",
    },
    "file": {
        "categories": {
            "windows": ("file_search",),
            "linux": ("file_search",),
            "macos": ("file_search",),
        },
        "paths": {},
        "why": "targeted file retrieval — needs a --fetch pattern",
    },
    "yara": {
        "categories": {"windows": ("pe",), "linux": ("pe",), "macos": ("pe",)},
        "paths": {},
        "why": "candidate binaries to scan",
    },
    "antivirus": {
        "categories": {"windows": ("antivirus",), "linux": ("antivirus",), "macos": ("antivirus",)},
        "paths": {},
        "why": "endpoint product detections and quarantine records",
    },
}

_ALL_OS = ("windows", "linux", "macos")


@dataclass
class CollectionRequest:
    """A runnable instruction, not a wish."""

    host: str
    os_family: str
    categories: list[str] = field(default_factory=list)
    fetch_paths: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)

    @property
    def is_actionable(self) -> bool:
        return bool(self.categories or self.fetch_paths)

    def command(self) -> str:
        """The Talon invocation an operator can run as-is."""
        if not self.is_actionable:
            return ""
        parts = ["talon"]
        if self.categories:
            parts.append("--collect " + ",".join(self.categories))
        for pattern in self.fetch_paths[:12]:
            parts.append(f"--fetch '{pattern}'")
        return " ".join(parts)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "os_family": self.os_family,
            "categories": self.categories,
            "fetch_paths": self.fetch_paths,
            "rationale": self.rationale,
            "unmapped_artifact_types": self.unmapped,
            "command": self.command(),
            "actionable": self.is_actionable,
        }


def infer_os(artifact_types) -> str:
    """Guess the host OS from the artifact types already present.

    Returns "unknown" rather than a default: a request aimed at the wrong OS
    collects nothing and burns the one chance to touch the host.
    """
    present = {t for t in (artifact_types or []) if t}
    scores = dict.fromkeys(_ALL_OS, 0)
    windows = {"evtx", "registry", "prefetch", "mft", "lnk", "scheduled_task", "win_log"}
    macos = {"plist", "macos_uls", "macos_triage", "macos_install_log", "macos_wifi_log"}
    linux = {"auditd", "iptables", "linux_triage", "apt_history", "utmp", "lastlog"}
    for t in present:
        if t in windows:
            scores["windows"] += 1
        if t in macos:
            scores["macos"] += 1
        if t in linux:
            scores["linux"] += 1
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] else "unknown"


def plan_collection(
    missing_types,
    host: str,
    os_family: str = "unknown",
    extra_paths=None,
) -> CollectionRequest:
    """Turn "these artifact types were missing" into a Talon instruction."""
    req = CollectionRequest(host=host or "", os_family=os_family or "unknown")
    targets = _ALL_OS if req.os_family == "unknown" else (req.os_family,)

    seen_cat: set[str] = set()
    seen_path: set[str] = set()
    for atype in missing_types or []:
        src = _SOURCES.get(atype)
        if not src:
            req.unmapped.append(atype)
            continue
        added_any = False
        for osf in targets:
            for cat in src["categories"].get(osf, ()):
                if cat not in seen_cat:
                    seen_cat.add(cat)
                    req.categories.append(cat)
                    added_any = True
            for path in src.get("paths", {}).get(osf, ()):
                if path not in seen_path:
                    seen_path.add(path)
                    req.fetch_paths.append(path)
                    added_any = True
        if added_any:
            req.rationale.append(f"{atype}: {src['why']}")
        else:
            # Mapped, but not for this OS — a Windows-only artifact requested
            # on a macOS host is not a gap the operator can close.
            req.unmapped.append(f"{atype} (not available on {req.os_family})")

    for path in extra_paths or []:
        if path and path not in seen_path:
            seen_path.add(path)
            req.fetch_paths.append(str(path))

    return req


def supported_artifact_types() -> list[str]:
    """Artifact types this module can turn into a collection instruction."""
    return sorted(_SOURCES)


def collection_catalog() -> list[dict]:
    """The mapping, for the admin surface — what the loop can actually close."""
    return [
        {
            "artifact_type": atype,
            "why": src["why"],
            "by_os": {
                osf: {
                    "categories": list(src["categories"].get(osf, ())),
                    "paths": list(src.get("paths", {}).get(osf, ())),
                }
                for osf in _ALL_OS
                if src["categories"].get(osf) or src.get("paths", {}).get(osf)
            },
        }
        for atype, src in sorted(_SOURCES.items())
    ]
