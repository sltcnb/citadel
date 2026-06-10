"""
BasePlugin: The contract all Citadel plugins must satisfy.

A plugin is a Python module placed into the shared plugins volume.
The PluginLoader discovers modules whose top-level class inherits from BasePlugin.

Lifecycle:
    1. Loader calls plugin_class.can_handle(file_path, mime_type) as a class method.
    2. If True, loader instantiates the plugin with context.
    3. Loader calls plugin.setup(), then iterates plugin.parse().
    4. Each yielded dict is a partial ForensicEvent document.
    5. Loader calls plugin.teardown() when done.
"""

from __future__ import annotations

import abc
import logging
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger(__name__)

# Artifact types that MUST carry a structured "raw" dict (full original record).
# Loader validator rejects events of these types if raw is missing/empty.
STRUCTURED_ARTIFACTS: frozenset[str] = frozenset(
    {
        "registry",
        "evtx",
        "mft",
        "lnk",
        "prefetch",
        "plist",
        "browser",
        "scheduled_task",
        "wer",
        "shell_history",
        "android",
        "ios",
        "suricata",
        "zeek",
        "hayabusa",
        "syslog",
        "access_log",
        "json",
        "ndjson",
        "wlan_profile",
        "auditd",
        "iptables",
        "netstat",
        "macos_uls",
        "pcap",
        "aws_cloudtrail",
        "azure_signin",
        "o365_audit",
        "gcp_audit",
        "okta_system_log",
    }
)

# Artifact type → OS family. Used to populate event["os"] for filtering.
# Values: "windows" | "linux" | "macos" | "mobile" | "cross"
# "cross" = format-agnostic (network captures, browser data, generic logs).
ARTIFACT_OS: dict[str, str] = {
    # ── Windows ───────────────────────────────────────────────────────────────
    "registry": "windows",
    "registry_hive": "windows",
    "user_account": "windows",
    "evtx": "windows",
    "win_log": "windows",
    "mft": "windows",
    "prefetch": "windows",
    "lnk": "windows",
    "scheduled_task": "windows",
    "wer": "windows",
    "persistence": "windows",
    "etw_trace": "windows",
    "wlan_profile": "windows",
    "usb_log": "windows",
    "iis_access_log": "windows",
    "firewall_log": "windows",
    "triage": "windows",
    "system_info": "windows",
    "network_conn": "windows",
    "process": "windows",
    "service": "windows",
    "startup_item": "windows",
    "installed_software": "windows",
    "powershell_script": "windows",
    "batch_script": "windows",
    "vbscript": "windows",
    "hayabusa": "windows",
    # ── Linux ─────────────────────────────────────────────────────────────────
    "syslog": "linux",
    "auditd": "linux",
    "iptables": "linux",
    "shell_history": "linux",
    "linux_triage": "linux",
    "kernel_module": "linux",
    "cron_job": "linux",
    "env_variable": "linux",
    "installed_pkg": "linux",
    "listening_port": "linux",
    "arp_entry": "linux",
    "route_entry": "linux",
    "logged_user": "linux",
    "login_event": "linux",
    "open_file": "linux",
    "shell_script": "linux",
    "package_event": "linux",
    # ── macOS ─────────────────────────────────────────────────────────────────
    "plist": "macos",
    "macos_uls": "macos",
    # ── Mobile ────────────────────────────────────────────────────────────────
    "android": "mobile",
    "ios": "mobile",
    # ── Cross / format-agnostic ───────────────────────────────────────────────
    "browser": "cross",
    "browser_report": "cross",
    "antivirus": "cross",
    "access_log": "cross",
    "suricata": "cross",
    "zeek": "cross",
    "pcap": "cross",
    "exiftool": "cross",
    "yara": "cross",
    "json": "cross",
    "yaml": "cross",
    "csv_row": "cross",
    "ndjson": "cross",
    "file": "cross",
    "binary_files": "cross",
    "config_file": "cross",
    "log_file": "cross",
    "certificate": "cross",
    "database": "cross",
    "diskimage": "cross",
    "dd_file": "cross",
    "dd_carved": "cross",
    "archive": "cross",
    "plaso": "cross",
    "log2timeline": "cross",
    # ── Cloud / identity audit logs (mapped via citadel_contracts.mapping) ──────
    "aws_cloudtrail": "cloud",
    "azure_signin": "cloud",
    "o365_audit": "cloud",
    "gcp_audit": "cloud",
    "okta_system_log": "cloud",
    "generic": "cross",
}


def classify_os(artifact_type: str) -> str:
    """Return os family ("windows"/"linux"/"macos"/"mobile"/"cross") for a type.
    Returns "cross" for unknown artifact_type — so analysts always get a value."""
    return ARTIFACT_OS.get(artifact_type, "cross")


def iso_z(value: str | datetime | int | float | None) -> str | None:
    """Canonicalize a timestamp to ISO-8601 UTC with a ``Z`` suffix.

    The project standardises ForensicEvent ``timestamp`` on the ``...Z`` form;
    every parser that funnels through :meth:`BasePlugin.make_event` gets this for
    free. Accepts datetime / epoch / ISO string (``Z`` or offset)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC).isoformat().replace("+00:00", "Z")
    s = str(value).strip()
    if s.endswith(("Z", "z")):
        return s[:-1] + "Z"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except ValueError:
        return s.replace("+00:00", "Z")


class PluginError(Exception):
    """Base class for plugin errors."""


class PluginParseError(PluginError):
    """Raised when parsing a specific record fails but processing can continue."""


class PluginFatalError(PluginError):
    """Raised when the plugin cannot process the file at all."""


@dataclass
class PluginContext:
    """Injected into every plugin instance. Provides access to platform resources."""

    case_id: str
    job_id: str
    source_file_path: Path
    source_minio_url: str
    config: dict[str, Any] = field(default_factory=dict)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("plugin"))


class BasePlugin(abc.ABC):
    """
    Abstract base class for all Citadel artifact parsers.

    Subclass this, implement the abstract methods, and drop the module into
    the plugins volume. No further registration is required.
    """

    PLUGIN_NAME: ClassVar[str] = "base"
    PLUGIN_VERSION: ClassVar[str] = "0.0.0"
    DEFAULT_ARTIFACT_TYPE: ClassVar[str] = "generic"
    SUPPORTED_EXTENSIONS: ClassVar[list[str]] = []
    SUPPORTED_MIME_TYPES: ClassVar[list[str]] = []
    # Higher value = tried first. Specific parsers should use 100; generic
    # fallbacks (log2timeline, plaso) should use 10 so they never shadow
    # a dedicated plugin.
    PLUGIN_PRIORITY: ClassVar[int] = 50

    def __init__(self, context: PluginContext) -> None:
        self.ctx = context
        self.log = context.logger.getChild(self.PLUGIN_NAME)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        """Return True if this plugin can parse the given file."""
        ext_match = file_path.suffix.lower() in cls.SUPPORTED_EXTENSIONS
        mime_match = mime_type in cls.SUPPORTED_MIME_TYPES
        # For files without extension (e.g., $MFT), allow filename matching
        name_match = file_path.name.upper() in cls.get_handled_filenames()
        return ext_match or mime_match or name_match

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        """Override to handle files matched by name (e.g., '$MFT', 'NTUSER.DAT')."""
        return []

    @classmethod
    def get_info(cls) -> dict[str, Any]:
        """Return plugin metadata for the /api/v1/plugins endpoint."""
        return {
            "name": cls.PLUGIN_NAME,
            "version": cls.PLUGIN_VERSION,
            "default_artifact_type": cls.DEFAULT_ARTIFACT_TYPE,
            "supported_extensions": cls.SUPPORTED_EXTENSIONS,
            "supported_mime_types": cls.SUPPORTED_MIME_TYPES,
            "handled_filenames": cls.get_handled_filenames(),
        }

    @abc.abstractmethod
    def parse(self) -> Generator[dict[str, Any], None, None]:
        """
        Parse the artifact and yield normalized event dicts.

        Required keys in each yielded dict:
            - "timestamp" (str, ISO8601 UTC)
            - "message"   (str, human-readable summary)

        Optional but recommended:
            - "artifact_type"  (str) — overrides DEFAULT_ARTIFACT_TYPE
            - "timestamp_desc" (str)
            - "host", "user", "process", "network" (dicts)
            - Artifact-specific sub-object (e.g., "evtx": {...})
            - "raw" (dict) — original parsed data, stored but not indexed

        Raises:
            PluginParseError: For skippable per-record errors.
            PluginFatalError: For file-level fatal errors.
        """
        ...

    def setup(self) -> None:
        """Called once before parse() is iterated. Open file handles here."""

    def teardown(self) -> None:
        """Called once after parse() is exhausted. Close file handles here."""

    def get_stats(self) -> dict[str, Any]:
        """Return plugin-specific statistics after parsing completes."""
        return {}

    # ── Event-construction helper ─────────────────────────────────────────────
    def make_event(
        self,
        *,
        timestamp: str | datetime | None,
        message: str,
        raw: dict[str, Any] | None = None,
        artifact_type: str | None = None,
        timestamp_desc: str = "Event Time",
        host: dict[str, Any] | None = None,
        user: dict[str, Any] | None = None,
        process: dict[str, Any] | None = None,
        network: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        **artifact_subobj: Any,
    ) -> dict[str, Any]:
        """
        Build a contract-compliant event dict.

        Every plugin should funnel through this helper so the timeline gets a
        consistent shape: enriched ``message`` + structured ``raw`` + standard
        enrichment sub-dicts (host/user/process/network).

        - ``timestamp``: ISO8601 UTC string or datetime. Falsy → falls back to
          file mtime in the loader (not None — never None at index time).
        - ``message``: human-readable summary. MUST NOT be ``str(raw)``.
        - ``raw``: original parsed record. For STRUCTURED_ARTIFACTS this is
          mandatory; the loader will warn if missing.
        - ``artifact_type``: defaults to plugin's DEFAULT_ARTIFACT_TYPE.
        - ``artifact_subobj``: free-form kwargs become an artifact-specific
          sub-object keyed by artifact_type (e.g., ``evtx={...}``).
        """
        ts_str: str | None = iso_z(timestamp) if timestamp else None  # let loader fall back

        at = artifact_type or self.DEFAULT_ARTIFACT_TYPE
        evt: dict[str, Any] = {
            "timestamp": ts_str or "",
            "timestamp_desc": timestamp_desc,
            "message": message or "",
            "artifact_type": at,
            "raw": raw if isinstance(raw, dict) else ({} if raw is None else {"value": raw}),
        }
        if host:
            evt["host"] = host
        if user:
            evt["user"] = user
        if process:
            evt["process"] = process
        if network:
            evt["network"] = network
        if artifact_subobj:
            evt[at] = artifact_subobj
        if extra:
            evt.update(extra)
        return evt
