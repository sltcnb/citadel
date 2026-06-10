"""
Log2Timeline Plugin — runs log2timeline/plaso on any uploaded artifact and
yields the resulting timeline events into the case.

log2timeline supports a very wide range of input formats:
  Windows EVTX, Registry hives, Prefetch, LNK, $MFT, Scheduled Tasks,
  macOS plist / ASL / unified logs, Linux syslog / utmp, SQLite databases
  (browsers, iOS backups), PCAP (via Dpfilter), PE files, and many more.

This plugin acts as a "universal" ingester for formats that have no dedicated
plugin in Citadel — or when you want Plaso's full timeline depth
instead of the targeted field extraction done by the native plugins.

Requirements: log2timeline (plaso suite) must be installed in the processor
image — `pip install plaso` or via OS packages.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

logger = logging.getLogger(__name__)

# Extensions that have NO dedicated Citadel plugin — log2timeline is
# the primary ingester for these formats.
_PRIMARY_EXTENSIONS = frozenset(
    {
        ".evt",  # Old Windows Event Log (NT/XP/2003)
        ".plist",  # macOS property list
        ".asl",  # macOS Apple System Log
        ".utmpx",  # UNIX login records
        ".utmp",
        ".wtmp",
        ".pcap",  # Network captures (plaso uses dpfilter)
        ".pcapng",
        ".esedb",  # Extensible Storage Engine (ESE/JET database)
        ".edb",  # Exchange / Windows Search DB
        ".db3",  # Generic SQLite alias
    }
)

# Extensions that log2timeline can also handle as a fallback (when no native
# plugin matched). Listed here so the loader can route them here if needed.
_SECONDARY_EXTENSIONS = frozenset(
    {
        ".evtx",  # Covered by EvtxPlugin, but l2t gives deeper context
        ".lnk",
        ".pf",
        ".dat",
        ".hive",
        ".sqlite",
        ".db",
        ".log",
        ".txt",
        ".csv",
        ".json",
    }
)

# Well-known filenames that l2t handles specially
_KNOWN_FILENAMES = frozenset(
    {
        "$MFT",
        "NTUSER.DAT",
        "SYSTEM",
        "SOFTWARE",
        "SAM",
        "SECURITY",
        "USRCLASS.DAT",
        "places.sqlite",
        "History",
        "Cookies",
        "Web Data",
    }
)

# Timestamp field candidates in psort JSON output
_TS_FIELDS = ("datetime", "timestamp", "date_time")


class Log2TimelinePlugin(BasePlugin):
    """
    Universal timeline ingester powered by log2timeline/plaso.
    Runs log2timeline on the source file, exports events via psort,
    and yields each event into the case timeline.
    """

    PLUGIN_NAME = "log2timeline"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "log2timeline"
    SUPPORTED_EXTENSIONS = sorted(_PRIMARY_EXTENSIONS | _SECONDARY_EXTENSIONS)
    # Intentionally empty: generic timeline fallback, routed purely by the broad
    # extension set above so it never shadows a dedicated parser via MIME.
    SUPPORTED_MIME_TYPES = []  # detected by extension / filename
    # Above json_file (15) so l2t gets first crack at text/log files;
    # below all dedicated parsers (50+).
    PLUGIN_PRIORITY = 20

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._work_dir: Path | None = None
        self._jsonl_path: Path | None = None
        self._parsed = 0
        self._skipped = 0

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_KNOWN_FILENAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        # Refuse immediately if the binary is not installed so the job
        # fails with "no plugin found" rather than a runtime PluginFatalError.
        if not (shutil.which("log2timeline.py") or shutil.which("log2timeline")):
            return False
        # Primary: extensions / filenames with no dedicated plugin
        name = file_path.name.upper()
        ext = file_path.suffix.lower()
        if name in _KNOWN_FILENAMES or ext in _PRIMARY_EXTENSIONS:
            return True
        # Secondary: broad match — handled here only when no other plugin
        # claims the file first (the loader picks the first matching plugin,
        # so native plugins like EvtxPlugin take priority)
        return ext in _SECONDARY_EXTENSIONS

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def setup(self) -> None:
        l2t_bin = shutil.which("log2timeline.py") or shutil.which("log2timeline")
        psort_bin = shutil.which("psort.py") or shutil.which("psort")

        if not l2t_bin:
            raise PluginFatalError(
                "log2timeline binary not found. Install the plaso suite in the processor "
                "image: pip install plaso   or   apt-get install plaso"
            )

        self._work_dir = Path(tempfile.mkdtemp(prefix="fo_l2t_"))
        src = self.ctx.source_file_path
        plaso_out = self._work_dir / "timeline.plaso"

        # log2timeline needs a directory (not a single file path on some versions)
        src_link = self._work_dir / "sources" / src.name
        src_link.parent.mkdir(parents=True)
        # hard-link if same filesystem, otherwise copy
        try:
            src_link.hardlink_to(src)
        except (OSError, AttributeError):
            shutil.copy2(str(src), str(src_link))

        logger.info("[l2t] Processing %s", src.name)
        try:
            result = subprocess.run(
                [
                    l2t_bin,
                    "--status_view",
                    "none",
                    "--logfile",
                    str(self._work_dir / "l2t.log"),
                    "-z",
                    "UTC",
                    str(plaso_out),
                    str(src_link.parent),
                ],
                capture_output=True,
                text=True,
                timeout=3600,
            )
        except subprocess.TimeoutExpired:
            raise PluginFatalError("log2timeline timed out after 1 hour")

        if not plaso_out.exists() or plaso_out.stat().st_size == 0:
            stderr = (result.stderr or "").strip()[:500]
            raise PluginFatalError(
                f"log2timeline produced no output (exit {result.returncode}): {stderr}"
            )

        logger.info("[l2t] .plaso size: %d B", plaso_out.stat().st_size)

        # Export to JSON Lines via psort for easy iteration
        if not psort_bin:
            logger.warning("[l2t] psort not found — cannot export events")
            return

        self._jsonl_path = self._work_dir / "events.jsonl"
        try:
            subprocess.run(
                [
                    psort_bin,
                    "--status_view",
                    "none",
                    "-z",
                    "UTC",
                    "-o",
                    "json_line",
                    "-w",
                    str(self._jsonl_path),
                    str(plaso_out),
                ],
                capture_output=True,
                text=True,
                timeout=3600,
            )
        except subprocess.TimeoutExpired:
            logger.warning("[l2t] psort timed out")
            self._jsonl_path = None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        if not self._jsonl_path or not self._jsonl_path.exists():
            logger.warning("[l2t] No event file to parse for %s", self.ctx.source_file_path.name)
            return

        try:
            fh = open(self._jsonl_path, encoding="utf-8", errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open psort output: {exc}") from exc

        with fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    self._skipped += 1
                    continue

                ev = self._normalise(obj)
                if ev:
                    self._parsed += 1
                    yield ev
                else:
                    self._skipped += 1

    def teardown(self) -> None:
        if self._work_dir and self._work_dir.exists():
            shutil.rmtree(self._work_dir, ignore_errors=True)
            self._work_dir = None

    # ── helpers ────────────────────────────────────────────────────────────────

    def _normalise(self, obj: dict) -> dict | None:
        # Timestamp
        ts = ""
        for f in _TS_FIELDS:
            v = obj.get(f, "")
            if v and v not in ("0000-00-00T00:00:00+00:00", "0000-00-00 00:00:00"):
                ts = str(v)
                break

        msg = str(obj.get("message", obj.get("description", ""))).strip()
        if not msg:
            return None

        src_short = str(obj.get("source_short", obj.get("source", ""))).strip()
        hostname = str(obj.get("hostname", obj.get("computer_name", ""))).strip()
        username = str(obj.get("username", "")).strip()
        filename = str(obj.get("filename", obj.get("display_name", ""))).strip()

        return {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "log2timeline",
            "timestamp": ts,
            "timestamp_desc": str(obj.get("timestamp_desc", "Event Time")),
            "message": msg[:1000],
            "host": {"hostname": hostname},
            "user": {"name": username},
            "log2timeline": {
                "source": src_short,
                "filename": filename,
                "parser": str(obj.get("parser", "")),
                "store_index": obj.get("store_index"),
            },
            "raw": {"line": json.dumps(obj, ensure_ascii=False)},
        }

    def get_stats(self) -> dict[str, Any]:
        return {"records_parsed": self._parsed, "records_skipped": self._skipped}
