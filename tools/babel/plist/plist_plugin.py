"""
Generic plist plugin — parses any Apple Property List (.plist) file.
Handles both XML and binary (bplist) formats using stdlib plistlib.

Each top-level key becomes one event. Nested dicts/lists are preserved
verbatim in the ``raw`` dict so analysts have the full original record.

Priority 20 — runs after iOS plugin (default 50) so iOS-specific files
like Info.plist and WiFi plists are already claimed before this plugin
sees them.
"""

from __future__ import annotations

import base64
import plistlib
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError


def _looks_like_plist(path: Path) -> bool:
    """True for a binary or XML Apple property list, by content.

    Cheap and byte-based: a bplist announces itself in the first 8 bytes, and an
    XML plist names ``<plist`` in its prologue (after the declaration and the
    Apple DOCTYPE). Reading a small head is enough and keeps a foreign XML
    dialect — Windows WER reports, scheduled tasks, IIS config — out.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(2048)
    except OSError:
        return False
    if head.startswith(b"bplist0"):
        return True
    # UTF-16 XML plists exist (rare); decode leniently before matching.
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = head.decode("utf-16", errors="replace")
    else:
        text = head.decode("utf-8", errors="replace")
    return "<plist" in text.lower()


def _file_mtime_iso(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return datetime.now(UTC).isoformat()


def _jsonable(val: Any) -> Any:
    """Convert plistlib output to a JSON-safe shape, preserving every byte.

    - bytes        → {"__bytes_b64__": "..."}  (full content, base64)
    - datetime     → ISO8601 UTC string
    - dict/list    → recursed
    """
    if val is None:
        return None
    if isinstance(val, bytes):
        return {"__bytes_b64__": base64.b64encode(val).decode("ascii"), "__bytes_len__": len(val)}
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=UTC)
        return val.isoformat()
    if isinstance(val, dict):
        return {str(k): _jsonable(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_jsonable(v) for v in val]
    if isinstance(val, (str, int, float, bool)):
        return val
    return str(val)


def _summary(val: Any, max_len: int = 200) -> str:
    """One-line human summary for the message field — never the full payload."""
    if val is None:
        return "<null>"
    if isinstance(val, bytes):
        return f"<binary {len(val)} bytes>"
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, dict):
        return (
            f"<dict {len(val)} keys: {', '.join(list(val.keys())[:3])}...>"
            if len(val) > 3
            else "{" + ", ".join(f"{k}={_summary(v, 40)}" for k, v in val.items()) + "}"
        )
    if isinstance(val, list):
        return f"<list {len(val)} items>"
    s = str(val)
    return s if len(s) <= max_len else s[:max_len] + "…"


def _pick_timestamp(value: Any) -> str | None:
    """If the value carries a datetime (top-level or shallow nested), use it."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    if isinstance(value, dict):
        for k in ("date", "timestamp", "lastModified", "lastUsed", "LastUsed", "creation_date"):
            v = value.get(k)
            if isinstance(v, datetime):
                if v.tzinfo is None:
                    v = v.replace(tzinfo=UTC)
                return v.isoformat()
    return None


class PlistPlugin(BasePlugin):
    PLUGIN_NAME = "plist"
    PLUGIN_VERSION = "1.1.0"
    DEFAULT_ARTIFACT_TYPE = "plist"
    SUPPORTED_EXTENSIONS = [".plist"]
    # Apple property list — binary (bplist) or XML variants.
    #
    # "text/xml" is deliberately NOT listed. It made this plugin claim *every*
    # XML file in a bundle: a Windows WER crash report (WER.<guid>.tmp.xml) was
    # being routed here, and because plistlib.load() returns None on non-plist
    # XML instead of raising, it emitted one junk "<null>" event per file and the
    # real WER report never reached the wer parser.
    SUPPORTED_MIME_TYPES = ["application/x-plist"]
    PLUGIN_PRIORITY = 20

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        """Claim only files that really are property lists.

        An Apple plist is either binary (``bplist00`` magic) or an XML document
        with a ``<plist>`` root. Checking for one of those is what keeps a
        foreign XML dialect from being silently mis-parsed into null events.
        """
        if super().can_handle(file_path, mime_type):
            return True
        return _looks_like_plist(file_path)

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        try:
            with open(fp, "rb") as f:
                data = plistlib.load(f)
        except Exception as exc:
            raise PluginFatalError(f"Cannot parse plist: {exc}")

        # plistlib.load() does not raise on XML that parses but is not a plist —
        # it returns None. Emitting an event for that produces a timeline entry
        # whose only content is "<null>", so refuse it as a parse failure and let
        # the router's next candidate (or the strings floor) have the file.
        if data is None:
            raise PluginFatalError(
                f"'{fp.name}' parsed as XML but yielded no property list — not a plist"
            )

        filename = fp.name
        mtime = _file_mtime_iso(fp)

        if isinstance(data, dict):
            for key, value in data.items():
                jv = _jsonable(value)
                yield {
                    "timestamp": _pick_timestamp(value) or mtime,
                    "timestamp_desc": "Plist Entry"
                    if _pick_timestamp(value)
                    else "Plist File mtime",
                    "message": f"{filename} | {key} = {_summary(value)}",
                    "artifact_type": "plist",
                    "plist": {
                        "filename": filename,
                        "key": key,
                        "value": jv,
                    },
                    "raw": {
                        "filename": filename,
                        "key": key,
                        "value": jv,
                    },
                }
        elif isinstance(data, list):
            for i, item in enumerate(data):
                jv = _jsonable(item)
                yield {
                    "timestamp": _pick_timestamp(item) or mtime,
                    "timestamp_desc": "Plist Entry"
                    if _pick_timestamp(item)
                    else "Plist File mtime",
                    "message": f"{filename}[{i}] = {_summary(item)}",
                    "artifact_type": "plist",
                    "plist": {
                        "filename": filename,
                        "index": i,
                        "value": jv,
                    },
                    "raw": {
                        "filename": filename,
                        "index": i,
                        "value": jv,
                    },
                }
        else:
            jv = _jsonable(data)
            yield {
                "timestamp": _pick_timestamp(data) or mtime,
                "timestamp_desc": "Plist File mtime",
                "message": f"{filename}: {_summary(data)}",
                "artifact_type": "plist",
                "plist": {
                    "filename": filename,
                    "value": jv,
                },
                "raw": {
                    "filename": filename,
                    "value": jv,
                },
            }
