"""
plist plugin — Apple Property Lists, XML and binary, via stdlib plistlib.

Most plists are configuration and the right output is a key/value dump. A few
carry the evidence a macOS investigation actually turns on, and for those a
dump is worse than useless — it scatters one fact across N events and elides
the part that matters. A LaunchDaemon used to come out as seven disconnected
rows, the load-bearing one reading::

    com.evil.agent.plist | ProgramArguments = <list 2 items>

The executable path — the whole point of the artifact — appeared nowhere in
any message, so searching for it found nothing. These get a semantic handler:

  launchd job (Label + Program/ProgramArguments)
      → ONE ``persistence`` event carrying the full command line, the trigger
        (RunAtLoad / StartInterval / WatchPaths / StartCalendarInterval) and a
        flag for a job running from a user-writable path.
  Safari Downloads.plist (DownloadHistory)
      → ``browser`` download events with the source URL.
  Login items (loginwindow / com.apple.loginitems)
      → ``persistence`` events, one per item.

Everything else keeps the per-key dump, but the message now carries real
content instead of ``<list N items>``: a container of scalars is rendered
inline, so its values are searchable in the timeline rather than only in the
structured ``plist.value`` object.

NSKeyedArchiver payloads ($archiver/$objects/$top) are resolved back into the
object graph they encode before any of the above runs. plistlib returns them
as a flat $objects table with integer back-references, which dumps as an
unreadable soup of indices.

Priority 20 — runs after the iOS plugin (default 50) so iOS-specific files
like Info.plist and the WiFi plists are claimed before this plugin sees them.
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
        # Render a list of scalars inline. "<list 2 items>" hid the one thing
        # worth reading — a LaunchDaemon's ProgramArguments IS the command line,
        # and eliding it made the executable path unsearchable.
        if val and all(isinstance(v, (str, int, float, bool)) for v in val):
            joined = " ".join(str(v) for v in val)
            return joined if len(joined) <= max_len else joined[:max_len] + "…"
        return f"<list {len(val)} items>"
    s = str(val)
    return s if len(s) <= max_len else s[:max_len] + "…"


# ── Semantic plist shapes ─────────────────────────────────────────────────────

# A launchd job is identified by shape, not filename: Talon collects these from
# /Library/LaunchDaemons, ~/Library/LaunchAgents and several other roots, and
# malware is free to name the file anything.
def _is_launchd_job(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and "Label" in data
        and ("Program" in data or "ProgramArguments" in data)
    )


# Paths any user can write to. A launchd job whose executable lives here is the
# classic macOS persistence pattern; one under /usr/libexec or /System is the OS.
_USER_WRITABLE = ("/Users/", "/tmp/", "/var/tmp/", "/private/tmp/", "/Volumes/")


def _launchd_command(data: dict) -> tuple[str, str]:
    """Return (executable, full command line) for a launchd job."""
    args = data.get("ProgramArguments")
    program = data.get("Program")
    if isinstance(args, list) and args:
        argv = [str(a) for a in args]
        # Program wins as argv[0] when both are present — that is launchd's own
        # rule, and a job can point Program at one binary while argv[0] lies.
        exe = str(program) if program else argv[0]
        return exe, " ".join(argv)
    if program:
        return str(program), str(program)
    return "", ""


def _launchd_trigger(data: dict) -> str:
    """Human summary of what makes the job run."""
    parts: list[str] = []
    if data.get("RunAtLoad"):
        parts.append("at load")
    if data.get("KeepAlive"):
        parts.append("kept alive")
    interval = data.get("StartInterval")
    if isinstance(interval, int):
        parts.append(f"every {interval}s")
    if data.get("StartCalendarInterval"):
        parts.append("on a calendar schedule")
    watch = data.get("WatchPaths")
    if isinstance(watch, list) and watch:
        parts.append(f"on changes to {', '.join(str(w) for w in watch[:3])}")
    if data.get("StartOnMount"):
        parts.append("on mount")
    if isinstance(data.get("Sockets"), dict):
        parts.append("on socket activity")
    return ", ".join(parts) or "on demand"


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


def _resolve_nskeyedarchiver(data: Any, _depth: int = 0) -> Any:
    """Rebuild the object graph an NSKeyedArchiver plist encodes.

    plistlib decodes the container faithfully and that is the problem: the
    payload is a flat ``$objects`` table plus ``$top`` holding integer indices
    into it, so a dump is a soup of numbers with the real strings sitting in a
    side table. Follow the references once, here, and every handler downstream
    sees ordinary dicts and lists.

    Returns *data* unchanged when it is not an archive, so this is safe to run
    over everything.
    """
    if not (isinstance(data, dict) and "$objects" in data and "$top" in data):
        return data
    objects = data.get("$objects")
    if not isinstance(objects, list):
        return data

    def deref(value: Any, depth: int) -> Any:
        # Cyclic graphs are legal in an archive (a parent holding its children
        # holding the parent); bound the walk rather than trusting the data.
        if depth > 24:
            return "<max depth>"
        if isinstance(value, plistlib.UID):
            idx = int(value.data)
            if not (0 <= idx < len(objects)):
                return None
            resolved = objects[idx]
            # $null is the archive's None.
            if resolved == "$null":
                return None
            return deref(resolved, depth + 1)
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if k == "$class":  # bookkeeping, not payload
                    continue
                out[str(k)] = deref(v, depth + 1)
            return out
        if isinstance(value, list):
            return [deref(v, depth + 1) for v in value]
        return value

    try:
        top = deref(data.get("$top"), _depth)
    except Exception:
        return data
    # A single-rooted archive ("root") is the common case; unwrap it so callers
    # see the payload rather than a one-key wrapper.
    if isinstance(top, dict) and set(top) == {"root"}:
        return top["root"]
    return top if top is not None else data


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
            raise PluginFatalError(f"Cannot parse plist: {exc}") from exc

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

        # Archives first: every handler below wants the decoded object graph,
        # not the $objects/$top index table plistlib hands back.
        data = _resolve_nskeyedarchiver(data)

        # Semantic shapes — these carry the evidence a macOS case turns on, and
        # a key/value dump destroys them. Each returns a complete event stream,
        # so the generic dump below is skipped entirely.
        if _is_launchd_job(data):
            yield from self._parse_launchd(data, filename, mtime)
            return
        downloads = self._safari_downloads(data)
        if downloads is not None:
            yield from self._parse_safari_downloads(downloads, filename, mtime)
            return
        login_items = self._login_items(data)
        if login_items is not None:
            yield from self._parse_login_items(login_items, filename, mtime)
            return

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

    # ── launchd job (LaunchAgents / LaunchDaemons) ────────────────────────────

    def _parse_launchd(
        self, data: dict, filename: str, mtime: str
    ) -> Generator[dict[str, Any], None, None]:
        """One event per job, not one per key.

        macOS persistence is a single fact — "this label runs this command on
        this trigger" — and splitting it across seven rows means no single
        event answers the question an analyst asks.
        """
        label = str(data.get("Label") or "")
        exe, command = _launchd_command(data)
        trigger = _launchd_trigger(data)
        disabled = bool(data.get("Disabled"))
        user_writable = exe.startswith(_USER_WRITABLE)
        run_as = data.get("UserName")

        bits = [f"launchd job {label or filename}"]
        if command:
            bits.append(f"runs {command}")
        bits.append(trigger)
        if run_as:
            bits.append(f"as {run_as}")
        if disabled:
            bits.append("[disabled]")
        if user_writable:
            bits.append("[user-writable path]")

        yield {
            "timestamp": mtime,
            "timestamp_desc": "Plist File mtime",
            "artifact_type": "persistence",
            # The shared taxonomy files "persistence" under windows; a launchd
            # job is macOS by construction, so say so rather than let it land
            # on the wrong side of an OS filter.
            "os": "macos",
            "message": "  ".join(bits),
            "process": {"path": exe, "name": exe.rsplit("/", 1)[-1], "command_line": command}
            if exe
            else {},
            "user": {"name": str(run_as)} if run_as else {},
            "persistence": {
                "kind": "launchd",
                "label": label,
                "executable": exe,
                "command_line": command,
                "trigger": trigger,
                "run_at_load": bool(data.get("RunAtLoad")),
                "keep_alive": bool(data.get("KeepAlive")),
                "start_interval": data.get("StartInterval"),
                "watch_paths": [str(w) for w in (data.get("WatchPaths") or [])]
                if isinstance(data.get("WatchPaths"), list)
                else [],
                "run_as": str(run_as) if run_as else "",
                "disabled": disabled,
                "user_writable_path": user_writable,
                "filename": filename,
            },
            "raw": {"filename": filename, "value": _jsonable(data)},
        }

    # ── Safari Downloads.plist ────────────────────────────────────────────────

    @staticmethod
    def _safari_downloads(data: Any) -> list | None:
        """Return the download list if this is a Safari Downloads.plist."""
        if isinstance(data, dict):
            hist = data.get("DownloadHistory")
            if isinstance(hist, list):
                return hist
        return None

    def _parse_safari_downloads(
        self, history: list, filename: str, mtime: str
    ) -> Generator[dict[str, Any], None, None]:
        """Safari's download log — the URL each file came from."""
        for entry in history:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("DownloadEntryURL") or "")
            path = str(entry.get("DownloadEntryPath") or "")
            ts = _pick_timestamp(entry.get("DownloadEntryDateAddedKey")) or _pick_timestamp(
                entry
            )
            total = entry.get("DownloadEntryProgressTotalToLoad")
            got = entry.get("DownloadEntryProgressBytesSoFar")
            yield {
                "timestamp": ts or mtime,
                "timestamp_desc": "Download Started" if ts else "Plist File mtime",
                "artifact_type": "browser",
                "os": "macos",
                "message": f"Safari download: {url}" + (f" -> {path}" if path else ""),
                "browser": {
                    "browser_type": "safari",
                    "data_type": "download",
                    "url": url,
                    "target_path": path,
                    "bytes_total": total if isinstance(total, int) else None,
                    "bytes_received": got if isinstance(got, int) else None,
                },
                "raw": {"filename": filename, "value": _jsonable(entry)},
            }

    # ── Login items ───────────────────────────────────────────────────────────

    @staticmethod
    def _login_items(data: Any) -> list | None:
        """Return the login-item list for a loginwindow / loginitems plist."""
        if not isinstance(data, dict):
            return None
        for key in ("AutoLaunchedApplicationDictionary", "SessionItems", "CustomListItems"):
            v = data.get(key)
            if isinstance(v, list):
                return v
            if isinstance(v, dict) and isinstance(v.get("CustomListItems"), list):
                return v["CustomListItems"]
        return None

    def _parse_login_items(
        self, items: list, filename: str, mtime: str
    ) -> Generator[dict[str, Any], None, None]:
        """Anything set to launch at login is persistence, same as a launchd job."""
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("Name") or item.get("name") or "")
            path = str(item.get("Path") or item.get("path") or "")
            hidden = bool(item.get("Hide") or item.get("hidden"))
            user_writable = path.startswith(_USER_WRITABLE)
            bits = [f"login item {name or path or '(unnamed)'}"]
            if path:
                bits.append(f"-> {path}")
            if hidden:
                bits.append("[hidden]")
            if user_writable:
                bits.append("[user-writable path]")
            yield {
                "timestamp": mtime,
                "timestamp_desc": "Plist File mtime",
                "artifact_type": "persistence",
                "os": "macos",
                "message": "  ".join(bits),
                "process": {"path": path, "name": path.rsplit("/", 1)[-1]} if path else {},
                "persistence": {
                    "kind": "login_item",
                    "label": name,
                    "executable": path,
                    "hidden": hidden,
                    "user_writable_path": user_writable,
                    "filename": filename,
                },
                "raw": {"filename": filename, "value": _jsonable(item)},
            }
