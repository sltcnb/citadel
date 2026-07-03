"""
Windows Timeline (ActivitiesCache.db) plugin.

Parses the Windows 10/11 Activity History SQLite DB — the "Timeline" feature.
Each row in the ``Activity`` table records an app the user ran and a document
they touched, with start/end times: strong execution + file-access evidence,
independent of Prefetch/UserAssist. Read-only, WAL-tolerant open.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError


def _epoch(v: Any) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    # ActivitiesCache uses Unix seconds; guard against ms.
    if n > 10_000_000_000:
        n //= 1000
    try:
        return datetime.fromtimestamp(n, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return ""


def _app_from(appid: str) -> str:
    if not appid:
        return ""
    try:
        arr = json.loads(appid)
        for entry in arr if isinstance(arr, list) else [arr]:
            app = (entry or {}).get("application", "")
            if app and app not in ("", "windows_universal"):
                return app.replace("/", "\\").split("\\")[-1]
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    return appid[:80]


class WinTimelinePlugin(BasePlugin):
    """Parses Windows Timeline ActivitiesCache.db activity history."""

    PLUGIN_NAME = "win_timeline"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "timeline_activity"
    SUPPORTED_EXTENSIONS = [".db"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3", "application/octet-stream"]
    PLUGIN_PRIORITY = 94

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return ["ActivitiesCache.db"]

    @classmethod
    def can_handle(cls, file_path, mime_type) -> bool:
        if file_path.name.lower().startswith("activitiescache"):
            return True
        try:
            with open(file_path, "rb") as fh:
                if fh.read(16) != b"SQLite format 3\x00":
                    return False
            con = sqlite3.connect(f"file:{file_path}?mode=ro&immutable=1", uri=True)
            try:
                names = {r[0].lower() for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                con.close()
            return "activity" in names or "activity_packageid" in names
        except (OSError, sqlite3.Error):
            return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error as exc:
            raise PluginFatalError(f"Cannot open ActivitiesCache: {exc}") from exc
        con.row_factory = sqlite3.Row
        try:
            try:
                rows = con.execute(
                    "SELECT AppId, ActivityType, StartTime, EndTime, LastModifiedTime, Payload "
                    "FROM Activity"
                ).fetchall()
            except sqlite3.Error:
                return
            for row in rows:
                app = _app_from(row["AppId"] if "AppId" in row.keys() else "")
                start = _epoch(row["StartTime"]) if "StartTime" in row.keys() else ""
                end = _epoch(row["EndTime"]) if "EndTime" in row.keys() else ""
                display = ""
                try:
                    pl = json.loads(row["Payload"]) if row["Payload"] else {}
                    display = pl.get("displayText") or pl.get("appDisplayName") or pl.get("description") or ""
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass
                ts = start or end or _epoch(row["LastModifiedTime"] if "LastModifiedTime" in row.keys() else 0)
                msg = f"Timeline: {app}" + (f" — {display}" if display else "")
                yield {
                    "timestamp": ts or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "timestamp_desc": "Windows Timeline Activity",
                    "message": msg,
                    "artifact_type": "timeline_activity",
                    "os": "windows",
                    "process": {"name": app} if app else {},
                    "timeline": {
                        "app": app,
                        "activity_type": row["ActivityType"] if "ActivityType" in row.keys() else None,
                        "start_time": start,
                        "end_time": end,
                        "display_text": display,
                    },
                    "raw": {"content": display or app},
                }
        finally:
            con.close()

    def get_stats(self) -> dict[str, Any]:
        return {}
