"""
Windows Notifications (wpndatabase.db) plugin.

Parses the Windows push-notification store — every toast that arrived (Teams/
Outlook/Slack messages, download-complete, AV alerts, calendar, etc.), with the
originating app and arrival time. Rich user-activity + comms timeline. Read-only
SQLite; joins Notification → NotificationHandler for the app id.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_TAGS = re.compile(r"<[^>]+>")


def _filetime(v: Any) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=n / 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


def _text_from_payload(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    txt = _TAGS.sub(" ", str(payload))
    return " ".join(txt.split())[:300]


class NotificationsPlugin(BasePlugin):
    """Parses Windows toast-notification history (wpndatabase.db)."""

    PLUGIN_NAME = "notifications"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "notifications"
    SUPPORTED_EXTENSIONS = [".db"]
    SUPPORTED_MIME_TYPES = ["application/x-sqlite3", "application/octet-stream"]
    PLUGIN_PRIORITY = 94

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return ["wpndatabase.db"]

    @classmethod
    def can_handle(cls, file_path, mime_type) -> bool:
        if file_path.name.lower().startswith("wpndatabase"):
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
            return "notification" in names and "notificationhandler" in names
        except (OSError, sqlite3.Error):
            return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error as exc:
            raise PluginFatalError(f"Cannot open wpndatabase: {exc}") from exc
        con.row_factory = sqlite3.Row
        try:
            # Map handler → app id.
            handlers: dict[Any, str] = {}
            try:
                for h in con.execute("SELECT RecordId, PrimaryId FROM NotificationHandler"):
                    handlers[h["RecordId"]] = h["PrimaryId"]
            except sqlite3.Error:
                pass
            try:
                rows = con.execute(
                    "SELECT HandlerId, Type, Payload, ArrivalTime, ExpiryTime FROM Notification"
                ).fetchall()
            except sqlite3.Error:
                return
            for row in rows:
                app = handlers.get(row["HandlerId"], "") if "HandlerId" in row.keys() else ""
                arrival = _filetime(row["ArrivalTime"]) if "ArrivalTime" in row.keys() else ""
                text = _text_from_payload(row["Payload"] if "Payload" in row.keys() else None)
                ntype = row["Type"] if "Type" in row.keys() else ""
                msg = f"Notification [{app}]" + (f": {text}" if text else "") + (f" ({ntype})" if ntype else "")
                yield {
                    "timestamp": arrival or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "timestamp_desc": "Toast Notification",
                    "message": msg,
                    "artifact_type": "notifications",
                    "os": "windows",
                    "notification": {
                        "app": app,
                        "type": ntype,
                        "text": text,
                        "arrival_time": arrival,
                        "expiry_time": _filetime(row["ExpiryTime"]) if "ExpiryTime" in row.keys() else "",
                    },
                    "raw": {"content": text or app},
                }
        finally:
            con.close()

    def get_stats(self) -> dict[str, Any]:
        return {}
