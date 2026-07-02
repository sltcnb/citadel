"""
Mark-of-the-Web (Zone.Identifier) Plugin.

Windows writes a ``Zone.Identifier`` NTFS alternate data stream onto files that
arrive from an untrusted source (browser downloads, email attachments, archive
extractions). The stream is a small INI:

    [ZoneTransfer]
    ZoneId=3
    ReferrerUrl=https://example.com/page
    HostUrl=https://miniwakaya.xyz/Bin/ScreenConnect.ClientSetup.msi?e=Access

This is the best NATIVE proof of "this file was downloaded from URL X" — no EDR
required. The collector stages each stream as ``<original>.Zone.Identifier``;
this plugin parses it into a mark_of_web event carrying the source URL + domain
so the IOC panel / entity graph / Lucene queries pick it up.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from babel.base_plugin import BasePlugin, PluginFatalError

# ZoneId → human label (MSDN URL security zones).
_ZONE_LABELS = {
    "0": "Local Machine",
    "1": "Local Intranet",
    "2": "Trusted Sites",
    "3": "Internet",
    "4": "Restricted Sites",
}

_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")


def _domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


class MarkOfWebPlugin(BasePlugin):
    """Parses NTFS Zone.Identifier (Mark-of-the-Web) alternate data streams."""

    PLUGIN_NAME = "markofweb"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "mark_of_web"
    SUPPORTED_EXTENSIONS = [".identifier"]
    SUPPORTED_MIME_TYPES = ["text/plain"]
    PLUGIN_PRIORITY = 95  # above generic text fallbacks

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return []  # names are dynamic (<file>.Zone.Identifier) — matched by content

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        name = file_path.name.lower()
        if name.endswith("zone.identifier") or name.endswith(".zoneidentifier"):
            return True
        # Content sniff: the stream always opens with the [ZoneTransfer] section.
        try:
            with open(file_path, errors="replace") as fh:
                head = fh.read(256)
            return "[ZoneTransfer]" in head
        except OSError:
            return False

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            text = path.read_text(errors="replace")
        except OSError as exc:
            raise PluginFatalError(f"Cannot read Zone.Identifier: {exc}") from exc

        fields: dict[str, str] = {}
        for line in text.splitlines():
            if line.strip().startswith("["):
                continue
            m = _KV_RE.match(line)
            if m:
                fields[m.group(1).lower()] = m.group(2)

        if not fields:
            return  # not a real Zone.Identifier — nothing to emit

        host_url = fields.get("hosturl", "")
        referrer = fields.get("referrerurl", "")
        zone_id = fields.get("zoneid", "")
        zone_label = _ZONE_LABELS.get(zone_id, zone_id or "unknown")

        # The stream's own filename is "<original>.Zone.Identifier" — recover the
        # original downloaded file's name for the message.
        stream_name = path.name
        orig = re.sub(r"[:.]zone\.identifier$", "", stream_name, flags=re.IGNORECASE)

        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except OSError:
            ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        src = host_url or referrer
        if src:
            msg = f"Mark-of-the-Web: {orig} downloaded from {src} (zone: {zone_label})"
        else:
            msg = f"Mark-of-the-Web on {orig} (zone: {zone_label}, no source URL recorded)"

        event: dict[str, Any] = {
            "timestamp": ts,
            "timestamp_desc": "File Downloaded (Mark-of-the-Web)",
            "message": msg,
            "artifact_type": "mark_of_web",
            "file": {"name": orig},
            "mark_of_web": {
                "host_url": host_url,
                "referrer_url": referrer,
                "zone_id": zone_id,
                "zone": zone_label,
            },
            "raw": {"content": text.strip()},
        }

        host = _domain(host_url) or _domain(referrer)
        url_obj: dict[str, Any] = {}
        if host_url:
            url_obj["full"] = host_url
        if host:
            url_obj["domain"] = host
        if referrer:
            url_obj["referrer"] = referrer
        if url_obj:
            event["url"] = url_obj

        yield event

    def get_stats(self) -> dict[str, Any]:
        return {}
