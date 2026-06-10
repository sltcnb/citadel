"""
WLAN Profile Plugin — parses Windows Wireless LAN profile XML files.

Each .xml file in a wifi_profiles/ collection directory is one saved network.
Extracts SSID, authentication, encryption, connection type, and the non-secret
connection metadata. Never extracts WPA keys from <keyMaterial>.

artifact_type: "wlan_profile"
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginFatalError

_WLAN_NS = {
    "wlan": "http://www.microsoft.com/networking/WLAN/profile/v1",
    "wlan2": "http://www.microsoft.com/networking/WLAN/profile/v2",
}

_WLAN_MIME = "application/x-wlan-profile"


class WlanProfilePlugin(BasePlugin):
    """Parses Windows WLAN profile XML files collected from wifi_profiles/."""

    PLUGIN_NAME = "wlan_profile"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "wlan_profile"
    SUPPORTED_EXTENSIONS = [".xml"]
    SUPPORTED_MIME_TYPES = [_WLAN_MIME]
    PLUGIN_PRIORITY = 110  # above syslog and log2timeline

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        # Claimed via MIME (set by file_type._PATH_PART_MIME_MAP["wifi_profiles"])
        if mime_type == _WLAN_MIME:
            return True
        # Fallback: XML file whose path includes wifi_profiles
        if file_path.suffix.lower() == ".xml":
            parts_lower = {p.lower() for p in file_path.parts}
            if "wifi_profiles" in parts_lower:
                return True
            # Peek at content for WLANProfile root element
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(512)
                if "WLANProfile" in head:
                    return True
            except OSError:
                pass
        return False

    def setup(self) -> None:
        if not self.ctx.source_file_path.exists():
            raise PluginFatalError(f"File not found: {self.ctx.source_file_path}")

    def parse(self) -> Generator[dict[str, Any], None, None]:
        path = self.ctx.source_file_path
        try:
            tree = ET.parse(str(path))
        except ET.ParseError as exc:
            raise PluginFatalError(f"XML parse error in {path.name}: {exc}") from exc

        root = tree.getroot()

        # Strip namespace from tag for easier matching
        def _tag(element: ET.Element) -> str:
            return element.tag.split("}", 1)[-1] if "}" in element.tag else element.tag

        def _find(parent: ET.Element, *tags: str) -> str:
            for t in tags:
                for ns_prefix in ("wlan:", "wlan2:", ""):
                    el = parent.find(f".//{ns_prefix}{t}", _WLAN_NS)
                    if el is not None and el.text:
                        return el.text.strip()
            return ""

        ssid_hex = _find(root, "hex")
        ssid_name = _find(root, "name")
        connection_type = _find(root, "connectionType")
        connection_mode = _find(root, "connectionMode")
        auth = _find(root, "authentication")
        encryption = _find(root, "encryption")
        profile_name = _find(root, "profileName", "name")

        ssid = ssid_name or (
            bytes.fromhex(ssid_hex).decode("utf-8", errors="replace") if ssid_hex else path.stem
        )

        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
        except OSError:
            mtime = datetime.now(UTC).isoformat()

        # Preserve the full XML for forensic reproducibility — analysts may
        # need to re-validate auth chains, custom EAP configs, etc.
        try:
            raw_xml = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw_xml = ""

        profile_data = {
            "ssid": ssid,
            "ssid_hex": ssid_hex,
            "profile_name": profile_name or ssid,
            "connection_type": connection_type,
            "connection_mode": connection_mode,
            "authentication": auth,
            "encryption": encryption,
            "source_file": path.name,
        }

        yield {
            "timestamp": mtime,
            "timestamp_desc": "Profile File mtime",
            "message": f"WLAN profile: {ssid} ({auth}/{encryption}, {connection_mode or 'unknown'})",
            "artifact_type": "wlan_profile",
            "wlan_profile": profile_data,
            "network": {
                "ssid": ssid,
                "protocol": "wifi",
            },
            "raw": {**profile_data, "xml": raw_xml},
        }
