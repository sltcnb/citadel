"""
Android Plugin -- parses common Android forensic artifacts.

Handles:
  - mmssms.db     (SMS/MMS messages)
  - contacts2.db / contacts.db (contacts)
  - calllog.db    (call history)
  - external.db   (media scanner database)
  - packages.xml  (installed applications)
  - wpa_supplicant.conf / WiFi config files
  - bugreport-*.txt (Android bug reports)
  - *.ab          (Android backup files -- header parsing)

Uses only stdlib modules: sqlite3, xml.etree.ElementTree, struct.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError


# Android stores most timestamps as milliseconds since Unix epoch.
def _ms_to_iso(ms_value: int | float | None) -> str:
    """Convert milliseconds-since-epoch to ISO8601 UTC string."""
    if not ms_value:
        return ""
    try:
        ts = ms_value / 1000.0
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OSError, ValueError, OverflowError):
        return ""


def _sec_to_iso(sec_value: int | float | None) -> str:
    """Convert seconds-since-epoch to ISO8601 UTC string."""
    if not sec_value:
        return ""
    try:
        return datetime.fromtimestamp(float(sec_value), tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OSError, ValueError, OverflowError):
        return ""


# Call type mapping (Android content provider constants)
_CALL_TYPES = {
    1: "incoming",
    2: "outgoing",
    3: "missed",
    4: "voicemail",
    5: "rejected",
    6: "blocked",
}

# SMS type mapping
_SMS_TYPES = {
    1: "received",
    2: "sent",
    3: "draft",
    4: "outbox",
    5: "failed",
    6: "queued",
}


class AndroidPlugin(BasePlugin):
    PLUGIN_NAME = "android"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "android"
    SUPPORTED_EXTENSIONS = [
        ".ab"
    ]  # Only Android backup by extension; DB/XML files matched by exact filename
    # Android backup container (.ab). The per-app SQLite/XML artifacts are
    # claimed by exact filename, not MIME, because their content type is ambiguous.
    SUPPORTED_MIME_TYPES = ["application/x-android-backup"]

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return [
            "MMSSMS.DB",
            "CONTACTS2.DB",
            "CONTACTS.DB",
            "CALLLOG.DB",
            "EXTERNAL.DB",
            "PACKAGES.XML",
        ]

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        """Extended matching for WiFi configs, bug reports, and .ab files."""
        name_upper = file_path.name.upper()

        # Standard base matching
        if super().can_handle(file_path, mime_type):
            return True

        # WiFi config files — only match known Android WiFi config formats,
        # not arbitrary files that happen to contain "wifi" in the name (e.g. Apple .plist)
        if name_upper == "WPA_SUPPLICANT.CONF":
            return True
        if "wifi" in name_upper.lower() and file_path.suffix.lower() in (".conf", ".xml"):
            return True

        # Bug report files
        if name_upper.startswith("BUGREPORT") and file_path.suffix.lower() == ".txt":
            return True

        # Android backup files
        if file_path.suffix.lower() == ".ab":
            return True

        return False

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        name_upper = fp.name.upper()
        suffix = fp.suffix.lower()

        # Route to the appropriate sub-parser
        if name_upper == "MMSSMS.DB":
            yield from self._parse_sms()
        elif name_upper in ("CONTACTS2.DB", "CONTACTS.DB"):
            yield from self._parse_contacts()
        elif name_upper == "CALLLOG.DB":
            yield from self._parse_calllog()
        elif name_upper == "EXTERNAL.DB":
            yield from self._parse_media()
        elif name_upper == "PACKAGES.XML":
            yield from self._parse_packages()
        elif "WPA_SUPPLICANT" in name_upper or (
            "WIFI" in name_upper and suffix in (".conf", ".xml")
        ):
            yield from self._parse_wifi_config()
        elif name_upper.startswith("BUGREPORT") and suffix == ".txt":
            yield from self._parse_bugreport()
        elif suffix == ".ab":
            yield from self._parse_ab_backup()
        else:
            raise PluginFatalError(f"Android plugin cannot determine artifact type for: {fp.name}")

    # ------------------------------------------------------------------
    # SMS / MMS  (mmssms.db)
    # ------------------------------------------------------------------
    def _parse_sms(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            cursor = conn.execute(
                "SELECT _id, address, date, date_sent, read, type, body, "
                "thread_id, subject, service_center "
                "FROM sms ORDER BY date"
            )
            for row in cursor:
                try:
                    (
                        row_id,
                        address,
                        date_ms,
                        date_sent,
                        read,
                        sms_type,
                        body,
                        thread_id,
                        subject,
                        service_center,
                    ) = row

                    ts = _ms_to_iso(date_ms)
                    direction = _SMS_TYPES.get(sms_type, f"unknown({sms_type})")
                    snippet = (body or "")[:120]
                    message = f"SMS {direction}: {address or 'unknown'} - {snippet}"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "android",
                        "timestamp": ts,
                        "timestamp_desc": "SMS Date",
                        "message": message,
                        "android": {
                            "data_type": "sms",
                            "sms_id": row_id,
                            "address": address or "",
                            "date": ts,
                            "date_sent": _ms_to_iso(date_sent),
                            "read": bool(read),
                            "direction": direction,
                            "body": body or "",
                            "thread_id": thread_id,
                            "subject": subject or "",
                            "service_center": service_center or "",
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "_id": row_id,
                                    "address": address,
                                    "date": date_ms,
                                    "date_sent": date_sent,
                                    "read": read,
                                    "type": sms_type,
                                    "body": body,
                                    "thread_id": thread_id,
                                    "subject": subject,
                                    "service_center": service_center,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped SMS row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read SMS table: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Contacts  (contacts2.db / contacts.db)
    # ------------------------------------------------------------------
    def _parse_contacts(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            # Try the data view joining mimetype info
            try:
                cursor = conn.execute(
                    "SELECT d.raw_contact_id, d.data1, d.data2, d.data3, "
                    "d.data4, m.mimetype "
                    "FROM data d LEFT JOIN mimetypes m ON d.mimetype_id = m._id "
                    "ORDER BY d.raw_contact_id"
                )
            except sqlite3.OperationalError:
                # Fallback: simpler query if mimetypes table missing
                cursor = conn.execute(
                    "SELECT raw_contact_id, data1, data2, data3, data4, "
                    "'unknown' FROM data ORDER BY raw_contact_id"
                )

            # Group data rows by raw_contact_id
            contacts: dict[int, dict[str, Any]] = {}
            for row in cursor:
                try:
                    contact_id, data1, data2, data3, data4, mimetype = row
                    if contact_id not in contacts:
                        contacts[contact_id] = {
                            "contact_id": contact_id,
                            "display_name": "",
                            "phone_numbers": [],
                            "emails": [],
                            "organization": "",
                        }
                    c = contacts[contact_id]
                    mt = (mimetype or "").lower()

                    if "name" in mt and data1:
                        c["display_name"] = data1
                    elif "phone" in mt and data1:
                        c["phone_numbers"].append(data1)
                    elif "email" in mt and data1:
                        c["emails"].append(data1)
                    elif "organization" in mt and data1:
                        c["organization"] = data1
                    elif not c["display_name"] and data1 and "name" not in mt:
                        # best-effort name capture
                        pass
                except Exception:
                    self._records_skipped += 1

            for cid, c in contacts.items():
                name = c["display_name"] or f"Contact #{cid}"
                phones = ", ".join(c["phone_numbers"]) if c["phone_numbers"] else "none"
                message = f"Contact: {name} ({phones})"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "android",
                    "timestamp": None,
                    "timestamp_desc": "Contact Record",
                    "message": message,
                    "android": {
                        "data_type": "contact",
                        "contact_id": cid,
                        "display_name": name,
                        "phone_numbers": c["phone_numbers"],
                        "emails": c["emails"],
                        "organization": c["organization"],
                    },
                    "raw": {"line": json.dumps(c, default=str)},
                }
        except Exception as exc:
            raise PluginFatalError(f"Cannot read contacts: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Call Log  (calllog.db)
    # ------------------------------------------------------------------
    def _parse_calllog(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            cursor = conn.execute(
                "SELECT _id, number, date, duration, type, name, "
                "numbertype, countryiso, geocoded_location "
                "FROM calls ORDER BY date"
            )
            for row in cursor:
                try:
                    row_id, number, date_ms, duration, call_type, name, numbertype, country, geo = (
                        row
                    )

                    ts = _ms_to_iso(date_ms)
                    direction = _CALL_TYPES.get(call_type, f"unknown({call_type})")
                    dur = int(duration or 0)
                    display = name or number or "unknown"
                    message = f"Call {direction}: {display} (duration: {dur}s)"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "android",
                        "timestamp": ts,
                        "timestamp_desc": "Call Date",
                        "message": message,
                        "android": {
                            "data_type": "call",
                            "call_id": row_id,
                            "number": number or "",
                            "name": name or "",
                            "date": ts,
                            "duration_seconds": dur,
                            "direction": direction,
                            "call_type_raw": call_type,
                            "number_type": numbertype,
                            "country_iso": country or "",
                            "geocoded_location": geo or "",
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "_id": row_id,
                                    "number": number,
                                    "date": date_ms,
                                    "duration": duration,
                                    "type": call_type,
                                    "name": name,
                                    "numbertype": numbertype,
                                    "countryiso": country,
                                    "geocoded_location": geo,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped call log row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read call log: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Media Scanner DB  (external.db)
    # ------------------------------------------------------------------
    def _parse_media(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            # Try the 'files' table first (modern Android), fallback to 'audio'/'images'
            try:
                cursor = conn.execute(
                    "SELECT _id, _data, _display_name, _size, mime_type, "
                    "date_added, date_modified, title "
                    "FROM files ORDER BY date_added"
                )
            except sqlite3.OperationalError:
                cursor = conn.execute(
                    "SELECT _id, _data, _display_name, _size, mime_type, "
                    "date_added, date_modified, title "
                    "FROM audio ORDER BY date_added"
                )

            for row in cursor:
                try:
                    (
                        row_id,
                        data_path,
                        display_name,
                        size,
                        mime,
                        date_added,
                        date_modified,
                        title,
                    ) = row

                    ts = _sec_to_iso(date_added)
                    fname = display_name or title or (data_path or "").split("/")[-1]
                    message = f"Media file: {fname} ({mime or 'unknown type'})"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "android",
                        "timestamp": ts,
                        "timestamp_desc": "Media Date Added",
                        "message": message,
                        "android": {
                            "data_type": "media",
                            "media_id": row_id,
                            "file_path": data_path or "",
                            "display_name": fname,
                            "size_bytes": size,
                            "mime_type": mime or "",
                            "date_added": ts,
                            "date_modified": _sec_to_iso(date_modified),
                            "title": title or "",
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "_id": row_id,
                                    "_data": data_path,
                                    "_display_name": display_name,
                                    "_size": size,
                                    "mime_type": mime,
                                    "date_added": date_added,
                                    "date_modified": date_modified,
                                    "title": title,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped media row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read media database: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Installed Apps  (packages.xml)
    # ------------------------------------------------------------------
    def _parse_packages(self) -> Generator[dict[str, Any], None, None]:
        try:
            tree = ET.parse(str(self.ctx.source_file_path))
        except ET.ParseError as exc:
            raise PluginFatalError(f"Cannot parse packages.xml: {exc}") from exc

        root = tree.getroot()
        for pkg in root.iter("package"):
            try:
                name = pkg.get("name", "")
                code_path = pkg.get("codePath", "")
                version_code = pkg.get("version", "") or pkg.get("versionCode", "")
                version_name = pkg.get("versionName", "")
                install_time = pkg.get("it", "") or pkg.get("installTime", "")
                update_time = pkg.get("ut", "") or pkg.get("updateTime", "")
                user_id = pkg.get("userId", "")

                # Timestamps in packages.xml are hex ms-since-epoch
                ts = ""
                for raw_ts in (install_time, update_time):
                    if raw_ts:
                        try:
                            ms = int(raw_ts, 16) if raw_ts.startswith("0") else int(raw_ts)
                            ts = _ms_to_iso(ms)
                            break
                        except (ValueError, TypeError):
                            pass

                permissions: list[str] = []
                perms_elem = pkg.find("perms")
                if perms_elem is not None:
                    for item in perms_elem.iter("item"):
                        perm_name = item.get("name", "")
                        if perm_name:
                            permissions.append(perm_name)

                message = f"Installed app: {name} (v{version_name or version_code})"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "android",
                    "timestamp": ts,
                    "timestamp_desc": "App Install/Update Time",
                    "message": message,
                    "android": {
                        "data_type": "app",
                        "package_name": name,
                        "code_path": code_path,
                        "version_code": version_code,
                        "version_name": version_name,
                        "user_id": user_id,
                        "permissions": permissions,
                    },
                    "raw": {
                        "line": json.dumps({**pkg.attrib, "permissions": permissions}, default=str)
                    },
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped package entry: %s", exc)

    # ------------------------------------------------------------------
    # WiFi Config  (wpa_supplicant.conf or XML wifi configs)
    # ------------------------------------------------------------------
    def _parse_wifi_config(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path

        if fp.suffix.lower() == ".xml":
            yield from self._parse_wifi_xml()
        else:
            yield from self._parse_wifi_conf()

    def _parse_wifi_conf(self) -> Generator[dict[str, Any], None, None]:
        """Parse wpa_supplicant.conf format."""
        try:
            text = self.ctx.source_file_path.read_text(errors="replace")
        except Exception as exc:
            raise PluginFatalError(f"Cannot read WiFi config: {exc}") from exc

        # Extract network blocks
        blocks = re.findall(r"network\s*=\s*\{(.*?)\}", text, re.DOTALL)
        for block in blocks:
            try:
                fields: dict[str, str] = {}
                for line in block.strip().splitlines():
                    line = line.strip()
                    if "=" in line:
                        key, _, val = line.partition("=")
                        fields[key.strip()] = val.strip().strip('"')

                ssid = fields.get("ssid", "unknown")
                key_mgmt = fields.get("key_mgmt", "")
                psk = "present" if "psk" in fields else "none"
                message = f"WiFi network: {ssid} (key_mgmt={key_mgmt})"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "android",
                    "timestamp": None,
                    "timestamp_desc": "WiFi Configuration",
                    "message": message,
                    "android": {
                        "data_type": "wifi",
                        "ssid": ssid,
                        "key_mgmt": key_mgmt,
                        "psk_present": psk == "present",
                        "priority": fields.get("priority", ""),
                        "hidden_ssid": fields.get("scan_ssid", "") == "1",
                    },
                    "raw": {"line": json.dumps(fields, default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped WiFi block: %s", exc)

    def _parse_wifi_xml(self) -> Generator[dict[str, Any], None, None]:
        """Parse Android XML WiFi config (newer Android versions)."""
        try:
            tree = ET.parse(str(self.ctx.source_file_path))
        except ET.ParseError as exc:
            raise PluginFatalError(f"Cannot parse WiFi XML: {exc}") from exc

        root = tree.getroot()
        # Look for WifiConfiguration nodes
        for net in root.iter("WifiConfiguration"):
            try:
                ssid = ""
                key_mgmt = ""
                for child in net:
                    tag = child.tag or ""
                    val = child.get("value", child.text or "")
                    if "SSID" in tag.upper():
                        ssid = val.strip('"')
                    elif "KeyMgmt" in tag or "key_mgmt" in tag.lower():
                        key_mgmt = val

                if not ssid:
                    # Try string elements
                    for s in net.iter("string"):
                        name = s.get("name", "")
                        if name.upper() == "SSID":
                            ssid = (s.text or "").strip('"')

                message = f"WiFi network: {ssid or 'unknown'}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "android",
                    "timestamp": None,
                    "timestamp_desc": "WiFi Configuration",
                    "message": message,
                    "android": {
                        "data_type": "wifi",
                        "ssid": ssid,
                        "key_mgmt": key_mgmt,
                    },
                    "raw": {
                        "line": json.dumps(
                            {**net.attrib, "ssid": ssid, "key_mgmt": key_mgmt}, default=str
                        )
                    },
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped WiFi XML entry: %s", exc)

    # ------------------------------------------------------------------
    # Bug Report  (bugreport-*.txt)
    # ------------------------------------------------------------------
    def _parse_bugreport(self) -> Generator[dict[str, Any], None, None]:
        """Extract key metadata sections from an Android bug report."""
        try:
            text = self.ctx.source_file_path.read_text(errors="replace")
        except Exception as exc:
            raise PluginFatalError(f"Cannot read bug report: {exc}") from exc

        # Extract header info
        build_fingerprint = ""
        build_display = ""
        report_time = ""

        for line in text[:8192].splitlines():
            if line.startswith("Build:") or line.startswith("ro.build.display.id"):
                build_display = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif line.startswith("Build fingerprint:") or "ro.build.fingerprint" in line:
                build_fingerprint = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif line.startswith("Bugreport format version:"):
                pass
            elif "dumpstate:" in line.lower() and not report_time:
                # Try to extract timestamp from dumpstate header
                ts_match = re.search(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line)
                if ts_match:
                    try:
                        dt = datetime.strptime(ts_match.group(), "%Y-%m-%d %H:%M:%S")
                        report_time = dt.replace(tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                    except ValueError:
                        pass

        message = f"Android Bug Report: {build_display or build_fingerprint or self.ctx.source_file_path.name}"

        self._records_read += 1
        yield {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "android",
            "timestamp": report_time,
            "timestamp_desc": "Bug Report Time",
            "message": message,
            "android": {
                "data_type": "bugreport",
                "build_fingerprint": build_fingerprint,
                "build_display": build_display,
                "report_time": report_time,
                "file_size_bytes": self.ctx.source_file_path.stat().st_size,
            },
            "raw": {
                "line": json.dumps(
                    {
                        "build_fingerprint": build_fingerprint,
                        "build_display": build_display,
                        "report_time": report_time,
                        "filename": self.ctx.source_file_path.name,
                    },
                    default=str,
                )
            },
        }

    # ------------------------------------------------------------------
    # Android Backup (.ab)
    # ------------------------------------------------------------------
    def _parse_ab_backup(self) -> Generator[dict[str, Any], None, None]:
        """Parse the header of an Android .ab backup file."""
        try:
            with open(str(self.ctx.source_file_path), "rb") as f:
                header_bytes = f.read(512)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read .ab file: {exc}") from exc

        lines = header_bytes.split(b"\n", 5)
        magic = lines[0].decode("ascii", errors="replace").strip() if len(lines) > 0 else ""
        version = lines[1].decode("ascii", errors="replace").strip() if len(lines) > 1 else ""
        compressed = lines[2].decode("ascii", errors="replace").strip() if len(lines) > 2 else ""
        encryption = lines[3].decode("ascii", errors="replace").strip() if len(lines) > 3 else ""

        is_encrypted = encryption.lower() not in ("none", "0", "")
        file_size = self.ctx.source_file_path.stat().st_size

        message = f"Android Backup: v{version}, {'encrypted' if is_encrypted else 'unencrypted'}, {file_size} bytes"
        if is_encrypted:
            message += " (NOTE: backup is encrypted, data extraction requires passphrase)"

        self._records_read += 1
        yield {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "android",
            "timestamp": None,
            "timestamp_desc": "Android Backup",
            "message": message,
            "android": {
                "data_type": "backup",
                "magic": magic,
                "version": version,
                "compressed": compressed,
                "encryption": encryption,
                "is_encrypted": is_encrypted,
                "file_size_bytes": file_size,
            },
            "raw": {
                "line": json.dumps(
                    {
                        "magic": magic,
                        "version": version,
                        "compressed": compressed,
                        "encryption": encryption,
                        "is_encrypted": is_encrypted,
                        "file_size_bytes": file_size,
                    },
                    default=str,
                )
            },
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _open_db(self) -> sqlite3.Connection:
        """Open a SQLite database with forensic-safe settings."""
        try:
            conn = sqlite3.connect(
                f"file:{self.ctx.source_file_path}?mode=ro",
                uri=True,
            )
            conn.row_factory = None
            return conn
        except sqlite3.Error as exc:
            raise PluginFatalError(
                f"Cannot open SQLite database {self.ctx.source_file_path.name}: {exc}"
            ) from exc

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
