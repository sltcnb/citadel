"""
iOS Plugin -- parses common iOS forensic artifacts.

Handles:
  - sms.db              (iMessage / SMS)
  - call_history.db     (call logs)
  - AddressBook.sqlitedb (contacts)
  - consolidated.db     (location data)
  - Safari/History.db   (Safari browsing history)
  - Safari/Bookmarks.db (Safari bookmarks)
  - com.apple.wifi.known-networks.plist / com.apple.wifi.plist (WiFi)
  - Info.plist          (device info)
  - Manifest.db         (iTunes backup manifest)

Uses only stdlib modules: sqlite3, plistlib.
"""

from __future__ import annotations

import json
import plistlib
import sqlite3
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# Apple Cocoa / Core Data epoch: 2001-01-01 00:00:00 UTC
_APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)


def _cocoa_to_iso(cocoa_ts: int | float | None) -> str:
    """Convert Apple Cocoa epoch timestamp (seconds since 2001-01-01) to ISO8601 UTC."""
    if cocoa_ts is None or cocoa_ts == 0:
        return ""
    try:
        dt = _APPLE_EPOCH + timedelta(seconds=float(cocoa_ts))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OSError, ValueError, OverflowError):
        return ""


def _cocoa_nano_to_iso(cocoa_ns: int | float | None) -> str:
    """Convert Apple Cocoa nanosecond timestamp to ISO8601 UTC."""
    if cocoa_ns is None or cocoa_ns == 0:
        return ""
    try:
        seconds = float(cocoa_ns) / 1e9
        dt = _APPLE_EPOCH + timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OSError, ValueError, OverflowError):
        return ""


def _unix_to_iso(ts: int | float | None) -> str:
    """Convert Unix epoch seconds to ISO8601 UTC."""
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(float(ts), tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OSError, ValueError, OverflowError):
        return ""


def _plist_date_to_iso(val: Any) -> str:
    """Convert a plist datetime object to ISO8601 string."""
    if val is None:
        return ""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=UTC)
        return val.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return ""


class IOSPlugin(BasePlugin):
    PLUGIN_NAME = "ios"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "ios"
    SUPPORTED_EXTENSIONS = []
    # Intentionally empty: iOS artifacts are heterogeneous (SQLite DBs + plists)
    # and indistinguishable by MIME alone. can_handle() matches by exact filename.
    SUPPORTED_MIME_TYPES: list[str] = []

    _KNOWN_FILES = {
        "SMS.DB",
        "CALL_HISTORY.DB",
        "ADDRESSBOOK.SQLITEDB",
        "CONSOLIDATED.DB",
        "MANIFEST.DB",
        "INFO.PLIST",
        "HISTORY.DB",
        "BOOKMARKS.DB",
        "COM.APPLE.WIFI.KNOWN-NETWORKS.PLIST",
        "COM.APPLE.WIFI.PLIST",
    }

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(cls._KNOWN_FILES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        """Only match specific known iOS artifact filenames."""
        return file_path.name.upper() in cls._KNOWN_FILES

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0

    def parse(self) -> Generator[dict[str, Any], None, None]:
        fp = self.ctx.source_file_path
        name_upper = fp.name.upper()

        # Route to the appropriate sub-parser
        if name_upper == "SMS.DB":
            yield from self._parse_sms()
        elif name_upper == "CALL_HISTORY.DB":
            yield from self._parse_calls()
        elif name_upper == "ADDRESSBOOK.SQLITEDB":
            yield from self._parse_contacts()
        elif name_upper == "CONSOLIDATED.DB":
            yield from self._parse_location()
        elif name_upper == "HISTORY.DB":
            yield from self._parse_safari_history()
        elif name_upper == "BOOKMARKS.DB":
            yield from self._parse_safari_bookmarks()
        elif name_upper in (
            "COM.APPLE.WIFI.KNOWN-NETWORKS.PLIST",
            "COM.APPLE.WIFI.PLIST",
        ):
            yield from self._parse_wifi_plist()
        elif name_upper == "INFO.PLIST":
            yield from self._parse_info_plist()
        elif name_upper == "MANIFEST.DB":
            yield from self._parse_manifest()
        else:
            raise PluginFatalError(f"iOS plugin cannot determine artifact type for: {fp.name}")

    # ------------------------------------------------------------------
    # iMessage / SMS  (sms.db)
    # ------------------------------------------------------------------
    def _parse_sms(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            # The main table in sms.db is 'message' joined with 'handle'
            try:
                cursor = conn.execute(
                    "SELECT m.ROWID, m.date, m.text, m.is_from_me, "
                    "m.is_read, m.service, m.cache_has_attachments, "
                    "h.id AS handle_id, h.service AS handle_service "
                    "FROM message m "
                    "LEFT JOIN handle h ON m.handle_id = h.ROWID "
                    "ORDER BY m.date"
                )
            except sqlite3.OperationalError:
                # Fallback for older iOS versions without handle table
                cursor = conn.execute(
                    "SELECT ROWID, date, text, is_from_me, is_read, "
                    "service, cache_has_attachments, address, '' "
                    "FROM message ORDER BY date"
                )

            for row in cursor:
                try:
                    (
                        row_id,
                        date_val,
                        text,
                        is_from_me,
                        is_read,
                        service,
                        has_attach,
                        handle_id,
                        handle_svc,
                    ) = row

                    # iOS timestamps: Cocoa epoch (seconds since 2001-01-01)
                    # Some newer iOS versions use nanoseconds
                    if date_val and abs(float(date_val)) > 1e15:
                        ts = _cocoa_nano_to_iso(date_val)
                    else:
                        ts = _cocoa_to_iso(date_val)

                    direction = "sent" if is_from_me else "received"
                    snippet = (text or "")[:120]
                    contact = handle_id or "unknown"
                    svc = service or handle_svc or ""
                    message = f"{'iMessage' if 'iMessage' in svc else 'SMS'} {direction}: {contact} - {snippet}"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "ios",
                        "timestamp": ts,
                        "timestamp_desc": "Message Date",
                        "message": message,
                        "ios": {
                            "data_type": "sms",
                            "message_id": row_id,
                            "date": ts,
                            "text": text or "",
                            "is_from_me": bool(is_from_me),
                            "is_read": bool(is_read),
                            "service": svc,
                            "has_attachments": bool(has_attach),
                            "handle": contact,
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "rowid": row_id,
                                    "date": date_val,
                                    "text": text,
                                    "is_from_me": is_from_me,
                                    "is_read": is_read,
                                    "service": service,
                                    "cache_has_attachments": has_attach,
                                    "handle_id": handle_id,
                                    "handle_service": handle_svc,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped SMS row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read SMS database: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Call History  (call_history.db)
    # ------------------------------------------------------------------
    def _parse_calls(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            # iOS call_history.db uses ZCALLRECORD table (CoreData)
            try:
                cursor = conn.execute(
                    "SELECT Z_PK, ZDATE, ZDURATION, ZADDRESS, "
                    "ZORIGINATED, ZANSWERED, ZCALLTYPE, "
                    "ZISO_COUNTRY_CODE, ZSERVICE_PROVIDER "
                    "FROM ZCALLRECORD ORDER BY ZDATE"
                )
            except sqlite3.OperationalError:
                # Older iOS format with 'call' table
                cursor = conn.execute(
                    "SELECT ROWID, date, duration, address, "
                    "flags, read, 0, country_code, '' "
                    "FROM call ORDER BY date"
                )

            for row in cursor:
                try:
                    (
                        row_id,
                        date_val,
                        duration,
                        address,
                        originated,
                        answered,
                        call_type,
                        country,
                        provider,
                    ) = row

                    ts = _cocoa_to_iso(date_val)
                    dur = int(duration or 0)

                    if originated:
                        direction = "outgoing"
                    elif answered:
                        direction = "incoming"
                    else:
                        direction = "missed"

                    display = address or "unknown"
                    message = f"Call {direction}: {display} (duration: {dur}s)"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "ios",
                        "timestamp": ts,
                        "timestamp_desc": "Call Date",
                        "message": message,
                        "ios": {
                            "data_type": "call",
                            "call_id": row_id,
                            "date": ts,
                            "duration_seconds": dur,
                            "address": address or "",
                            "direction": direction,
                            "originated": bool(originated),
                            "answered": bool(answered),
                            "call_type": call_type,
                            "country_iso": country or "",
                            "service_provider": provider or "",
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "rowid": row_id,
                                    "date": date_val,
                                    "duration": duration,
                                    "address": address,
                                    "originated": originated,
                                    "answered": answered,
                                    "call_type": call_type,
                                    "country_iso": country,
                                    "service_provider": provider,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped call row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read call history: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Contacts  (AddressBook.sqlitedb)
    # ------------------------------------------------------------------
    def _parse_contacts(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            # ABPerson table holds contact records
            persons = {}
            try:
                cursor = conn.execute(
                    "SELECT ROWID, First, Last, Organization, Department, "
                    "Birthday, CreationDate, ModificationDate "
                    "FROM ABPerson ORDER BY ROWID"
                )
            except sqlite3.OperationalError:
                raise PluginFatalError("ABPerson table not found in AddressBook.sqlitedb")

            for row in cursor:
                try:
                    row_id, first, last, org, dept, birthday, created, modified = row
                    persons[row_id] = {
                        "first": first or "",
                        "last": last or "",
                        "organization": org or "",
                        "department": dept or "",
                        "birthday": _cocoa_to_iso(birthday) if birthday else "",
                        "created": _cocoa_to_iso(created) if created else "",
                        "modified": _cocoa_to_iso(modified) if modified else "",
                        "phone_numbers": [],
                        "emails": [],
                    }
                except Exception:
                    self._records_skipped += 1

            # Collect phone numbers and emails from ABMultiValue
            try:
                mv_cursor = conn.execute("SELECT record_id, property, value FROM ABMultiValue")
                for mv_row in mv_cursor:
                    try:
                        rec_id, prop, value = mv_row
                        if rec_id in persons and value:
                            # property 3 = phone, property 4 = email
                            if prop == 3:
                                persons[rec_id]["phone_numbers"].append(value)
                            elif prop == 4:
                                persons[rec_id]["emails"].append(value)
                    except Exception:
                        pass
            except sqlite3.OperationalError:
                self.log.debug("ABMultiValue table not found, skipping extra fields")

            for pid, c in persons.items():
                name = f"{c['first']} {c['last']}".strip() or c["organization"] or f"Contact #{pid}"
                phones = ", ".join(c["phone_numbers"]) if c["phone_numbers"] else "none"
                message = f"Contact: {name} ({phones})"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "ios",
                    "timestamp": c["created"] or c["modified"],
                    "timestamp_desc": "Contact Creation Date",
                    "message": message,
                    "ios": {
                        "data_type": "contact",
                        "contact_id": pid,
                        "first_name": c["first"],
                        "last_name": c["last"],
                        "display_name": name,
                        "organization": c["organization"],
                        "department": c["department"],
                        "birthday": c["birthday"],
                        "phone_numbers": c["phone_numbers"],
                        "emails": c["emails"],
                        "created": c["created"],
                        "modified": c["modified"],
                    },
                    "raw": {"line": json.dumps({"contact_id": pid, **c}, default=str)},
                }
        except PluginFatalError:
            raise
        except Exception as exc:
            raise PluginFatalError(f"Cannot read contacts: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Location Data  (consolidated.db)
    # ------------------------------------------------------------------
    def _parse_location(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            # consolidated.db contains CellLocation, WifiLocation, etc.
            tables = [
                ("CellLocation", "Cell Tower"),
                ("WifiLocation", "WiFi"),
                ("CdmaCellLocation", "CDMA Cell"),
            ]
            for table_name, source_type in tables:
                try:
                    cursor = conn.execute(
                        f"SELECT Timestamp, Latitude, Longitude, "
                        f"HorizontalAccuracy, Altitude, Speed, Course, "
                        f"Confidence FROM {table_name} "
                        f"ORDER BY Timestamp"
                    )
                except sqlite3.OperationalError:
                    self.log.debug("Table %s not found, skipping", table_name)
                    continue

                for row in cursor:
                    try:
                        timestamp, lat, lon, accuracy, alt, speed, course, conf = row

                        ts = _cocoa_to_iso(timestamp)
                        if not ts:
                            continue

                        message = f"Location ({source_type}): lat={lat:.6f}, lon={lon:.6f}"
                        if accuracy:
                            message += f", accuracy={accuracy:.0f}m"

                        self._records_read += 1
                        yield {
                            "fo_id": str(uuid.uuid4()),
                            "artifact_type": "ios",
                            "timestamp": ts,
                            "timestamp_desc": f"{source_type} Location Fix",
                            "message": message,
                            "ios": {
                                "data_type": "location",
                                "source_type": source_type.lower().replace(" ", "_"),
                                "latitude": lat,
                                "longitude": lon,
                                "horizontal_accuracy": accuracy,
                                "altitude": alt,
                                "speed": speed,
                                "course": course,
                                "confidence": conf,
                            },
                            "raw": {
                                "line": json.dumps(
                                    {
                                        "Timestamp": timestamp,
                                        "Latitude": lat,
                                        "Longitude": lon,
                                        "HorizontalAccuracy": accuracy,
                                        "Altitude": alt,
                                        "Speed": speed,
                                        "Course": course,
                                        "Confidence": conf,
                                        "source_table": table_name,
                                    },
                                    default=str,
                                )
                            },
                        }
                    except Exception as exc:
                        self._records_skipped += 1
                        self.log.debug("Skipped location row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read location data: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Safari History  (History.db)
    # ------------------------------------------------------------------
    def _parse_safari_history(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            cursor = conn.execute(
                "SELECT hi.ROWID, hi.url, hv.visit_time, hv.title, "
                "hv.redirect_source, hv.redirect_destination "
                "FROM history_items hi "
                "JOIN history_visits hv ON hi.id = hv.history_item "
                "ORDER BY hv.visit_time"
            )
            for row in cursor:
                try:
                    row_id, url, visit_time, title, redirect_src, redirect_dst = row

                    ts = _cocoa_to_iso(visit_time)
                    display_title = title or url or "unknown"
                    message = f"Safari visit: {display_title}"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "ios",
                        "timestamp": ts,
                        "timestamp_desc": "Safari Visit Time",
                        "message": message,
                        "ios": {
                            "data_type": "safari",
                            "safari_type": "history",
                            "url": url or "",
                            "title": title or "",
                            "visit_time": ts,
                            "redirect_source": redirect_src,
                            "redirect_destination": redirect_dst,
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "rowid": row_id,
                                    "url": url,
                                    "visit_time": visit_time,
                                    "title": title,
                                    "redirect_source": redirect_src,
                                    "redirect_destination": redirect_dst,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped Safari history row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read Safari history: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Safari Bookmarks  (Bookmarks.db)
    # ------------------------------------------------------------------
    def _parse_safari_bookmarks(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            cursor = conn.execute(
                "SELECT id, title, url, parent, type, "
                "order_index, external_uuid "
                "FROM bookmarks WHERE url IS NOT NULL AND url != '' "
                "ORDER BY id"
            )
            for row in cursor:
                try:
                    bm_id, title, url, parent, bm_type, order_idx, ext_uuid = row

                    display_title = title or url or "unknown"
                    message = f"Safari bookmark: {display_title}"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "ios",
                        "timestamp": None,
                        "timestamp_desc": "Safari Bookmark",
                        "message": message,
                        "ios": {
                            "data_type": "safari",
                            "safari_type": "bookmark",
                            "bookmark_id": bm_id,
                            "title": title or "",
                            "url": url or "",
                            "parent_id": parent,
                            "bookmark_type": bm_type,
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "id": bm_id,
                                    "title": title,
                                    "url": url,
                                    "parent": parent,
                                    "type": bm_type,
                                    "order_index": order_idx,
                                    "external_uuid": ext_uuid,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped Safari bookmark row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read Safari bookmarks: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # WiFi Known Networks  (plist)
    # ------------------------------------------------------------------
    def _parse_wifi_plist(self) -> Generator[dict[str, Any], None, None]:
        plist_data = self._load_plist()

        # com.apple.wifi.known-networks.plist stores a dict keyed by SSID
        # com.apple.wifi.plist uses a "List of known networks" key
        networks = []

        if isinstance(plist_data, dict):
            # Try known-networks format (keyed by SSID)
            known = plist_data.get("wifi.network.ssid.list", plist_data)
            if isinstance(known, dict):
                for ssid, info in known.items():
                    if isinstance(info, dict):
                        networks.append((ssid, info))
                    else:
                        networks.append((ssid, {}))

            # Try legacy format
            net_list = plist_data.get("List of known networks", [])
            if isinstance(net_list, list):
                for net in net_list:
                    if isinstance(net, dict):
                        ssid = net.get("SSID_STR", net.get("SSIDString", "unknown"))
                        networks.append((ssid, net))

        for ssid, info in networks:
            try:
                last_joined = _plist_date_to_iso(info.get("lastJoined")) or _plist_date_to_iso(
                    info.get("LAST_JOINED")
                )
                last_auto_joined = _plist_date_to_iso(info.get("lastAutoJoined"))
                added_at = _plist_date_to_iso(info.get("addedAt"))
                security_type = info.get("SecurityType", info.get("SECURITY_TYPE", ""))
                was_captive = info.get("CaptiveBypass", info.get("wasCaptiveNetwork", False))

                ts = last_joined or added_at or ""
                message = f"WiFi network: {ssid}"
                if security_type:
                    message += f" ({security_type})"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "ios",
                    "timestamp": ts,
                    "timestamp_desc": "WiFi Last Joined",
                    "message": message,
                    "ios": {
                        "data_type": "wifi",
                        "ssid": ssid,
                        "security_type": str(security_type),
                        "last_joined": last_joined,
                        "last_auto_joined": last_auto_joined,
                        "added_at": added_at,
                        "was_captive": bool(was_captive),
                    },
                    "raw": {"line": json.dumps({"ssid": ssid, **info}, default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipped WiFi network entry: %s", exc)

    # ------------------------------------------------------------------
    # Device Info  (Info.plist)
    # ------------------------------------------------------------------
    def _parse_info_plist(self) -> Generator[dict[str, Any], None, None]:
        plist_data = self._load_plist()

        if not isinstance(plist_data, dict):
            raise PluginFatalError("Info.plist is not a dictionary")

        device_name = plist_data.get("Device Name", plist_data.get("DeviceName", ""))
        product_type = plist_data.get("Product Type", plist_data.get("ProductType", ""))
        product_version = plist_data.get("Product Version", plist_data.get("ProductVersion", ""))
        build_version = plist_data.get("Build Version", plist_data.get("BuildVersion", ""))
        serial_number = plist_data.get("Serial Number", plist_data.get("SerialNumber", ""))
        udid = plist_data.get("Unique Identifier", plist_data.get("UniqueDeviceID", ""))
        phone_number = plist_data.get("Phone Number", plist_data.get("PhoneNumber", ""))
        imei = plist_data.get("IMEI", plist_data.get("InternationalMobileEquipmentIdentity", ""))
        iccid = plist_data.get("ICCID", plist_data.get("IntegratedCircuitCardIdentity", ""))

        last_backup = _plist_date_to_iso(plist_data.get("Last Backup Date"))

        message = f"iOS Device: {device_name or product_type} (iOS {product_version})"

        self._records_read += 1
        yield {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "ios",
            "timestamp": last_backup,
            "timestamp_desc": "Last Backup Date",
            "message": message,
            "ios": {
                "data_type": "device_info",
                "device_name": device_name,
                "product_type": product_type,
                "product_version": product_version,
                "build_version": build_version,
                "serial_number": serial_number,
                "unique_device_id": udid,
                "phone_number": phone_number,
                "imei": imei,
                "iccid": iccid,
                "last_backup_date": last_backup,
            },
            "raw": {"line": json.dumps(plist_data, default=str)},
        }

    # ------------------------------------------------------------------
    # iTunes Backup Manifest  (Manifest.db)
    # ------------------------------------------------------------------
    def _parse_manifest(self) -> Generator[dict[str, Any], None, None]:
        conn = self._open_db()
        try:
            cursor = conn.execute(
                "SELECT fileID, domain, relativePath, flags, "
                "file AS file_blob "
                "FROM Files ORDER BY domain, relativePath"
            )
            for row in cursor:
                try:
                    file_id, domain, rel_path, flags, file_blob = row

                    # flags: 1=file, 2=directory, 4=symlink
                    entry_type = "file"
                    if flags == 2:
                        entry_type = "directory"
                    elif flags == 4:
                        entry_type = "symlink"

                    message = f"Backup entry ({entry_type}): {domain}/{rel_path}"

                    self._records_read += 1
                    yield {
                        "fo_id": str(uuid.uuid4()),
                        "artifact_type": "ios",
                        "timestamp": None,
                        "timestamp_desc": "Backup Manifest Entry",
                        "message": message,
                        "ios": {
                            "data_type": "manifest",
                            "file_id": file_id or "",
                            "domain": domain or "",
                            "relative_path": rel_path or "",
                            "entry_type": entry_type,
                            "flags": flags,
                        },
                        "raw": {
                            "line": json.dumps(
                                {
                                    "fileID": file_id,
                                    "domain": domain,
                                    "relativePath": rel_path,
                                    "flags": flags,
                                },
                                default=str,
                            )
                        },
                    }
                except Exception as exc:
                    self._records_skipped += 1
                    self.log.debug("Skipped manifest row: %s", exc)
        except Exception as exc:
            raise PluginFatalError(f"Cannot read Manifest.db: {exc}") from exc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _open_db(self) -> sqlite3.Connection:
        """Open a SQLite database with forensic-safe read-only settings."""
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

    def _load_plist(self) -> Any:
        """Load a plist file, handling both binary and XML formats."""
        try:
            with open(str(self.ctx.source_file_path), "rb") as f:
                return plistlib.load(f)
        except Exception as exc:
            raise PluginFatalError(
                f"Cannot parse plist {self.ctx.source_file_path.name}: {exc}"
            ) from exc

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
