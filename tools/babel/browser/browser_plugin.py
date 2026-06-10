"""
Browser Plugin -- parses browser forensic artifacts from major browsers.

Supports: Chrome, Firefox, Brave, Opera, Edge, Safari.
Artifact types: History, Cookies, Downloads, Login Data, Bookmarks, Web Data,
                places.sqlite, cookies.sqlite, favicons.sqlite, formhistory.sqlite.

Uses stdlib sqlite3 for direct database parsing. Handles both Chromium WebKit
timestamps (microseconds since 1601-01-01) and Firefox timestamps (microseconds
since Unix epoch).
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from babel.base_plugin import (
    BasePlugin,
    PluginContext,
    PluginFatalError,
)

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

# Chromium / WebKit epoch: microseconds since 1601-01-01 00:00:00 UTC
_WEBKIT_EPOCH_DELTA_US = 11_644_473_600_000_000  # difference to Unix epoch in us


def _format_bytes(n: int) -> str:
    """Return a compact human-readable file size string (e.g. 1.4 MB)."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _webkit_to_iso(us: int | None) -> str:
    """Convert a Chromium/WebKit microsecond timestamp to ISO 8601 UTC string."""
    if not us or us <= 0:
        return ""
    try:
        unix_us = us - _WEBKIT_EPOCH_DELTA_US
        if unix_us < 0:
            return ""
        dt = datetime.fromtimestamp(unix_us / 1_000_000, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OSError, ValueError, OverflowError):
        return ""


def _firefox_us_to_iso(us: int | None) -> str:
    """Convert a Firefox microsecond timestamp (Unix epoch) to ISO 8601 UTC string."""
    if not us or us <= 0:
        return ""
    try:
        dt = datetime.fromtimestamp(us / 1_000_000, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OSError, ValueError, OverflowError):
        return ""


def _firefox_s_to_iso(s: int | float | None) -> str:
    """Convert a Firefox seconds-based timestamp to ISO 8601 UTC string."""
    if not s or s <= 0:
        return ""
    try:
        dt = datetime.fromtimestamp(float(s), tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OSError, ValueError, OverflowError):
        return ""


# ---------------------------------------------------------------------------
# Filename -> data_type / browser_family mapping
# ---------------------------------------------------------------------------

# Upper-case filenames that this plugin handles
_HANDLED_FILENAMES: list[str] = [
    "HISTORY",
    "COOKIES",
    "LOGIN DATA",
    "BOOKMARKS",
    "WEB DATA",
    "DOWNLOADS",
    "FAVICONS",  # Chrome: extensionless favicon database
    "SHORTCUTS",  # Chrome: address bar shortcut/autocomplete database
    "TOP SITES",  # Chrome: most-visited sites database
    "PLACES.SQLITE",
    "COOKIES.SQLITE",
    "FAVICONS.SQLITE",
    "FORMHISTORY.SQLITE",
    "DOWNLOADS.SQLITE",  # Firefox: download history
    "KEY4.DB",  # Firefox: password encryption keys (NSS key store)
]

# Chromium-family filenames (no extension, title-case)
_CHROMIUM_FILES = {
    "HISTORY",
    "COOKIES",
    "LOGIN DATA",
    "BOOKMARKS",
    "WEB DATA",
    "DOWNLOADS",
    "FAVICONS",
    "SHORTCUTS",
    "TOP SITES",
}
# Firefox-family filenames
_FIREFOX_FILES = {
    "PLACES.SQLITE",
    "COOKIES.SQLITE",
    "FAVICONS.SQLITE",
    "FORMHISTORY.SQLITE",
    "DOWNLOADS.SQLITE",
    "KEY4.DB",
}


def _detect_browser_family(filename_upper: str) -> str:
    """Return 'chromium' or 'firefox' based on the filename."""
    if filename_upper in _FIREFOX_FILES:
        return "firefox"
    return "chromium"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class BrowserPlugin(BasePlugin):
    PLUGIN_NAME = "browser"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "browser"
    SUPPORTED_EXTENSIONS: list[
        str
    ] = []  # Claim only by exact filename — no broad extension matching
    # Intentionally empty: browser stores are generic SQLite/JSON files whose
    # MIME is indistinguishable from unrelated databases. Matched by exact filename.
    SUPPORTED_MIME_TYPES: list[str] = []

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        return list(_HANDLED_FILENAMES)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        # Strict — claim only files we recognize by exact name. The previous
        # 'any SQLite file' catch-all hijacked unrelated databases (OneDrive
        # Microsoft.CDN_2.db, Microsoft.ListSync.db, …) and emitted 0 events,
        # which is worse than letting the generic SQLite/database plugin
        # handle them.
        return super().can_handle(file_path, mime_type)

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._records_read = 0
        self._records_skipped = 0
        self._conn: sqlite3.Connection | None = None
        self._tmp_path: Path | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Copy artifact to a temp file to avoid WAL/lock issues."""
        src = self.ctx.source_file_path
        if not src.exists():
            raise PluginFatalError(f"Source file does not exist: {src}")

        suffix = src.suffix or (".json" if src.name.upper() == "BOOKMARKS" else ".db")
        tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp.close()
        self._tmp_path = Path(tmp.name)
        try:
            shutil.copy2(str(src), str(self._tmp_path))
        except OSError as exc:
            raise PluginFatalError(f"Cannot copy file to temp: {exc}") from exc

        # BOOKMARKS (Chrome/Edge/Brave) is JSON — skip the SQLite connection
        if src.name.upper() == "BOOKMARKS":
            return

        try:
            self._conn = sqlite3.connect(
                f"file:{self._tmp_path}?mode=ro&nolock=1",
                uri=True,
                timeout=5,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("SELECT name FROM sqlite_master LIMIT 1")
        except sqlite3.DatabaseError as exc:
            raise PluginFatalError(f"Cannot open SQLite database: {exc}") from exc

    def teardown(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
        if self._tmp_path and self._tmp_path.exists():
            try:
                self._tmp_path.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Main parse dispatcher
    # ------------------------------------------------------------------

    def parse(self) -> Generator[dict[str, Any], None, None]:
        filename_upper = self.ctx.source_file_path.name.upper()
        # BOOKMARKS is JSON — no SQLite connection is needed
        if not self._conn and filename_upper != "BOOKMARKS":
            raise PluginFatalError("Database connection not available")

        family = _detect_browser_family(filename_upper)
        tables = self._list_tables()

        self.log.info(
            "Parsing %s (family=%s, tables=%s)",
            self.ctx.source_file_path.name,
            family,
            tables,
        )

        # Dispatch to the right parser(s) based on what tables exist
        if family == "firefox":
            yield from self._dispatch_firefox(filename_upper, tables)
        else:
            yield from self._dispatch_chromium(filename_upper, tables)

    def _list_tables(self) -> set[str]:
        """Return the set of table names in the database."""
        assert self._conn
        try:
            rows = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            return {r[0] for r in rows}
        except sqlite3.DatabaseError:
            return set()

    # ------------------------------------------------------------------
    # Chromium dispatcher
    # ------------------------------------------------------------------

    def _dispatch_chromium(
        self, filename_upper: str, tables: set[str]
    ) -> Generator[dict[str, Any], None, None]:
        # History file contains urls + visits tables
        if filename_upper == "HISTORY" or ("urls" in tables and "visits" in tables):
            yield from self._parse_chromium_history(tables)
            if "downloads" in tables:
                yield from self._parse_chromium_downloads(tables)

        elif filename_upper == "DOWNLOADS" and "downloads" in tables:
            yield from self._parse_chromium_downloads(tables)

        elif filename_upper == "COOKIES" or "cookies" in tables:
            yield from self._parse_chromium_cookies(tables)

        elif filename_upper == "LOGIN DATA" or "logins" in tables:
            yield from self._parse_chromium_logins(tables)

        elif filename_upper == "WEB DATA":
            if "autofill" in tables:
                yield from self._parse_chromium_autofill(tables)

        elif filename_upper == "BOOKMARKS":
            # Chromium Bookmarks is JSON, not SQLite -- handle gracefully
            yield from self._parse_chromium_bookmarks_json()

        elif filename_upper in ("FAVICONS", "FAVICONS.SQLITE"):
            yield from self._parse_chromium_favicons(tables)

        elif filename_upper == "SHORTCUTS":
            yield from self._parse_chromium_shortcuts(tables)

        elif filename_upper == "TOP SITES":
            yield from self._parse_chromium_top_sites(tables)

    # ------------------------------------------------------------------
    # Chromium: History (urls + visits)
    # ------------------------------------------------------------------

    def _parse_chromium_history(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT
                v.visit_time,
                u.url,
                u.title,
                u.visit_count,
                u.typed_count,
                u.last_visit_time,
                v.transition
            FROM visits v
            JOIN urls u ON v.url = u.id
            ORDER BY v.visit_time ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Chromium history query failed: %s", exc)
            return

        for row in cursor:
            try:
                visit_time = row["visit_time"]
                ts = _webkit_to_iso(visit_time)
                url = row["url"] or ""
                title = row["title"] or ""
                visit_count = row["visit_count"] or 0
                typed_count = row["typed_count"] or 0
                transition = row["transition"] or 0

                # Decode Chromium page transition bitmask
                transition_core = transition & 0xFF
                transition_names = {
                    0: "link",
                    1: "typed",
                    2: "auto_bookmark",
                    3: "auto_subframe",
                    4: "manual_subframe",
                    5: "generated",
                    6: "start_page",
                    7: "form_submit",
                    8: "reload",
                    9: "keyword",
                    10: "keyword_generated",
                }
                transition_str = transition_names.get(transition_core, str(transition_core))

                # Build rich message: how navigated, title, full URL, visit count
                visit_label = f"{visit_count}×" if visit_count > 1 else "1×"
                typed_label = " [typed]" if transition_str == "typed" or typed_count else ""
                title_part = f"{title} — " if title and title != url else ""
                message = f"[{visit_label}{typed_label}] {title_part}{url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "URL Visit Time",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "history",
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "typed_count": typed_count,
                        "transition": transition_str,
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium history row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Downloads
    # ------------------------------------------------------------------

    def _parse_chromium_downloads(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT
                start_time, end_time, tab_url, current_path,
                target_path, total_bytes, received_bytes,
                danger_type, interrupt_reason, mime_type, state
            FROM downloads
            ORDER BY start_time ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Chromium downloads query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _webkit_to_iso(row["start_time"])
                tab_url = row["tab_url"] or ""
                target_path = row["target_path"] or row["current_path"] or ""
                total_bytes = row["total_bytes"] or 0
                received_bytes = row["received_bytes"] or 0
                mime_type = row["mime_type"] or ""
                state = row["state"]
                danger = row["danger_type"] or 0

                state_names = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}
                state_str = state_names.get(state, str(state))

                danger_names = {
                    0: "not_dangerous",
                    1: "dangerous_file",
                    2: "dangerous_url",
                    3: "dangerous_content",
                    4: "maybe_dangerous_content",
                    5: "uncommon_content",
                    6: "user_validated",
                    7: "dangerous_host",
                    8: "potentially_unwanted",
                }
                danger_str = danger_names.get(danger, str(danger))

                filename = Path(target_path).name if target_path else ""

                # Build rich message: filename, size, source URL, danger flag
                size_str = _format_bytes(total_bytes) if total_bytes else ""
                size_part = f" ({size_str})" if size_str else ""
                src_part = f" from {tab_url}" if tab_url else ""
                danger_part = f" ⚠ {danger_str}" if danger > 0 else ""
                message = f"Downloaded: {filename or tab_url}{size_part}{src_part}{danger_part}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Download Start Time",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "download",
                        "url": tab_url,
                        "target_path": target_path,
                        "filename": filename,
                        "total_bytes": total_bytes,
                        "received_bytes": received_bytes,
                        "mime_type": mime_type,
                        "state": state_str,
                        "danger_type": danger_str,
                        "end_time": _webkit_to_iso(row["end_time"]),
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium download row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Cookies
    # ------------------------------------------------------------------

    def _parse_chromium_cookies(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        # Chromium cookie schema varies across versions; detect columns
        try:
            info = self._conn.execute("PRAGMA table_info(cookies)").fetchall()
        except sqlite3.DatabaseError:
            return
        col_names = {r["name"] for r in info}

        # Build a safe SELECT with available columns
        cols = ["creation_utc", "host_key", "name", "path"]
        if "expires_utc" in col_names:
            cols.append("expires_utc")
        if "last_access_utc" in col_names:
            cols.append("last_access_utc")
        if "last_update_utc" in col_names:
            cols.append("last_update_utc")
        if "is_secure" in col_names:
            cols.append("is_secure")
        if "is_httponly" in col_names:
            cols.append("is_httponly")
        if "samesite" in col_names:
            cols.append("samesite")
        if "source_scheme" in col_names:
            cols.append("source_scheme")
        if "is_persistent" in col_names:
            cols.append("is_persistent")

        query = f"SELECT {', '.join(cols)} FROM cookies ORDER BY creation_utc ASC"
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Chromium cookies query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _webkit_to_iso(row["creation_utc"])
                host = row["host_key"] or ""
                name = row["name"] or ""
                path = row["path"] or ""

                cookie_data: dict[str, Any] = {
                    "browser_type": "chromium",
                    "data_type": "cookie",
                    "host": host,
                    "cookie_name": name,
                    "path": path,
                    "creation_utc": ts,
                }
                if "expires_utc" in col_names:
                    cookie_data["expires_utc"] = _webkit_to_iso(row["expires_utc"])
                if "last_access_utc" in col_names:
                    cookie_data["last_access_utc"] = _webkit_to_iso(row["last_access_utc"])
                if "last_update_utc" in col_names:
                    cookie_data["last_update_utc"] = _webkit_to_iso(row["last_update_utc"])
                if "is_secure" in col_names:
                    cookie_data["is_secure"] = bool(row["is_secure"])
                if "is_httponly" in col_names:
                    cookie_data["is_httponly"] = bool(row["is_httponly"])

                message = f"Cookie: {name} on {host}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Cookie Creation Time",
                    "message": message,
                    "browser": cookie_data,
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium cookie row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Login Data
    # ------------------------------------------------------------------

    def _parse_chromium_logins(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT
                date_created, date_last_used, origin_url, action_url,
                username_value, signon_realm, times_used, date_password_modified
            FROM logins
            ORDER BY date_created ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Chromium logins query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _webkit_to_iso(row["date_created"])
                origin_url = row["origin_url"] or ""
                action_url = row["action_url"] or ""
                username = row["username_value"] or ""
                signon_realm = row["signon_realm"] or ""
                times_used = row["times_used"] or 0

                message = f"Saved login: {username} on {signon_realm}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Login Entry Created",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "login",
                        "url": origin_url,
                        "action_url": action_url,
                        "username": username,
                        "signon_realm": signon_realm,
                        "times_used": times_used,
                        "date_last_used": _webkit_to_iso(row["date_last_used"]),
                        "date_password_modified": _webkit_to_iso(row["date_password_modified"]),
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium login row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Autofill (Web Data)
    # ------------------------------------------------------------------

    def _parse_chromium_autofill(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT name, value, count, date_created, date_last_used
            FROM autofill
            ORDER BY date_created ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Chromium autofill query failed: %s", exc)
            return

        for row in cursor:
            try:
                # Autofill date_created can be seconds or WebKit depending on version
                raw_created = row["date_created"] or 0
                if raw_created > 1_000_000_000_000_000:
                    ts = _webkit_to_iso(raw_created)
                elif raw_created > 1_000_000_000:
                    ts = _firefox_s_to_iso(raw_created)
                else:
                    ts = ""

                name_field = row["name"] or ""
                value_field = row["value"] or ""
                count = row["count"] or 0

                message = f"Autofill: {name_field}={value_field[:64]}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Autofill Entry Created",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "autofill",
                        "field_name": name_field,
                        "field_value": value_field[:512],
                        "usage_count": count,
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium autofill row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Bookmarks (JSON file, not SQLite)
    # ------------------------------------------------------------------

    def _parse_chromium_bookmarks_json(
        self,
    ) -> Generator[dict[str, Any], None, None]:
        """Parse Chromium Bookmarks file, which is JSON not SQLite."""
        # Close the SQLite connection since this is a JSON file
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

        src = self._tmp_path or self.ctx.source_file_path
        try:
            data = json.loads(src.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as exc:
            self.log.warning("Cannot parse Bookmarks JSON: %s", exc)
            return

        roots = data.get("roots", {})
        for root_name, root_node in roots.items():
            if isinstance(root_node, dict):
                yield from self._walk_bookmark_node(root_node, root_name)

    def _walk_bookmark_node(self, node: dict, path: str) -> Generator[dict[str, Any], None, None]:
        node_type = node.get("type", "")
        name = node.get("name", "")
        current_path = f"{path}/{name}" if name else path

        if node_type == "url":
            url = node.get("url", "")
            # date_added is WebKit microsecond timestamp
            date_added = node.get("date_added")
            ts = ""
            if date_added:
                try:
                    ts = _webkit_to_iso(int(date_added))
                except (ValueError, TypeError):
                    pass

            message = f"Bookmark: {name or url}"

            self._records_read += 1
            yield {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "browser",
                "timestamp": ts,
                "timestamp_desc": "Bookmark Added",
                "message": message,
                "browser": {
                    "browser_type": "chromium",
                    "data_type": "bookmark",
                    "url": url,
                    "title": name,
                    "bookmark_path": current_path,
                },
                "raw": {"line": json.dumps(node, default=str)},
            }

        children = node.get("children", [])
        for child in children:
            if isinstance(child, dict):
                yield from self._walk_bookmark_node(child, current_path)

    # ------------------------------------------------------------------
    # Firefox dispatcher
    # ------------------------------------------------------------------

    def _dispatch_firefox(
        self, filename_upper: str, tables: set[str]
    ) -> Generator[dict[str, Any], None, None]:
        if filename_upper == "PLACES.SQLITE":
            if "moz_places" in tables and "moz_historyvisits" in tables:
                yield from self._parse_firefox_history(tables)
            if "moz_bookmarks" in tables:
                yield from self._parse_firefox_bookmarks(tables)
            if "moz_annos" in tables:
                yield from self._parse_firefox_downloads_annos(tables)

        elif filename_upper == "COOKIES.SQLITE" and "moz_cookies" in tables:
            yield from self._parse_firefox_cookies(tables)

        elif filename_upper == "FORMHISTORY.SQLITE" and "moz_formhistory" in tables:
            yield from self._parse_firefox_formhistory(tables)

        elif filename_upper == "FAVICONS.SQLITE":
            if "moz_icons" in tables:
                yield from self._parse_firefox_favicons(tables)

    # ------------------------------------------------------------------
    # Firefox: History (moz_places + moz_historyvisits)
    # ------------------------------------------------------------------

    def _parse_firefox_history(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT
                v.visit_date,
                p.url,
                p.title,
                p.visit_count,
                p.typed,
                p.frecency,
                v.visit_type
            FROM moz_historyvisits v
            JOIN moz_places p ON v.place_id = p.id
            ORDER BY v.visit_date ASC
        """
        visit_type_names = {
            1: "link",
            2: "typed",
            3: "bookmark",
            4: "embed",
            5: "redirect_permanent",
            6: "redirect_temporary",
            7: "download",
            8: "framed_link",
        }

        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Firefox history query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _firefox_us_to_iso(row["visit_date"])
                url = row["url"] or ""
                title = row["title"] or ""
                visit_count = row["visit_count"] or 0
                typed = row["typed"] or 0
                visit_type = row["visit_type"] or 0

                visit_label = f"{visit_count}×" if visit_count > 1 else "1×"
                typed_label = " [typed]" if typed else ""
                title_part = f"{title} — " if title and title != url else ""
                message = f"[{visit_label}{typed_label}] {title_part}{url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "URL Visit Time",
                    "message": message,
                    "browser": {
                        "browser_type": "firefox",
                        "data_type": "history",
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "typed_count": typed,
                        "transition": visit_type_names.get(visit_type, str(visit_type)),
                        "frecency": row["frecency"] or 0,
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping firefox history row: %s", exc)

    # ------------------------------------------------------------------
    # Firefox: Bookmarks (moz_bookmarks + moz_places)
    # ------------------------------------------------------------------

    def _parse_firefox_bookmarks(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT
                b.dateAdded,
                b.lastModified,
                b.title AS bookmark_title,
                b.type,
                p.url
            FROM moz_bookmarks b
            LEFT JOIN moz_places p ON b.fk = p.id
            WHERE b.type = 1
            ORDER BY b.dateAdded ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Firefox bookmarks query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _firefox_us_to_iso(row["dateAdded"])
                url = row["url"] or ""
                title = row["bookmark_title"] or ""

                message = f"Bookmark: {title or url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Bookmark Added",
                    "message": message,
                    "browser": {
                        "browser_type": "firefox",
                        "data_type": "bookmark",
                        "url": url,
                        "title": title,
                        "last_modified": _firefox_us_to_iso(row["lastModified"]),
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping firefox bookmark row: %s", exc)

    # ------------------------------------------------------------------
    # Firefox: Downloads via moz_annos (legacy) + moz_places
    # ------------------------------------------------------------------

    def _parse_firefox_downloads_annos(
        self, tables: set[str]
    ) -> Generator[dict[str, Any], None, None]:
        """Parse Firefox downloads from moz_annos annotations table."""
        assert self._conn
        query = """
            SELECT
                a.dateAdded,
                a.content,
                an.name AS anno_name,
                p.url
            FROM moz_annos a
            JOIN moz_anno_attributes an ON a.anno_attribute_id = an.id
            JOIN moz_places p ON a.place_id = p.id
            WHERE an.name LIKE '%download%'
            ORDER BY a.dateAdded ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.debug("Firefox downloads annos query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _firefox_us_to_iso(row["dateAdded"])
                url = row["url"] or ""
                content = row["content"] or ""
                anno_name = row["anno_name"] or ""

                message = f"Download annotation ({anno_name}): {url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Download Annotation Time",
                    "message": message,
                    "browser": {
                        "browser_type": "firefox",
                        "data_type": "download",
                        "url": url,
                        "annotation_name": anno_name,
                        "annotation_content": content[:1024],
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping firefox download anno row: %s", exc)

    # ------------------------------------------------------------------
    # Firefox: Cookies (moz_cookies)
    # ------------------------------------------------------------------

    def _parse_firefox_cookies(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        # Detect available columns (schema varies by version)
        try:
            info = self._conn.execute("PRAGMA table_info(moz_cookies)").fetchall()
        except sqlite3.DatabaseError:
            return
        col_names = {r["name"] for r in info}

        cols = ["creationTime", "host", "name", "path"]
        if "expiry" in col_names:
            cols.append("expiry")
        if "lastAccessed" in col_names:
            cols.append("lastAccessed")
        if "isSecure" in col_names:
            cols.append("isSecure")
        if "isHttpOnly" in col_names:
            cols.append("isHttpOnly")
        if "sameSite" in col_names:
            cols.append("sameSite")

        query = f"SELECT {', '.join(cols)} FROM moz_cookies ORDER BY creationTime ASC"
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Firefox cookies query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _firefox_us_to_iso(row["creationTime"])
                host = row["host"] or ""
                name = row["name"] or ""
                path = row["path"] or ""

                cookie_data: dict[str, Any] = {
                    "browser_type": "firefox",
                    "data_type": "cookie",
                    "host": host,
                    "cookie_name": name,
                    "path": path,
                    "creation_time": ts,
                }
                if "expiry" in col_names:
                    cookie_data["expiry"] = _firefox_s_to_iso(row["expiry"])
                if "lastAccessed" in col_names:
                    cookie_data["last_accessed"] = _firefox_us_to_iso(row["lastAccessed"])
                if "isSecure" in col_names:
                    cookie_data["is_secure"] = bool(row["isSecure"])
                if "isHttpOnly" in col_names:
                    cookie_data["is_httponly"] = bool(row["isHttpOnly"])

                message = f"Cookie: {name} on {host}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Cookie Creation Time",
                    "message": message,
                    "browser": cookie_data,
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping firefox cookie row: %s", exc)

    # ------------------------------------------------------------------
    # Firefox: Form History (moz_formhistory)
    # ------------------------------------------------------------------

    def _parse_firefox_formhistory(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT fieldname, value, timesUsed, firstUsed, lastUsed
            FROM moz_formhistory
            ORDER BY firstUsed ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.warning("Firefox form history query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _firefox_us_to_iso(row["firstUsed"])
                fieldname = row["fieldname"] or ""
                value = row["value"] or ""
                times_used = row["timesUsed"] or 0

                message = f"Form field: {fieldname}={value[:64]}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Form Entry First Used",
                    "message": message,
                    "browser": {
                        "browser_type": "firefox",
                        "data_type": "formhistory",
                        "field_name": fieldname,
                        "field_value": value[:512],
                        "usage_count": times_used,
                        "last_used": _firefox_us_to_iso(row["lastUsed"]),
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping firefox formhistory row: %s", exc)

    # ------------------------------------------------------------------
    # Firefox: Favicons (moz_icons)
    # ------------------------------------------------------------------

    def _parse_firefox_favicons(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        query = """
            SELECT icon_url, fixed_icon_url_hash, width, expire_ms
            FROM moz_icons
            ORDER BY expire_ms ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.debug("Firefox favicons query failed: %s", exc)
            return

        for row in cursor:
            try:
                # expire_ms is milliseconds since Unix epoch
                expire_ms = row["expire_ms"] or 0
                ts = ""
                if expire_ms > 0:
                    try:
                        dt = datetime.fromtimestamp(expire_ms / 1000, tz=UTC)
                        ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
                    except (OSError, ValueError, OverflowError):
                        pass

                icon_url = row["icon_url"] or ""
                width = row["width"] or 0

                message = f"Favicon: {icon_url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Favicon Expiry Time",
                    "message": message,
                    "browser": {
                        "browser_type": "firefox",
                        "data_type": "favicon",
                        "url": icon_url,
                        "width": width,
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping firefox favicon row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Favicons (icon_mapping + favicons tables)
    # ------------------------------------------------------------------

    def _parse_chromium_favicons(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        # icon_mapping maps page URLs to favicon IDs
        if "icon_mapping" not in tables or "favicons" not in tables:
            return
        query = """
            SELECT im.page_url, f.url AS icon_url, f.expiry
            FROM icon_mapping im
            LEFT JOIN favicons f ON im.icon_id = f.id
            ORDER BY im.id ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.debug("Chromium favicons query failed: %s", exc)
            return

        for row in cursor:
            try:
                page_url = row["page_url"] or ""
                icon_url = row["icon_url"] or ""
                expiry = row["expiry"] or 0
                ts = _webkit_to_iso(expiry) if expiry else ""

                message = f"Favicon cached for: {page_url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Favicon Cache Entry",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "favicon",
                        "page_url": page_url,
                        "icon_url": icon_url,
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium favicon row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Shortcuts (address bar autocomplete)
    # ------------------------------------------------------------------

    def _parse_chromium_shortcuts(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        if "omni_box_shortcuts" not in tables:
            return
        query = """
            SELECT text, fill_into_edit, url, contents, last_access_time, number_of_hits
            FROM omni_box_shortcuts
            ORDER BY last_access_time ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.debug("Chromium shortcuts query failed: %s", exc)
            return

        for row in cursor:
            try:
                ts = _webkit_to_iso(row["last_access_time"])
                text = row["text"] or ""
                url = row["url"] or ""
                contents = row["contents"] or ""
                hits = row["number_of_hits"] or 0

                message = f"Address bar shortcut: {text} → {url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": ts,
                    "timestamp_desc": "Shortcut Last Access",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "shortcut",
                        "typed_text": text,
                        "fill_into_edit": row["fill_into_edit"] or "",
                        "url": url,
                        "display_text": contents,
                        "hit_count": hits,
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium shortcut row: %s", exc)

    # ------------------------------------------------------------------
    # Chromium: Top Sites (most-visited thumbnail database)
    # ------------------------------------------------------------------

    def _parse_chromium_top_sites(self, tables: set[str]) -> Generator[dict[str, Any], None, None]:
        assert self._conn
        if "top_sites" not in tables:
            return
        query = """
            SELECT url, url_rank, title, redirects
            FROM top_sites
            ORDER BY url_rank ASC
        """
        try:
            cursor = self._conn.execute(query)
        except sqlite3.DatabaseError as exc:
            self.log.debug("Chromium top sites query failed: %s", exc)
            return

        for row in cursor:
            try:
                url = row["url"] or ""
                title = row["title"] or ""
                rank = row["url_rank"] or 0

                message = f"Top site #{rank}: {title or url}"

                self._records_read += 1
                yield {
                    "fo_id": str(uuid.uuid4()),
                    "artifact_type": "browser",
                    "timestamp": None,
                    "timestamp_desc": "Top Site",
                    "message": message,
                    "browser": {
                        "browser_type": "chromium",
                        "data_type": "top_site",
                        "url": url,
                        "title": title,
                        "rank": rank,
                        "redirects": row["redirects"] or "",
                    },
                    "raw": {"line": json.dumps(dict(row), default=str)},
                }
            except Exception as exc:
                self._records_skipped += 1
                self.log.debug("Skipping chromium top site row: %s", exc)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_read": self._records_read,
            "records_skipped": self._records_skipped,
        }
