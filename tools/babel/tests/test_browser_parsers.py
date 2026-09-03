"""Contract tests for the browser parser across all three browser families.

Safari and the macOS LaunchServices quarantine database were collected by Talon
but had no parser branch — History.db was not even in the handled-filename set,
so `can_handle` returned False and every macOS browsing timeline came back
empty. These tests pin the parse→indexable-event contract for all three
families, plus the download-provenance fields the "what did it touch after it
landed" pivots key on (domain, host_is_ip, target_path, filename).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from babel.base_plugin import PluginContext
from babel.browser.browser_plugin import BrowserPlugin

# 2026-03-04T09:12:33Z expressed in each family's own epoch.
_WHEN = datetime(2026, 3, 4, 9, 12, 33, tzinfo=UTC)
_WEBKIT_US = int((_WHEN - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 1_000_000)
_FIREFOX_US = int(_WHEN.timestamp() * 1_000_000)
_MAC_ABS_S = _WHEN.timestamp() - datetime(2001, 1, 1, tzinfo=UTC).timestamp()


def _ctx(path):
    return PluginContext(case_id="c", job_id="j", source_file_path=path, source_minio_url="")


def _events(path):
    plugin = BrowserPlugin(_ctx(path))
    plugin.setup()
    try:
        return list(plugin.parse())
    finally:
        plugin.teardown()


def _by_type(events, data_type):
    return [e for e in events if e["browser"]["data_type"] == data_type]


# ── Safari: History.db ────────────────────────────────────────────────────────
def test_safari_history_and_tombstones(tmp_path):
    f = tmp_path / "History.db"
    con = sqlite3.connect(f)
    con.execute(
        "CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, "
        "domain_expansion TEXT, visit_count INTEGER)"
    )
    con.execute(
        "CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, "
        "visit_time REAL, title TEXT, load_successful INTEGER, http_non_get INTEGER, "
        "origin INTEGER, redirect_source INTEGER, redirect_destination INTEGER)"
    )
    con.execute("CREATE TABLE history_tombstones(id INTEGER PRIMARY KEY, "
                "start_time REAL, end_time REAL, url TEXT, generation INTEGER)")
    con.execute(
        "INSERT INTO history_items VALUES(1, 'https://updates.miniwakaya.xyz/stage2', "
        "'miniwakaya', 3)"
    )
    con.execute(
        "INSERT INTO history_visits VALUES(1, 1, ?, 'Stage 2', 1, 0, 0, NULL, NULL)",
        (_MAC_ABS_S,),
    )
    con.execute(
        "INSERT INTO history_tombstones VALUES(1, ?, ?, 'https://updates.miniwakaya.xyz/drop', 1)",
        (_MAC_ABS_S, _MAC_ABS_S),
    )
    con.commit()
    con.close()

    assert BrowserPlugin.can_handle(f, "application/vnd.sqlite3")
    events = _events(f)

    hist = _by_type(events, "history")
    assert len(hist) == 1
    b = hist[0]["browser"]
    assert hist[0]["artifact_type"] == "browser"
    assert b["browser_type"] == "safari"
    assert b["url"] == "https://updates.miniwakaya.xyz/stage2"
    assert b["domain"] == "updates.miniwakaya.xyz"
    assert b["host_is_ip"] is False
    assert b["visit_count"] == 3
    assert hist[0]["timestamp"].startswith("2026-03-04T09:12:33")
    assert hist[0]["timestamp"].endswith("Z")

    # Deleted history is evidence in its own right.
    gone = _by_type(events, "history_deleted")
    assert len(gone) == 1
    assert gone[0]["browser"]["url"].endswith("/drop")


# ── macOS: LaunchServices quarantine ─────────────────────────────────────────
def test_launchservices_quarantine(tmp_path):
    f = tmp_path / "quarantine_events.sqlite"
    con = sqlite3.connect(f)
    con.execute(
        "CREATE TABLE LSQuarantineEvent("
        "LSQuarantineEventIdentifier TEXT PRIMARY KEY, LSQuarantineTimeStamp REAL, "
        "LSQuarantineAgentName TEXT, LSQuarantineAgentBundleIdentifier TEXT, "
        "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT, "
        "LSQuarantineOriginTitle TEXT, LSQuarantineSenderName TEXT, "
        "LSQuarantineSenderAddress TEXT, LSQuarantineTypeNumber INTEGER)"
    )
    con.execute(
        "INSERT INTO LSQuarantineEvent VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            "0F0E-1", _MAC_ABS_S, "curl", "com.apple.curl",
            "http://185.99.4.12:8443/payload.dmg",
            "https://updates.miniwakaya.xyz/download",
            "Get the update", "", "", 0,
        ),
    )
    con.commit()
    con.close()

    assert BrowserPlugin.can_handle(f, "application/vnd.sqlite3")
    events = _events(f)
    assert len(events) == 1
    b = events[0]["browser"]
    assert b["data_type"] == "quarantine"
    assert b["filename"] == "payload.dmg"
    assert b["domain"] == "185.99.4.12"
    # A payload pulled straight from an IP literal skipped DNS entirely.
    assert b["host_is_ip"] is True
    assert b["agent_name"] == "curl"
    assert b["agent_bundle_id"] == "com.apple.curl"
    assert b["page_url"] == "https://updates.miniwakaya.xyz/download"
    assert b["page_domain"] == "updates.miniwakaya.xyz"
    assert b["quarantine_type"] == "webdownload"
    assert events[0]["timestamp"].startswith("2026-03-04T09:12:33")


def test_quarantine_tolerates_a_reduced_column_set(tmp_path):
    """Older macOS releases ship fewer columns — parse what is there."""
    f = tmp_path / "quarantine_events.sqlite"
    con = sqlite3.connect(f)
    con.execute(
        "CREATE TABLE LSQuarantineEvent(LSQuarantineTimeStamp REAL, "
        "LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT)"
    )
    con.execute(
        "INSERT INTO LSQuarantineEvent VALUES(?, 'Safari', 'https://evil.test/a.pkg')",
        (_MAC_ABS_S,),
    )
    con.commit()
    con.close()

    events = _events(f)
    assert len(events) == 1
    assert events[0]["browser"]["filename"] == "a.pkg"
    assert events[0]["browser"]["agent_bundle_id"] == ""


# ── Chromium: domain / host_is_ip on history and downloads ───────────────────
def test_chromium_history_and_download_carry_the_host(tmp_path):
    f = tmp_path / "History"
    con = sqlite3.connect(f)
    con.execute(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
        "visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)"
    )
    con.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, "
                "visit_time INTEGER, transition INTEGER)")
    con.execute(
        "CREATE TABLE downloads(id INTEGER PRIMARY KEY, start_time INTEGER, "
        "end_time INTEGER, tab_url TEXT, current_path TEXT, target_path TEXT, "
        "total_bytes INTEGER, received_bytes INTEGER, danger_type INTEGER, "
        "interrupt_reason INTEGER, mime_type TEXT, state INTEGER)"
    )
    con.execute("INSERT INTO urls VALUES(1, 'http://45.61.136.9/gate.php', 'gate', 2, 1, ?)",
                (_WEBKIT_US,))
    con.execute("INSERT INTO visits VALUES(1, 1, ?, 1)", (_WEBKIT_US,))
    con.execute(
        "INSERT INTO downloads VALUES(1, ?, ?, 'http://45.61.136.9/gate.php', "
        r"'C:\Users\v\Downloads\inv.exe', 'C:\Users\v\Downloads\inv.exe', "
        "40960, 40960, 1, 0, 'application/x-msdownload', 1)",
        (_WEBKIT_US, _WEBKIT_US),
    )
    con.commit()
    con.close()

    events = _events(f)
    hist = _by_type(events, "history")[0]["browser"]
    assert hist["domain"] == "45.61.136.9"
    assert hist["host_is_ip"] is True
    assert hist["transition"] == "typed"

    dl = _by_type(events, "download")[0]["browser"]
    assert dl["domain"] == "45.61.136.9"
    assert dl["host_is_ip"] is True
    assert dl["filename"] == "inv.exe"
    assert dl["danger_type"] == "dangerous_file"
    assert dl["state"] == "complete"


# ── Firefox: a download's destination path ───────────────────────────────────
def test_firefox_download_annotation_yields_a_target_path(tmp_path):
    f = tmp_path / "places.sqlite"
    con = sqlite3.connect(f)
    con.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
                "visit_count INTEGER, typed INTEGER, frecency INTEGER)")
    con.execute("CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, "
                "visit_date INTEGER, visit_type INTEGER)")
    con.execute("CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, "
                "anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER)")
    con.execute("INSERT INTO moz_places VALUES(1, 'https://cdn.miniwakaya.xyz/inv.iso', "
                "'invoice', 1, 1, 100)")
    con.execute("INSERT INTO moz_historyvisits VALUES(1, 1, ?, 7)", (_FIREFOX_US,))
    con.execute("INSERT INTO moz_anno_attributes VALUES(1, 'downloads/destinationFileURI')")
    con.execute(
        "INSERT INTO moz_annos VALUES(1, 1, 1, 'file:///home/v/Downloads/inv%20copy.iso', ?)",
        (_FIREFOX_US,),
    )
    con.commit()
    con.close()

    events = _events(f)
    hist = _by_type(events, "history")[0]["browser"]
    assert hist["domain"] == "cdn.miniwakaya.xyz"
    assert hist["transition"] == "download"

    dl = _by_type(events, "download")[0]["browser"]
    assert dl["target_path"] == "/home/v/Downloads/inv copy.iso"
    assert dl["filename"] == "inv copy.iso"
    assert dl["domain"] == "cdn.miniwakaya.xyz"


# ── Handled-filename contract ────────────────────────────────────────────────
def test_safari_and_quarantine_filenames_are_claimed(tmp_path):
    for name in (
        "History.db",
        "quarantine_events.sqlite",
        "com.apple.LaunchServices.QuarantineEventsV2",
    ):
        p = tmp_path / name
        p.write_bytes(b"SQLite format 3\x00")
        assert BrowserPlugin.can_handle(p, "application/octet-stream"), name
