"""Contract tests for the macOS post-collection parsing path.

These cover the gap that made a real macOS investigation come back empty: Talon
collected the host, but downstream almost nothing understood what it wrote, so
the case held 45 syslog lines and no process, network, or browser evidence at
all. Each test below pins one link in that chain.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3

from babel.base_plugin import PluginContext


def _ctx(path):
    return PluginContext(case_id="c", job_id="j", source_file_path=path, source_minio_url="")


def _banner(title: str) -> str:
    bar = "=" * 60
    return f"\n{bar}\n{title}\n{bar}\n"


MAC_TRIAGE = (
    _banner("OS VERSION")
    + "ProductName:\tmacOS\nProductVersion:\t14.4.1\nBuildVersion:\t23E224\n"
    + _banner("UNAME")
    + "Darwin L20336 23.4.0 Darwin Kernel Version 23.4.0: Fri Mar  8 22:33:00 PST 2024; "
    "root:xnu-10063.101.15~3/RELEASE_ARM64_T6020 arm64\n"
    + _banner("PROCESSES")
    + "USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND\n"
    "tmoll              501   3.4  1.2 412345678 198765   ??  S     9:00AM   1:23.45 "
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --no-first-run\n"
    "tmoll              812   0.0  0.1  33812345   8192   ??  S     9:12AM   0:00.31 "
    "/Users/tmoll/Library/Application Support/.dnt/updater --silent\n"
    + _banner("NETWORK SOCKETS")
    + "Active Internet connections (including servers)\n"
    "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n"
    "tcp4       0      0  192.168.1.10.52344     178.16.53.137.443      ESTABLISHED "
    "131072 131072   812     0 0x0102\n"
    "tcp4       0      0  *.22                   *.*                    LISTEN "
    "131072 131072    98     0 0x0000\n"
    "Active LOCAL (UNIX) domain sockets\n"
    "Address          Type   Recv-Q Send-Q            inode\n"
    + _banner("ARP CACHE")
    + "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
    + _banner("ROUTING TABLE")
    + "Routing tables\n\nInternet:\nDestination        Gateway            Flags        Netif\n"
    "default            192.168.1.1        UGScg                 en0\n"
    + _banner("LAST LOGINS")
    + "tmoll    ttys000  10.0.0.5         Mon Aug 25 09:05 - 09:30  (00:25)\n"
    + _banner("LOADED KEXTS")
    + "Index Refs Address            Size       Wired      Name (Version) UUID\n"
    "  145    0 0xffffff7f8a1b2000 0x8000     0x8000     com.evil.rootkit (1.0) UUID <5 6>\n"
    + _banner("LAUNCH DAEMONS")
    + "PID\tStatus\tLabel\n812\t0\tcom.dnt.updater\n-\t0\tcom.apple.safaridavclient\n"
    + _banner("INSTALLED APPS")
    + "Applications:\n\n    DNTUpdater:\n\n      Version: 1.0\n"
    "      Obtained from: Unknown\n"
    "      Location: /Users/tmoll/Library/Application Support/.dnt/DNTUpdater.app\n"
    + _banner("SUID FILES")
    + " 98765     64 -rwsr-xr-x    1 root     wheel       65536 Aug 25 09:12 "
    "/Users/tmoll/Library/Application Support/.dnt/helper\n"
    + _banner("ENVIRONMENT")
    + "DYLD_INSERT_LIBRARIES=/Users/tmoll/Library/Application Support/.dnt/inject.dylib\n"
    + _banner("FIREWALL")
    + "Firewall is disabled. (State = 0)\n"
)

LINUX_TRIAGE = (
    "=== uname -a ===\nLinux web01 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux\n"
    "=== hostname ===\nweb01\n"
)


def _parse_mac_triage(tmp_path):
    from babel.macos_triage.macos_triage_plugin import MacOSTriagePlugin

    f = tmp_path / "system_triage.txt"
    f.write_text(MAC_TRIAGE)
    assert MacOSTriagePlugin.can_handle(f, "text/plain")
    return list(MacOSTriagePlugin(_ctx(f)).parse())


# ── Routing: the same filename on two platforms ───────────────────────────────


def test_linux_system_triage_is_not_claimed_by_the_macos_parser(tmp_path):
    """Talon writes system_triage.txt on Linux too — it must keep its parser."""
    from babel.macos_triage.macos_triage_plugin import MacOSTriagePlugin

    f = tmp_path / "system_triage.txt"
    f.write_text(LINUX_TRIAGE)
    assert not MacOSTriagePlugin.can_handle(f, "text/plain")


def test_macos_triage_claims_only_its_own_filenames(tmp_path):
    from babel.macos_triage.macos_triage_plugin import MacOSTriagePlugin

    f = tmp_path / "something_else.txt"
    f.write_text(MAC_TRIAGE)
    assert not MacOSTriagePlugin.can_handle(f, "text/plain")


# ── The sections that were being thrown away ──────────────────────────────────


def test_macos_triage_emits_every_section_not_just_sysinfo(tmp_path):
    """The regression this parser exists for: linux_triage matched the filename
    and ran ``_parse_sysinfo``, so a whole macOS host reduced to ONE event."""
    events = _parse_mac_triage(tmp_path)
    types = {e["artifact_type"] for e in events}
    assert {
        "system_info",
        "process",
        "network_conn",
        "arp_entry",
        "route_entry",
        "login_event",
        "kernel_module",
        "service",
        "installed_software",
        "file",
        "env_variable",
    } <= types
    assert len(events) > 10


def test_every_event_is_tagged_macos_and_carries_the_hostname(tmp_path):
    """``process``/``network_conn``/``service`` map to "windows" in the shared
    taxonomy, so the parser must set os itself — and a triage snapshot that
    does not name its host is invisible to the host-scoped search an analyst
    runs first."""
    events = _parse_mac_triage(tmp_path)
    assert events
    assert all(e["os"] == "macos" for e in events)
    assert all(e["host"]["hostname"] == "L20336" for e in events)


def test_outbound_connection_keeps_remote_ip_port_and_owning_pid(tmp_path):
    """macOS netstat writes ``addr.port``, not ``addr:port`` — read as a colon
    format the remote IP comes out as "178.16.53.137.443" and matches no IOC."""
    events = _parse_mac_triage(tmp_path)
    conns = [e for e in events if e["artifact_type"] == "network_conn"]
    established = [e for e in conns if e["network"].get("remote_ip")]
    assert len(established) == 1
    net = established[0]["network"]
    assert net["remote_ip"] == "178.16.53.137"
    assert net["remote_port"] == 443
    assert net["local_ip"] == "192.168.1.10"
    assert net["local_port"] == 52344
    assert established[0]["process"]["pid"] == 812


def test_wildcard_listener_does_not_index_a_star_as_an_ip(tmp_path):
    """"*" is not an address; indexing it as one poisons IP-based CTI matching."""
    events = _parse_mac_triage(tmp_path)
    listeners = [
        e
        for e in events
        if e["artifact_type"] == "network_conn" and e["macos_socket"]["state"] == "LISTEN"
    ]
    assert len(listeners) == 1
    net = listeners[0]["network"]
    assert "remote_ip" not in net
    assert "local_ip" not in net
    assert net["local_port"] == 22


def test_unix_domain_socket_section_is_not_parsed_as_network(tmp_path):
    events = _parse_mac_triage(tmp_path)
    conns = [e for e in events if e["artifact_type"] == "network_conn"]
    assert len(conns) == 2  # the two Internet rows only


def test_app_bundle_path_with_spaces_survives(tmp_path):
    """argv[0] on macOS routinely contains a space; splitting on the first one
    truncates "/Applications/Google Chrome.app/..." to "/Applications/Google"."""
    events = _parse_mac_triage(tmp_path)
    procs = {e["process"]["pid"]: e for e in events if e["artifact_type"] == "process"}
    chrome = procs[501]
    assert chrome["process"]["path"] == (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    )
    assert chrome["process"]["name"] == "Google Chrome"
    assert chrome["process"]["command_line"].endswith("--no-first-run")

    updater = procs[812]
    assert updater["process"]["path"] == (
        "/Users/tmoll/Library/Application Support/.dnt/updater"
    )


def test_third_party_kext_and_launchd_job_are_flagged(tmp_path):
    events = _parse_mac_triage(tmp_path)
    kexts = [e for e in events if e["artifact_type"] == "kernel_module"]
    assert len(kexts) == 1
    assert kexts[0]["kernel_module"]["name"] == "com.evil.rootkit"
    assert kexts[0]["kernel_module"]["third_party"] is True

    svcs = {e["service"]["name"]: e["service"] for e in events if e["artifact_type"] == "service"}
    assert svcs["com.dnt.updater"]["third_party"] is True
    assert svcs["com.dnt.updater"]["pid"] == 812
    assert svcs["com.apple.safaridavclient"]["third_party"] is False
    # "-" in the PID column means loaded but not running.
    assert svcs["com.apple.safaridavclient"]["pid"] is None


def test_unsigned_app_and_suid_outside_system_paths_are_flagged(tmp_path):
    events = _parse_mac_triage(tmp_path)
    apps = [e for e in events if e["artifact_type"] == "installed_software"]
    assert len(apps) == 1
    assert apps[0]["installed_software"]["name"] == "DNTUpdater"
    assert apps[0]["installed_software"]["unsigned"] is True

    suid = [e for e in events if e["artifact_type"] == "file"]
    assert len(suid) == 1
    assert suid[0]["file"]["suspicious_location"] is True


def test_login_event_uses_its_own_time_not_the_snapshot_time(tmp_path):
    """Every other section is a snapshot, but ``last`` rows carry real times —
    stamping them all with the collection moment collapses the login history."""
    events = _parse_mac_triage(tmp_path)
    logins = [e for e in events if e["artifact_type"] == "login_event"]
    assert len(logins) == 1
    assert logins[0]["timestamp_desc"] == "Login Time"
    assert logins[0]["timestamp"].endswith("Z")
    assert "-08-25T09:05" in logins[0]["timestamp"]
    assert logins[0]["network"]["remote_ip"] == "10.0.0.5"


def test_unrecognised_section_is_kept_as_context(tmp_path):
    """An unknown banner must not silently drop its body."""
    from babel.macos_triage.macos_triage_plugin import MacOSTriagePlugin

    f = tmp_path / "system_triage.txt"
    f.write_text(MAC_TRIAGE + _banner("SOME NEW SECTION") + "surprising output\n")
    events = list(MacOSTriagePlugin(_ctx(f)).parse())
    ctx_events = [e for e in events if "surprising output" in str(e.get("raw", {}))]
    assert len(ctx_events) == 1
    assert ctx_events[0]["artifact_type"] == "system_info"


# ── macOS quarantine (download provenance) ────────────────────────────────────


def _quarantine_db(path, ts_cocoa: float):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE LSQuarantineEvent ("
        "LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL,"
        "LSQuarantineTimeStamp REAL,"
        "LSQuarantineAgentBundleIdentifier TEXT,"
        "LSQuarantineAgentName TEXT,"
        "LSQuarantineDataURLString TEXT,"
        "LSQuarantineSenderName TEXT,"
        "LSQuarantineSenderAddress TEXT,"
        "LSQuarantineTypeNumber INTEGER,"
        "LSQuarantineOriginTitle TEXT,"
        "LSQuarantineOriginURLString TEXT,"
        "LSQuarantineOriginAlias BLOB)"
    )
    conn.execute(
        "INSERT INTO LSQuarantineEvent VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "F1A2-B3C4",
            ts_cocoa,
            "com.google.Chrome",
            "Google Chrome",
            "https://cdn.dntds.shop/setup.dmg",
            "",
            "",
            2,
            "Free Mac Cleaner",
            "https://dntds.shop/download",
            None,
        ),
    )
    conn.commit()
    conn.close()


def test_quarantine_db_yields_download_url_and_referrer(tmp_path):
    """The best macOS answer to "where did this file come from" used to route
    to ``strings``. Both URLs matter: in a drive-by the origin is the malicious
    site and the data URL is a CDN."""
    from babel.browser.browser_plugin import BrowserPlugin

    when = _dt.datetime(2026, 8, 25, 9, 12, 0, tzinfo=_dt.UTC)
    cocoa = (when - _dt.datetime(2001, 1, 1, tzinfo=_dt.UTC)).total_seconds()
    f = tmp_path / "quarantine_events.sqlite"
    _quarantine_db(f, cocoa)

    assert BrowserPlugin.can_handle(f, "application/vnd.sqlite3")
    plugin = BrowserPlugin(_ctx(f))
    plugin.setup()
    try:
        events = list(plugin.parse())
    finally:
        plugin.teardown()

    assert len(events) == 1
    ev = events[0]
    assert ev["artifact_type"] == "browser"
    assert ev["os"] == "macos"
    assert ev["browser"]["data_type"] == "download"
    assert ev["browser"]["url"] == "https://cdn.dntds.shop/setup.dmg"
    assert ev["browser"]["referrer"] == "https://dntds.shop/download"
    assert ev["browser"]["agent"] == "Google Chrome"
    # Cocoa epoch (2001), not Unix — off by 31 years if read as the latter.
    assert ev["timestamp"].startswith("2026-08-25T09:12:00")


def test_quarantine_live_filename_also_routes(tmp_path):
    """The on-disk name has no extension at all."""
    from babel.browser.browser_plugin import BrowserPlugin

    f = tmp_path / "com.apple.LaunchServices.QuarantineEventsV2"
    _quarantine_db(f, 807_699_120.0)
    assert BrowserPlugin.can_handle(f, "application/octet-stream")


# ── Unified log: the text fallback ────────────────────────────────────────────

ULS_COLUMN = (
    'Filtering the log data using "senderImagePath CONTAINS \'dnt\'"\n'
    "Skipping info and debug messages, pass --info and/or --debug to include.\n"
    "Timestamp                       Thread     Type        Activity             PID    TTL\n"
    "2026-08-25 09:00:00.123456+0200 0x1a2b3    Default     0x0                  501    0    "
    "mDNSResponder: [com.apple.mDNSResponder:dns] query A dntds.shop\n"
    "2026-08-25 09:00:01.456789+0200 0x1a2b4    Error       0x1f2                812    0    "
    "updater: (libnetwork.dylib) nw_connection failed\n"
    "-------------------------------------------------------------------------\n"
    "Log      - Default:          2, Info:      0, Debug:  0, Error:  1, Fault: 0\n"
)


def test_log_show_column_format_is_parsed_per_line(tmp_path):
    """Talon's ULS fallback is default ``log show`` output — a column table that
    matched no pattern, so a 7-day system log became one metadata event."""
    from babel.macos_uls.macos_uls_plugin import MacOSULSPlugin

    f = tmp_path / "unified_logs.log"
    f.write_text(ULS_COLUMN)
    assert MacOSULSPlugin.can_handle(f, "text/plain")
    events = list(MacOSULSPlugin(_ctx(f)).parse())
    assert len(events) == 2

    dns = events[0]
    assert dns["artifact_type"] == "macos_uls"
    assert dns["process"]["name"] == "mDNSResponder"
    assert dns["process"]["pid"] == "501"
    assert dns["macos_uls"]["subsystem"] == "com.apple.mDNSResponder"
    assert dns["macos_uls"]["category"] == "dns"
    assert "dntds.shop" in dns["message"]
    assert dns["timestamp"] == "2026-08-25T07:00:00.123Z"  # +0200 → UTC

    err = events[1]
    assert err["macos_uls"]["level"] == "error"
    assert err["macos_uls"]["image"] == "libnetwork.dylib"


def test_talon_unified_log_filenames_are_claimed_by_name(tmp_path):
    """Content sniffing is a backstop; the names Talon writes must be listed."""
    from babel.macos_uls.macos_uls_plugin import MacOSULSPlugin

    for name in ("unified_logs.ndjson", "unified_logs.log", "unified_logs.json"):
        f = tmp_path / name
        f.write_text("")
        assert MacOSULSPlugin.can_handle(f, "text/plain"), name


# ── macOS syslog-family variants ──────────────────────────────────────────────


def test_install_log_two_digit_utc_offset_parses(tmp_path):
    """macOS writes "+02", not "+0200" — with the minutes mandatory the whole
    install history fell through to json_file."""
    from babel.syslog.syslog_plugin import SyslogPlugin

    f = tmp_path / "install.log"
    f.write_text(
        "2026-08-25 09:00:00+02 L20336 softwareupdated[456]: Descriptor state: Downloaded\n"
        "2026-08-25 09:12:31+02 L20336 installer[812]: PackageKit: Install Failed\n"
    )
    assert SyslogPlugin.can_handle(f, "text/plain")
    events = list(SyslogPlugin(_ctx(f)).parse())
    assert len(events) == 2
    assert all(e["artifact_type"] == "macos_install_log" for e in events)
    assert events[0]["host"]["hostname"] == "L20336"
    assert events[0]["timestamp"].startswith("2026-08-25")


def test_wifi_log_association_history_parses(tmp_path):
    from babel.syslog.syslog_plugin import SyslogPlugin

    f = tmp_path / "wifi.log"
    f.write_text(
        "Mon Aug 25 09:00:00.000 <airportd[123]> _handleLinkEvent: en0 associated to CORP-WIFI\n"
    )
    assert SyslogPlugin.can_handle(f, "text/plain")
    events = list(SyslogPlugin(_ctx(f)).parse())
    assert len(events) == 1
    assert events[0]["artifact_type"] == "macos_wifi_log"
    assert events[0]["os"] == "macos"
    assert events[0]["process"]["name"] == "airportd"
    assert "CORP-WIFI" in events[0]["message"]


def test_linux_syslog_still_parses_unchanged(tmp_path):
    """The ISO pattern was widened; RFC 3164 must be untouched."""
    from babel.syslog.syslog_plugin import SyslogPlugin

    f = tmp_path / "syslog"
    f.write_text("Jan 15 10:00:01 web01 sshd[1234]: Accepted publickey for root\n")
    events = list(SyslogPlugin(_ctx(f)).parse())
    assert len(events) == 1
    assert events[0]["artifact_type"] == "syslog"
    assert events[0]["host"]["hostname"] == "web01"


# ── Taxonomy ──────────────────────────────────────────────────────────────────


def test_new_macos_artifact_types_are_classified_macos():
    from citadel_contracts.parser import classify_os

    for at in ("macos_triage", "macos_install_log", "macos_wifi_log", "macos_uls"):
        assert classify_os(at) == "macos", at


# ── Desktop Safari history ────────────────────────────────────────────────────


def _safari_history_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER)")
    conn.execute(
        "CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, "
        "visit_time REAL, title TEXT, redirect_source INTEGER, redirect_destination INTEGER)"
    )
    when = _dt.datetime(2026, 8, 25, 9, 10, 0, tzinfo=_dt.UTC)
    cocoa = (when - _dt.datetime(2001, 1, 1, tzinfo=_dt.UTC)).total_seconds()
    conn.execute("INSERT INTO history_items VALUES (1,'https://dntds.shop/download',3)")
    conn.execute(
        "INSERT INTO history_visits VALUES (1,1,?,'Free Mac Cleaner',NULL,NULL)", (cocoa,)
    )
    conn.commit()
    conn.close()


def test_desktop_safari_history_is_a_browser_artifact(tmp_path):
    """Parsed as artifact_type "ios" it was invisible to the
    ``artifact_type:browser`` search an analyst actually runs on a macOS host."""
    from babel.browser.browser_plugin import BrowserPlugin

    f = tmp_path / "browser" / "tmoll" / "safari" / "History.db"
    f.parent.mkdir(parents=True)
    _safari_history_db(f)

    assert BrowserPlugin.can_handle(f, "application/vnd.sqlite3")
    plugin = BrowserPlugin(_ctx(f))
    plugin.setup()
    try:
        events = list(plugin.parse())
    finally:
        plugin.teardown()

    assert len(events) == 1
    ev = events[0]
    assert ev["artifact_type"] == "browser"
    assert ev["os"] == "macos"
    assert ev["browser"]["browser_type"] == "safari"
    assert ev["browser"]["url"] == "https://dntds.shop/download"
    assert ev["browser"]["visit_count"] == 3
    # Cocoa epoch, not Unix — off by 31 years if read as the latter.
    assert ev["timestamp"].startswith("2026-08-25T09:10:00")


def test_ios_safari_history_is_left_to_the_ios_parser(tmp_path):
    """Same filename, same schema — only the path distinguishes them, and
    hijacking an iOS extraction here would lose its ios typing."""
    from babel.browser.browser_plugin import BrowserPlugin
    from babel.ios.ios_plugin import IOSPlugin

    f = tmp_path / "HomeDomain" / "Library" / "Safari" / "History.db"
    f.parent.mkdir(parents=True)
    _safari_history_db(f)

    assert not BrowserPlugin.can_handle(f, "application/vnd.sqlite3")
    assert IOSPlugin.can_handle(f, "application/vnd.sqlite3")
