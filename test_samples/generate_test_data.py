#!/usr/bin/env python3
"""
Generate test forensic artifacts for Citadel testing.

Creates synthetic test files in various supported formats:
- Syslog entries
- Zeek conn.log
- Suricata eve.json
- Browser History (SQLite)
- NDJSON events

Run:  python3 generate_test_data.py
Output lands in ./test_output/

Then upload the generated files (or the zip) to a Citadel case to verify
all ingesters work correctly.
"""
import json
import os
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(__file__), "test_output")
os.makedirs(OUT, exist_ok=True)


def write_syslog():
    """Generate a sample syslog file."""
    lines = []
    base = datetime(2024, 6, 15, 8, 0, 0)
    entries = [
        ("sshd[12345]", "Accepted publickey for root from 192.168.1.100 port 55234 ssh2"),
        ("sshd[12346]", "Failed password for admin from 10.0.0.50 port 44321 ssh2"),
        ("sudo", "   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"),
        ("kernel", "Out of memory: Kill process 5678 (java) score 900 or sacrifice child"),
        ("cron[999]", "CMD (/usr/bin/python3 /opt/scripts/backup.py)"),
        ("sshd[12350]", "Accepted password for analyst from 172.16.0.5 port 33211 ssh2"),
        ("systemd[1]", "Starting Daily Cleanup of Temporary Directories..."),
        ("auditd[100]", "ANOM_ABEND auid=0 uid=0 gid=0 ses=1 pid=5678 comm=\"suspicious\""),
        ("sshd[12355]", "Failed password for invalid user hacker from 203.0.113.50 port 22"),
        ("kernel", "TCP: request_sock_TCP: Possible SYN flooding on port 80."),
    ]
    for i, (proc, msg) in enumerate(entries):
        ts = (base + timedelta(minutes=i * 15)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} forensic-server {proc}: {msg}")
    path = os.path.join(OUT, "auth.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(lines)} entries)")


def write_zeek_conn():
    """Generate a sample Zeek conn.log."""
    header = """#separator \t
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2024-06-15-08-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]"""
    base_ts = 1718438400.0  # 2024-06-15 08:00:00 UTC
    conns = [
        ("192.168.1.100", 55234, "192.168.1.1", 22, "tcp", "ssh", "120.5", "5000", "12000", "SF"),
        ("10.0.0.50", 44321, "192.168.1.1", 22, "tcp", "ssh", "0.5", "200", "400", "REJ"),
        ("192.168.1.100", 8080, "93.184.216.34", 443, "tcp", "ssl", "30.2", "1500", "45000", "SF"),
        ("172.16.0.5", 33211, "192.168.1.1", 22, "tcp", "ssh", "3600.0", "50000", "100000", "SF"),
        ("203.0.113.50", 12345, "192.168.1.1", 80, "tcp", "http", "0.01", "0", "0", "S0"),
        ("192.168.1.100", 53000, "8.8.8.8", 53, "udp", "dns", "0.001", "50", "200", "SF"),
    ]
    lines = [header]
    for i, (oh, op, rh, rp, proto, svc, dur, ob, rb, cs) in enumerate(conns):
        ts = base_ts + i * 300
        uid = f"C{i:06d}"
        lines.append(f"{ts}\t{uid}\t{oh}\t{op}\t{rh}\t{rp}\t{proto}\t{svc}\t{dur}\t{ob}\t{rb}\t{cs}\t-\t-\t0\tShADad\t10\t500\t8\t400\t(empty)")
    lines.append("#close\t2024-06-15-10-00-00")
    path = os.path.join(OUT, "conn.log")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(conns)} connections)")


def write_suricata_eve():
    """Generate a sample Suricata eve.json."""
    base = datetime(2024, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
    alerts = [
        {"sid": 2001219, "msg": "ET SCAN Potential SSH Scan", "severity": 2, "category": "Attempted Information Leak"},
        {"sid": 2013028, "msg": "ET POLICY curl User-Agent Outbound", "severity": 3, "category": "Potentially Bad Traffic"},
        {"sid": 2024897, "msg": "ET TROJAN CobaltStrike Beacon Activity", "severity": 1, "category": "A Network Trojan was Detected"},
        {"sid": 2100498, "msg": "GPL ATTACK_RESPONSE id check returned root", "severity": 1, "category": "Potentially Bad Traffic"},
    ]
    lines = []
    for i, alert in enumerate(alerts):
        ts = (base + timedelta(minutes=i * 20)).isoformat()
        event = {
            "timestamp": ts,
            "flow_id": 1000000 + i,
            "event_type": "alert",
            "src_ip": "203.0.113.50",
            "src_port": 12345 + i,
            "dest_ip": "192.168.1.1",
            "dest_port": 22 if i == 0 else 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": alert["sid"],
                "rev": 1,
                "signature": alert["msg"],
                "category": alert["category"],
                "severity": alert["severity"],
            },
        }
        lines.append(json.dumps(event))
    path = os.path.join(OUT, "eve.json")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(alerts)} alerts)")


def write_browser_history():
    """Generate a sample Chromium History SQLite database."""
    path = os.path.join(OUT, "History")
    if os.path.exists(path):
        os.unlink(path)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    # Chromium schema (simplified)
    c.execute("""CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        title TEXT,
        visit_count INTEGER DEFAULT 0,
        typed_count INTEGER DEFAULT 0,
        last_visit_time INTEGER NOT NULL,
        hidden INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE visits (
        id INTEGER PRIMARY KEY,
        url INTEGER NOT NULL,
        visit_time INTEGER NOT NULL,
        from_visit INTEGER DEFAULT 0,
        transition INTEGER DEFAULT 0,
        segment_id INTEGER DEFAULT 0,
        visit_duration INTEGER DEFAULT 0
    )""")
    # Chromium WebKit epoch: microseconds since 1601-01-01
    # 2024-06-15 08:00:00 UTC in WebKit = 13363027200000000
    base_webkit = 13363027200000000
    urls = [
        ("https://mail.google.com/mail/u/0/", "Gmail - Inbox", 15),
        ("https://github.com/forensics/citadel", "forensics/citadel - GitHub", 8),
        ("https://stackoverflow.com/questions/12345", "python sqlite3 - Stack Overflow", 3),
        ("https://attacker-c2.evil.com/beacon", "404 Not Found", 1),
        ("https://docs.python.org/3/library/sqlite3.html", "sqlite3 - Python docs", 5),
        ("https://virustotal.com/gui/file/abc123", "VirusTotal - File Analysis", 2),
    ]
    for i, (url, title, vc) in enumerate(urls):
        visit_time = base_webkit + i * 3600 * 1000000  # 1 hour apart
        c.execute("INSERT INTO urls VALUES (?, ?, ?, ?, 0, ?, 0)", (i + 1, url, title, vc, visit_time))
        c.execute("INSERT INTO visits VALUES (?, ?, ?, 0, 0, 0, 60000000)", (i + 1, i + 1, visit_time))
    conn.commit()
    conn.close()
    print(f"  Created {path} ({len(urls)} URLs)")


def write_ndjson():
    """Generate a sample NDJSON forensic events file."""
    base = datetime(2024, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = [
        {"event_type": "process_create", "process_name": "powershell.exe", "command_line": "powershell -enc SQBFAFgA", "user": "CORP\\admin"},
        {"event_type": "file_create", "path": "C:\\Windows\\Temp\\payload.exe", "size": 45056, "user": "SYSTEM"},
        {"event_type": "network_connect", "process_name": "payload.exe", "dest_ip": "203.0.113.50", "dest_port": 443},
        {"event_type": "registry_modify", "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "payload.exe", "user": "SYSTEM"},
        {"event_type": "process_create", "process_name": "cmd.exe", "command_line": "cmd /c whoami > C:\\temp\\out.txt", "user": "CORP\\admin"},
    ]
    lines = []
    for i, ev in enumerate(events):
        ev["timestamp"] = (base + timedelta(minutes=i * 5)).isoformat()
        ev["hostname"] = "WORKSTATION-01"
        ev["message"] = f"{ev['event_type']}: {ev.get('process_name', ev.get('path', ev.get('key', '')))}"
        lines.append(json.dumps(ev))
    path = os.path.join(OUT, "forensic_events.jsonl")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Created {path} ({len(events)} events)")


def create_zip():
    """Bundle all test files into a single zip."""
    zip_path = os.path.join(OUT, "test_artifacts.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in os.listdir(OUT):
            fpath = os.path.join(OUT, fname)
            if os.path.isfile(fpath) and fname != "test_artifacts.zip":
                zf.write(fpath, fname)
    print(f"  Created {zip_path}")


if __name__ == "__main__":
    print("Generating Citadel test artifacts...")
    print()
    write_syslog()
    write_zeek_conn()
    write_suricata_eve()
    write_browser_history()
    write_ndjson()
    print()
    create_zip()
    print()
    print(f"All test files in: {OUT}/")
    print("Upload test_artifacts.zip to a Citadel case to test all ingesters.")
