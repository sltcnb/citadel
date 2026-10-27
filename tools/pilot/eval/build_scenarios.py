#!/usr/bin/env python3
"""Generate the attribution scenarios (scenarios/1x_*.yaml).

Each scenario is a synthetic Windows Security log around an admin-share write
alert. They share one shape on purpose — an alert naming a source IP, a source
port and an account — and differ in what the join on that port reveals, so a
harness that only works for one outcome fails the others:

  10  reference      join → a backup service account the alert did not name;
                     off-schedule session; prior detections near the alert
  11  benign         join → the account the alert named, on its usual schedule
  12  malicious      join → a local admin from a legitimate backup server,
                     followed by a service install
  13  logs cleared   the session is gone: Security log cleared right after
  14  wrong account  join → a routine SQL agent account, not the alert's user

All names, addresses and paths are invented. Regenerate with:

    python3 tools/pilot/eval/build_scenarios.py
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import yaml

OUT = Path(__file__).resolve().parent / "scenarios"


class Log:
    """Builds evtx/hayabusa seed docs with per-host sequential record IDs."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.docs: list[dict] = []
        self.n = 0

    def _id(self) -> str:
        self.n += 1
        return f"{self.prefix}-{self.n:03d}"

    def _evtx(self, ts: datetime, host: str, eid: int, msg: str, data: dict, *, user=None,
              net=None, process=None, key=False, channel="Security") -> str:
        fid = self._id()
        doc = {
            "fo_id": fid,
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "message": f"{msg} on {host} [{channel}]",
            "host": {"hostname": host},
            "evtx": {"event_id": eid, "channel": channel, "computer": host, "event_data": data},
        }
        if user:
            doc["user"] = {"name": user, "domain": host.upper()}
        if net:
            doc["network"] = net
        if process:
            doc["process"] = process
        self.docs.append({"artifact_type": "evtx", "doc": doc, **({"key": True} if key else {})})
        return fid

    def logon(self, ts, host, user, ip, port, ws, logon_id, ltype="3", key=False):
        return self._evtx(ts, host, 4624, "Account logon success", {
            "TargetUserName": user, "TargetDomainName": host.upper(), "TargetLogonId": logon_id,
            "LogonType": ltype, "LogonProcessName": "NtLmSsp" if ltype == "3" else "User32",
            "AuthenticationPackageName": "NTLM" if ltype == "3" else "Negotiate",
            "WorkstationName": ws, "IpAddress": ip, "IpPort": str(port),
        }, user=user, net={"src_ip": ip, "src_port": port, "workstation": ws}, key=key)

    def privileges(self, ts, host, user, logon_id):
        return self._evtx(ts, host, 4672, "Special privileges assigned to new logon", {
            "SubjectUserName": user, "SubjectDomainName": host.upper(), "SubjectLogonId": logon_id,
            "PrivilegeList": "SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege",
        }, user=user)

    def logoff(self, ts, host, user, logon_id):
        return self._evtx(ts, host, 4634, "Account logoff", {
            "TargetUserName": user, "TargetLogonId": logon_id, "LogonType": "3",
        }, user=user)

    def enumerate_user(self, ts, host, target, caller):
        return self._evtx(ts, host, 4798, "EventID 4798", {
            "TargetUserName": target, "SubjectUserName": f"{host.upper()}$",
            "SubjectLogonId": "0x3e7", "CallerProcessName": caller,
        }, user=target)

    def service_install(self, ts, host, name, image, key=False):
        return self._evtx(ts, host, 7045, "New service installed", {
            "ServiceName": name, "ImagePath": image, "ServiceType": "user mode service",
            "StartType": "demand start", "AccountName": "LocalSystem",
        }, channel="System", key=key)

    def process(self, ts, host, user, logon_id, image, cmd, parent, key=False):
        return self._evtx(ts, host, 4688, "A new process has been created", {
            "SubjectUserName": user, "SubjectLogonId": logon_id, "NewProcessName": image,
            "CommandLine": cmd, "ParentProcessName": parent,
        }, user=user, process={"name": image.rsplit("\\", 1)[-1], "command_line": cmd,
                                "parent": {"name": parent.rsplit("\\", 1)[-1]}}, key=key)

    def log_cleared(self, ts, host, user, key=False):
        return self._evtx(ts, host, 1102, "The audit log was cleared", {
            "SubjectUserName": user, "SubjectLogonId": "0x9f1",
        }, user=user, key=key)

    def service_state(self, ts, host, name, state):
        return self._evtx(ts, host, 7036, "Service state change", {"param1": name, "param2": state},
                          channel="System")

    def detection(self, ts, host, title, level):
        fid = self._id()
        self.docs.append({"artifact_type": "hayabusa", "doc": {
            "fo_id": fid, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "message": f"[{level.upper()}] {title} on {host}",
            "host": {"hostname": host},
            "hayabusa": {"rule_title": title, "level": level, "computer": host},
        }})
        return fid

    def finish(self) -> list[dict]:
        """Assign Security/System record IDs in time order, per host and channel."""
        counters: dict[tuple[str, str], int] = {}
        for entry in sorted(self.docs, key=lambda e: e["doc"]["timestamp"]):
            ev = entry["doc"].get("evtx")
            if not ev:
                continue
            k = (ev["computer"], ev["channel"])
            counters[k] = counters.get(k, 1000) + 1
            ev.setdefault("record_id", counters[k])
        return self.docs


def daily(start: datetime, days: int, hour: int, minute: int = 0):
    for d in range(days):
        yield (start + timedelta(days=d)).replace(hour=hour, minute=minute, second=11)


def scenario(sid: str, alert: str, docs: list[dict], rubric: dict, description: str) -> dict:
    key = [e["doc"]["fo_id"] for e in docs if e.get("key")]
    rubric = {"key_evidence": key, **rubric}
    return {"id": sid, "description": description, "scenario": alert, "seed": docs, "rubric": rubric}


def alert_text(*, host, host_ip, src_ip, port, account, path, when, prior=60):
    return (
        "Alert: Uncommon File Dropped Under Noteworthy Folder via SMB\n\n"
        f"Machine : {host}\n\n"
        f"Comptes : NT AUTHORITY\\SYSTEM, {account}\n\n"
        f"Indicateurs : {host_ip} (IP) ; {src_ip} (IP)\n\n"
        f"Heure de l'occurrence : {when} UTC\n\n"
        f"Source port : {port}\n\n"
        "Application : SMB\n\nPartage SMB : ADMIN$\n\n"
        f"The file {path} was written to the ADMIN$ share of {host} ({host_ip}) from "
        f"{src_ip}, under the account {account}. Prior analysis: benign at {prior} % "
        "confidence, most likely an internal tool testing write access; the source "
        "machine was not found in the inventories. The analyst reports no recurrence "
        "over 7 days and no execution after the drop."
    )


# ── 10 reference ─────────────────────────────────────────────────────────────
def reference() -> dict:
    L = Log("ref")
    host, src, ws = "srv-files01", "10.20.30.40", "BKP-SRV01"
    day0 = datetime(2026, 10, 7)
    for ts in daily(day0, 14, 19):
        lid = f"0x{ts.day:02x}a1"
        L.logon(ts, host, "svc_backup", src, 50000 + ts.day, ws, lid)
        L.logoff(ts + timedelta(minutes=3), host, "svc_backup", lid)
    alert = datetime(2026, 10, 21, 8, 4, 14)
    for i, (off, port) in enumerate([(-60, 51010), (-1, 51015), (0, 51021), (19, 51030)]):
        lid = f"0x1a2b3c{i:02d}"
        L.logon(alert + timedelta(seconds=off), host, "svc_backup", src, port, ws, lid,
                key=(port == 51021))
        L.privileges(alert + timedelta(seconds=off), host, "svc_backup", lid)
        L.logoff(alert + timedelta(seconds=off + 40), host, "svc_backup", lid)
    for d in (3, 9):
        L.logon(datetime(2026, 10, d + 5, 15, 18), host, "app_jdoe", "10.20.40.86", 61000 + d,
                "WS-CLIENT01", f"0x5{d}", ltype="10")
    for off, caller in [(25200, r"C:\Program Files\EDR\Agent\responder.exe")] * 2 + \
            [(-27000, r"C:\Windows\System32\wbem\WmiPrvSE.exe")]:
        L.enumerate_user(alert + timedelta(seconds=off), host, "app_jdoe", caller)
    for h in range(6, 11):
        L.service_state(datetime(2026, 10, 21, h, 30), host, "MSSQLSERVER", "running")
    L.log_cleared(datetime(2026, 3, 31, 10, 2), host, "Administrator")
    L.detection(datetime(2026, 3, 31, 10, 2), host, "Security Log Cleared", "high")
    L.detection(alert + timedelta(minutes=-1), host, "NTLM Logon from Backup Account", "medium")
    L.detection(datetime(2026, 10, 12, 15, 18), host, "RDP Logon", "informational")
    path = r"C:\Windows\testIsShareWriteable_q8w2e4r6.tmp"
    return scenario(
        "ref_admin_share_token",
        alert_text(host=host, host_ip="10.20.30.10", src_ip=src, port=51021, account="app_jdoe",
                   path=path, when="2026-10-21 08:04:14"),
        L.finish(),
        {
            "incident_confirmed_any": ["no", "inconclusive"],
            "attribution": {"actor": "svc_backup", "unresolved_ok_when": ["inconclusive"]},
            "required_content": {
                "account discrepancy": ["app_jdoe", "svc_backup"],
                "prior detection near the alert": ["NTLM Logon from Backup Account"],
            },
            "forbid_refuted_keywords": ["malicious", "compromis", "attack", "recon", "lateral"],
            "exact_iocs": [path],
            "confidence_range": [30, 85],
            "require_citations": True,
            "max_steps": 40,
        },
        "Reference-equivalent: the port join names a backup service account the "
        "alert did not; the session is off-schedule; a detection fired a minute before.",
    )


# ── 11 benign, join confirms the alert's account ─────────────────────────────
def benign() -> dict:
    L = Log("ben")
    host, src, ws = "srv-app02", "10.30.0.15", "DEPLOY01"
    for ts in daily(datetime(2026, 9, 20), 15, 2, 5):
        lid = f"0x{ts.day:02x}b"
        L.logon(ts, host, "svc_deploy", src, 49000 + ts.day, ws, lid)
        L.logoff(ts + timedelta(minutes=4), host, "svc_deploy", lid)
    alert = datetime(2026, 10, 5, 2, 5, 40)
    L.logon(alert - timedelta(seconds=1), host, "svc_deploy", src, 49822, ws, "0x77d1", key=True)
    L.privileges(alert - timedelta(seconds=1), host, "svc_deploy", "0x77d1")
    L.logoff(alert + timedelta(minutes=3), host, "svc_deploy", "0x77d1")
    for d in range(5):
        L.service_state(datetime(2026, 10, 1 + d, 2, 6), host, "AppAgent", "running")
    path = r"C:\Windows\Temp\agent_update_7.msi"
    return scenario(
        "benign_deploy_join",
        alert_text(host=host, host_ip="10.30.0.20", src_ip=src, port=49822, account="svc_deploy",
                   path=path, when="2026-10-05 02:05:40", prior=70),
        L.finish(),
        {
            "incident_confirmed": "no",
            "attribution": {"actor": "svc_deploy"},
            "required_content": {},
            "exact_iocs": [path],
            "confidence_range": [70, 100],
            "require_citations": True,
            "max_steps": 30,
        },
        "Genuinely benign: the port join confirms the alert's own account, on the "
        "nightly schedule it has kept for two weeks. High confidence is correct.",
    )


# ── 12 malicious from legitimate infrastructure ─────────────────────────────
def malicious() -> dict:
    L = Log("mal")
    host, src, ws = "srv-hr03", "10.50.0.20", "BKP-SRV02"
    for ts in daily(datetime(2026, 9, 25), 14, 21):
        lid = f"0x{ts.day:02x}c"
        L.logon(ts, host, "svc_bkp", src, 52000 + ts.day, ws, lid)
        L.logoff(ts + timedelta(minutes=2), host, "svc_bkp", lid)
    alert = datetime(2026, 10, 9, 13, 41, 7)
    lid = "0x9c41"
    L.logon(alert - timedelta(seconds=2), host, "Administrator", src, 53110, ws, lid, key=True)
    L.privileges(alert - timedelta(seconds=2), host, "Administrator", lid)
    L.service_install(alert + timedelta(seconds=20), host, "WinSvcUpd",
                      r"%COMSPEC% /c C:\Windows\upd_k2.exe", key=True)
    L.process(alert + timedelta(seconds=21), host, "Administrator", lid, r"C:\Windows\upd_k2.exe",
              r"C:\Windows\upd_k2.exe -c 10.50.0.20:443", r"C:\Windows\System32\services.exe",
              key=True)
    L.logoff(alert + timedelta(minutes=2), host, "Administrator", lid)
    L.detection(alert + timedelta(seconds=20), host, "Suspicious Service Installation", "high")
    path = r"C:\Windows\upd_k2.exe"
    return scenario(
        "malicious_from_infra",
        alert_text(host=host, host_ip="10.50.0.30", src_ip=src, port=53110, account="svc_bkp",
                   path=path, when="2026-10-09 13:41:07"),
        L.finish(),
        {
            "incident_confirmed_any": ["yes", "partial"],
            "attribution": {"actor": "Administrator"},
            "required_content": {
                "account discrepancy": ["svc_bkp", "Administrator"],
                "prior detection near the alert": ["Suspicious Service Installation"],
            },
            "techniques": ["T1021", "T1543"],
            "min_key_evidence": 1,
            "exact_iocs": [path],
            "confidence_range": [60, 100],
            "require_citations": True,
            "max_steps": 40,
        },
        "Malicious from a legitimate backup server: the join shows a local "
        "Administrator, not the backup account, then a service install. 'Known "
        "infrastructure with valid credentials' must not read as benign.",
    )


# ── 13 logs cleared around the alert ────────────────────────────────────────
def cleared() -> dict:
    L = Log("clr")
    host, src = "srv-db02", "10.60.0.33"
    for ts in daily(datetime(2026, 10, 1), 12, 4):
        lid = f"0x{ts.day:02x}d"
        L.logon(ts, host, "svc_mon", src, 58000 + ts.day, "MON01", lid)
        L.logoff(ts + timedelta(minutes=1), host, "svc_mon", lid)
    alert = datetime(2026, 10, 14, 23, 52, 3)
    cleared_at = alert + timedelta(minutes=2)
    L.log_cleared(cleared_at, host, "adm_tmp", key=True)
    L.detection(cleared_at, host, "Security Log Cleared", "high")
    docs = L.finish()
    # The clear wiped the session: record IDs jump past the alert window.
    for e in docs:
        ev = e["doc"].get("evtx") or {}
        if ev.get("event_id") == 1102:
            ev["record_id"] = 7000
    path = r"C:\Windows\svc_probe.tmp"
    return scenario(
        "logs_cleared",
        alert_text(host=host, host_ip="10.60.0.40", src_ip=src, port=60001, account="svc_mon",
                   path=path, when="2026-10-14 23:52:03"),
        docs,
        {
            "incident_confirmed_any": ["inconclusive", "partial", "yes"],
            "attribution": {"actor": "adm_tmp", "unresolved_ok_when": ["inconclusive", "partial"]},
            "required_content": {"log clearing": ["1102"]},
            "forbid_refuted_keywords": ["malicious", "compromis", "attack", "anti-forensic", "tamper"],
            "exact_iocs": [path],
            "confidence_range": [20, 80],
            "require_citations": True,
            "max_steps": 30,
        },
        "Logs cleared two minutes after the alert: the session that would answer "
        "it is gone. 'No 4624 for the port' is not 'nothing happened'.",
    )


# ── 14 the alert's account is wrong ─────────────────────────────────────────
def wrong_account() -> dict:
    L = Log("acc")
    host, src, ws = "srv-web03", "10.70.0.12", "SQLAGENT01"
    for ts in daily(datetime(2026, 9, 28), 14, 3, 15):
        lid = f"0x{ts.day:02x}e"
        L.logon(ts, host, "svc_sql", src, 50000 + ts.day, ws, lid)
        L.logoff(ts + timedelta(minutes=5), host, "svc_sql", lid)
    alert = datetime(2026, 10, 11, 3, 15, 2)
    L.logon(alert - timedelta(seconds=1), host, "svc_sql", src, 50550, ws, "0x5e11", key=True)
    L.logoff(alert + timedelta(minutes=5), host, "svc_sql", "0x5e11")
    L.logon(datetime(2026, 10, 10, 9, 12), "ws-jsmith", "jsmith", "10.70.5.21", 50123,
            "WS-JSMITH", "0x7a1", ltype="2")
    path = r"C:\Windows\Temp\sqlprobe_31.tmp"
    return scenario(
        "wrong_account_join",
        alert_text(host=host, host_ip="10.70.0.20", src_ip=src, port=50550, account="jsmith",
                   path=path, when="2026-10-11 03:15:02"),
        L.finish(),
        {
            "incident_confirmed_any": ["no", "inconclusive"],
            "attribution": {"actor": "svc_sql"},
            "required_content": {"account discrepancy": ["jsmith", "svc_sql"]},
            "exact_iocs": [path],
            "confidence_range": [50, 95],
            "require_citations": True,
            "max_steps": 30,
        },
        "The alert names the wrong account: the port join shows the nightly SQL "
        "agent account. Benign, with the discrepancy stated.",
    )


def main() -> None:
    for i, build in enumerate([reference, benign, malicious, cleared, wrong_account], start=10):
        doc = build()
        out = OUT / f"{i}_{doc['id']}.yaml"
        out.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100))
        print(f"wrote {out.name}: {len(doc['seed'])} docs")


if __name__ == "__main__":
    main()
