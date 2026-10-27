"""Windows logon-session pivot and log-coverage check.

Two questions an analyst answers by join, never by eyeballing timestamps:

- session_pivot: *which logon session carried this action?* An alert that
  gives a source IP and port (or a logon ID) pins exactly one 4624/4625; its
  TargetLogonId then ties together everything done in that session (4672
  privileges, 5140/5145 share access, 4688 processes, 4663 object access,
  4634 logoff). "Logons in the same minute" is coincidence; this is a join.
- coverage_check: *could the log have recorded it?* Which event IDs and
  channels exist for a host and window, whether record numbers have gaps,
  whether the log was cleared (1102/104), and whether the audit policy was
  collected at all.

Both take an ``es(method, path, body)`` callable so they can be tested without
Elasticsearch. EDR session identifiers are not part of the data model; the
pivot says so instead of guessing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable

ES = Callable[[str, str, Any], dict]

LOGON_IDS = (
    "evtx.event_data.TargetLogonId.keyword",
    "evtx.event_data.SubjectLogonId.keyword",
    "evtx.event_data.LogonId.keyword",
    "process.logon_id",
)
_LOGON_FIELDS = ("TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType", "WorkstationName",
                 "IpAddress", "IpPort", "AuthenticationPackageName", "LmPackageName")
_ACTIVITY_FIELDS = ("SubjectUserName", "ShareName", "RelativeTargetName", "ObjectName", "NewProcessName",
                    "CommandLine", "PrivilegeList", "AccessMask", "ServiceName", "ImagePath")


def logon_id_forms(value: str) -> list[str]:
    """Windows logs logon IDs both padded (0x00000030c73b10cc) and short (0x30c73b10cc)."""
    v = (value or "").strip().lower()
    if not v:
        return []
    hexpart = v[2:] if v.startswith("0x") else v
    hexpart = hexpart.lstrip("0") or "0"
    return sorted({v, f"0x{hexpart}", f"0x{hexpart.zfill(16)}"})


def _host_filter(host: str) -> list[dict]:
    if not host:
        return []
    variants = sorted({host, host.lower(), host.upper()})
    return [{"terms": {"host.hostname.keyword": variants}}]


def _get(doc: dict, path: str):
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _row(src: dict, fields: tuple[str, ...]) -> dict:
    data = _get(src, "evtx.event_data") or {}
    row = {
        "fo_id": src.get("fo_id"),
        "timestamp": src.get("timestamp"),
        "event_id": _get(src, "evtx.event_id"),
        "host": _get(src, "host.hostname"),
    }
    for f in fields:
        v = data.get(f)
        if isinstance(v, str):
            v = " ".join(v.split())  # PrivilegeList and friends are multi-line
        if v not in (None, "", "-"):
            row[f] = v
    return row


def session_pivot(es: ES, index: str, *, ip: str = "", port: str | int = "", logon_id: str = "",
                  host: str = "", minutes: int = 240) -> dict:
    """Find the logon an alert's IP+port (or logon ID) belongs to, then its activity."""
    port = str(port or "").strip()
    if not (logon_id or (ip and port) or port):
        return {"query_status": "invalid",
                "query_error": 'session_pivot needs {"ip":..,"port":..} or {"logon_id":..} (host optional)'}
    must: list[dict] = [{"terms": {"evtx.event_id": [4624, 4625]}}, *_host_filter(host)]
    if logon_id:
        must.append({"terms": {"evtx.event_data.TargetLogonId.keyword": logon_id_forms(logon_id)}})
    if ip:
        must.append({"bool": {"should": [{"term": {"network.src_ip": ip}},
                                         {"term": {"evtx.event_data.IpAddress.keyword": ip}}],
                              "minimum_should_match": 1}})
    if port:
        should = [{"term": {"evtx.event_data.IpPort.keyword": port}}]
        if port.isdigit():
            should.append({"term": {"network.src_port": int(port)}})
        must.append({"bool": {"should": should, "minimum_should_match": 1}})
    res = es("POST", f"/{index}/_search", {
        "size": 5, "query": {"bool": {"filter": must}}, "sort": [{"timestamp": "asc"}],
    })
    logons = [_row(h.get("_source") or {}, _LOGON_FIELDS) for h in (res.get("hits") or {}).get("hits") or []]
    out: dict[str, Any] = {"query_status": "ok", "result_count": len(logons), "logons": logons,
                           "join": {"ip": ip, "port": port, "logon_id": logon_id, "host": host}}
    if not logons:
        out["summary"] = [
            "NO logon matches this join. Not proof of absence: the port may fall outside the "
            "collected window, the log may have rolled over or been cleared, or logon auditing "
            "is off. Run coverage_check on the host and window before concluding.",
            "EDR session IDs are not in this data model; if the alert came from an EDR, its own "
            "telemetry is the only other source for this session.",
        ]
        return out

    sessions = []
    for lg in logons[:2]:
        lid = lg.get("TargetLogonId")
        if not lid:
            continue
        start = datetime.fromisoformat(str(lg["timestamp"]).replace("Z", "+00:00"))
        flt = [
            {"bool": {"should": [{"terms": {f: logon_id_forms(lid)}} for f in LOGON_IDS],
                      "minimum_should_match": 1}},
            {"range": {"timestamp": {"gte": (start - timedelta(minutes=1)).isoformat(),
                                     "lte": (start + timedelta(minutes=minutes)).isoformat()}}},
            *_host_filter(lg.get("host") or host),
        ]
        r = es("POST", f"/{index}/_search", {
            "size": 25, "track_total_hits": True, "query": {"bool": {"filter": flt}},
            "sort": [{"timestamp": "asc"}],
            "aggs": {"ids": {"terms": {"field": "evtx.event_id", "size": 20}}},
        })
        hits = (r.get("hits") or {}).get("hits") or []
        events = [_row(h.get("_source") or {}, _ACTIVITY_FIELDS) for h in hits]
        by_id = {str(b["key"]): b["doc_count"] for b in ((r.get("aggregations") or {}).get("ids") or {}).get("buckets", [])}
        logoff = next((e["timestamp"] for e in events if e.get("event_id") in (4634, 4647)), None)
        sessions.append({"logon_id": lid, "account": lg.get("TargetUserName"),
                         "total_events": ((r.get("hits") or {}).get("total") or {}).get("value", len(events)),
                         "by_event_id": by_id, "logoff": logoff, "events": events})
    out["sessions"] = sessions
    summary = []
    for lg in logons[:3]:
        summary.append(
            f"JOIN → fo_id={lg['fo_id']} {lg.get('timestamp')} event {lg.get('event_id')} "
            f"account={lg.get('TargetUserName')} logon_id={lg.get('TargetLogonId')} type={lg.get('LogonType')} "
            f"from {lg.get('IpAddress')}:{lg.get('IpPort')} ({lg.get('WorkstationName')}) "
            f"auth={lg.get('AuthenticationPackageName')}")
    for s in sessions:
        summary.append(
            f"session {s['logon_id']} ({s['account']}): {s['total_events']} event(s) by ID {s['by_event_id']}"
            + (f", logoff {s['logoff']}" if s["logoff"] else ", no logoff seen"))
        for e in s["events"][:8]:
            extra = " ".join(f"{k}={v}" for k, v in e.items() if k not in ("fo_id", "timestamp", "event_id", "host"))
            summary.append(f"  {e['timestamp']} {e['event_id']} fo_id={e['fo_id']} {extra}"[:240])
    if len(logons) > 1:
        summary.append(f"⚠ {len(logons)} logons match — the join is ambiguous; narrow by host or time.")
    out["summary"] = summary
    return out


def coverage_check(es: ES, index: str, *, host: str = "", start: str = "", end: str = "") -> dict:
    """What the collected logs can and cannot show for a host and window."""
    if not (start and end):
        return {"query_status": "invalid",
                "query_error": 'coverage_check needs {"start":ISO,"end":ISO} (host optional)'}
    window = [{"range": {"timestamp": {"gte": start, "lte": end}}}, *_host_filter(host)]
    res = es("POST", f"/{index}/_search", {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [{"term": {"artifact_type": "evtx"}}, *window]}},
        "aggs": {
            "channels": {"terms": {"field": "evtx.channel", "size": 15},
                         "aggs": {"rmin": {"min": {"field": "evtx.record_id"}},
                                  "rmax": {"max": {"field": "evtx.record_id"}}}},
            "ids": {"terms": {"field": "evtx.event_id", "size": 40}},
            "cleared": {"filter": {"terms": {"evtx.event_id": [1102, 104]}},
                        "aggs": {"when": {"terms": {"field": "timestamp", "size": 5}}}},
        },
    })
    a = res.get("aggregations") or {}
    total = ((res.get("hits") or {}).get("total") or {}).get("value", 0)
    channels = []
    gaps = []
    for b in (a.get("channels") or {}).get("buckets", []):
        lo, hi, n = (b.get("rmin") or {}).get("value"), (b.get("rmax") or {}).get("value"), b["doc_count"]
        channels.append({"channel": b["key"], "events": n, "record_min": lo, "record_max": hi})
        if lo is not None and hi is not None and (hi - lo + 1) > n:
            gaps.append(f"{b['key']}: {int(hi - lo + 1 - n)} record number(s) missing between {int(lo)} and {int(hi)}")
    ids = {str(b["key"]): b["doc_count"] for b in (a.get("ids") or {}).get("buckets", [])}
    cleared = (a.get("cleared") or {}).get("doc_count", 0)

    audit = es("POST", f"/{index}/_search", {
        "size": 1, "query": {"bool": {"filter": [*_host_filter(host)],
                                      "must": [{"query_string": {"query": "*auditpol* OR \"Audit Policy\" OR PolAdtEv",
                                                                 "lenient": True}}]}},
    })
    audit_hits = ((audit.get("hits") or {}).get("total") or {}).get("value", 0)

    summary = [f"{total} evtx event(s) {('on ' + host) if host else ''} between {start} and {end}"]
    if channels:
        summary.append("channels: " + ", ".join(f"{c['channel']} ({c['events']})" for c in channels))
    if ids:
        summary.append("event IDs present: " + ", ".join(f"{k}×{v}" for k, v in list(ids.items())[:25]))
    summary.extend(f"⚠ record gap — {g}" for g in gaps)
    if cleared:
        summary.append(f"⚠ log cleared (1102/104) {cleared}× in this window")
    summary.append(
        "audit policy: collected (see the auditpol / policy artifact)" if audit_hits else
        "audit policy: NOT collected — which categories were enabled is unknown; say so instead of assuming"
    )
    if total == 0:
        summary.append("no evtx at all in this window — nothing can be concluded from absence here")
    return {"query_status": "ok", "result_count": total, "channels": channels, "event_ids": ids,
            "record_gaps": gaps, "log_cleared": cleared, "audit_policy_collected": bool(audit_hits),
            "summary": summary}
