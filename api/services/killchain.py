"""
Reverse kill-chain assembly.

Given a confirmed-bad anchor (by fo_id, or host+timestamp), auto-assemble the
attack story for that host: walk a time window around the anchor, pull related
events, tag each with a MITRE ATT&CK tactic / kill-chain phase, order them
chronologically, and return a report-ready chain.

The ES I/O lives in `assemble_chain`. All mapping logic is pure and lives in
`event_to_phase` / `order_tactics`, so it can be unit-tested without ES.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from services.elasticsearch import build_bool_query
from services.elasticsearch import es_request as es_req
from services.elasticsearch import get_event_by_id

logger = logging.getLogger(__name__)


# Ordered ATT&CK tactics — kill-chain progression. Index in this list is the
# canonical chronological/logical ordering used to label phases and to report
# which tactics the assembled chain covers.
TACTIC_ORDER: list[str] = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Human-readable phase label per tactic id.
PHASE_LABEL: dict[str, str] = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

# Normalize the many ways a tactic can be spelled on an event's `mitre.tactic`
# (ATT&CK display names, dashed slugs, spaced slugs, shorthand) to our slug.
_TACTIC_ALIASES: dict[str, str] = {
    "initial access": "initial-access",
    "initialaccess": "initial-access",
    "ta0001": "initial-access",
    "execution": "execution",
    "ta0002": "execution",
    "persistence": "persistence",
    "ta0003": "persistence",
    "privilege escalation": "privilege-escalation",
    "privilegeescalation": "privilege-escalation",
    "priv-esc": "privilege-escalation",
    "privesc": "privilege-escalation",
    "ta0004": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "defenseevasion": "defense-evasion",
    "ta0005": "defense-evasion",
    "credential access": "credential-access",
    "credentialaccess": "credential-access",
    "cred-access": "credential-access",
    "ta0006": "credential-access",
    "discovery": "discovery",
    "ta0007": "discovery",
    "lateral movement": "lateral-movement",
    "lateralmovement": "lateral-movement",
    "ta0008": "lateral-movement",
    "collection": "collection",
    "ta0009": "collection",
    "command and control": "command-and-control",
    "commandandcontrol": "command-and-control",
    "c2": "command-and-control",
    "c&c": "command-and-control",
    "ta0011": "command-and-control",
    "exfiltration": "exfiltration",
    "exfil": "exfiltration",
    "ta0010": "exfiltration",
    "impact": "impact",
    "ta0040": "impact",
}

# Fallback: map an event's artifact_type to a default tactic when the event
# carries no `mitre.tactic`. Conservative — execution-ish artifacts default to
# execution, auth to credential-access, network to C2, etc.
_ARTIFACT_TACTIC: dict[str, str] = {
    "audit_event": "execution",
    "prefetch": "execution",
    "lnk": "execution",
    "registry": "persistence",
    "login_event": "credential-access",
    "antivirus": "defense-evasion",
    "network": "command-and-control",
    "http": "command-and-control",
    "access_log": "initial-access",
    "mft": "collection",
}


def normalize_tactic(raw: str | None) -> str | None:
    """Map a raw mitre.tactic value to one of our canonical tactic slugs, or None."""
    if not raw:
        return None
    key = str(raw).strip().lower().replace("_", "-")
    if key in TACTIC_ORDER:
        return key
    # Try alias table on both dashed and spaced forms.
    if key in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[key]
    spaced = key.replace("-", " ")
    if spaced in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[spaced]
    collapsed = key.replace("-", "").replace(" ", "")
    if collapsed in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[collapsed]
    return None


def _evtx_event_id(event: dict):
    return (event.get("evtx") or {}).get("event_id")


def _derive_tactic(event: dict) -> str:
    """Best-effort tactic slug for an event.

    Priority:
      1. mitre.tactic (normalized)
      2. artifact_type default
      3. a couple of event-id heuristics (process creation → execution,
         logon → credential-access)
      4. "execution" as a last-resort label so every step is placed.
    """
    mitre = event.get("mitre") or {}
    fromm = normalize_tactic(mitre.get("tactic"))
    if fromm:
        return fromm

    artifact = (event.get("artifact_type") or "").strip().lower()
    if artifact in _ARTIFACT_TACTIC:
        return _ARTIFACT_TACTIC[artifact]

    eid = _evtx_event_id(event)
    if eid in (4688, 1):  # process creation (EVTX 4688 / Sysmon 1)
        return "execution"
    if eid in (4624, 4625, 4768, 4769):  # logon / kerberos
        return "credential-access"
    if eid == 3:  # Sysmon network connection
        return "command-and-control"

    return "execution"


def event_to_phase(event: dict) -> dict:
    """PURE: turn one event dict into a chain step with tactic / phase labels.

    Expects an ECS-ish event dict with any of: timestamp, mitre.{tactic,id,
    technique}, artifact_type, evtx.event_id, host, user, message, fo_id.
    Returns a step dict — does NOT touch ES.
    """
    mitre = event.get("mitre") or {}
    tactic = _derive_tactic(event)
    technique = mitre.get("technique") or mitre.get("id") or ""

    host = (event.get("host") or {}).get("hostname") or ""
    user = (event.get("user") or {}).get("name") or (event.get("process") or {}).get("user") or ""

    summary = (
        event.get("message")
        or mitre.get("technique")
        or (event.get("process") or {}).get("command_line")
        or event.get("artifact_type")
        or ""
    )
    if isinstance(summary, str) and len(summary) > 280:
        summary = summary[:277] + "..."

    return {
        "ts": event.get("timestamp", ""),
        "phase": PHASE_LABEL.get(tactic, tactic),
        "tactic": tactic,
        "technique": technique,
        "host": host,
        "user": user,
        "summary": summary,
        "fo_id": event.get("fo_id"),
    }


def _ts_sort_key(step: dict):
    """Sort key: chronological by timestamp string, empties last."""
    ts = step.get("ts") or ""
    # Empty timestamps sort last; ISO8601 strings sort correctly lexically.
    return (ts == "", ts)


def order_tactics(events: list[dict]) -> dict:
    """PURE: map a list of event dicts to an ordered kill-chain.

    Returns ``{"steps": [...], "tactics_covered": [...]}`` where steps are
    sorted chronologically by timestamp and tactics_covered is the set of
    observed tactics ordered by the canonical TACTIC_ORDER. No ES.
    """
    steps = [event_to_phase(e) for e in (events or [])]
    steps.sort(key=_ts_sort_key)

    seen = {s["tactic"] for s in steps}
    tactics_covered = [t for t in TACTIC_ORDER if t in seen]
    # Any non-canonical tactic labels (shouldn't normally happen) appended last.
    tactics_covered += sorted(t for t in seen if t not in TACTIC_ORDER)

    return {"steps": steps, "tactics_covered": tactics_covered}


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        s = str(ts).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


_SOURCE_FIELDS = [
    "fo_id",
    "timestamp",
    "host",
    "user",
    "process",
    "mitre",
    "artifact_type",
    "evtx.event_id",
    "message",
    "network",
    "http",
]


def assemble_chain(
    case_id: str,
    fo_id: str | None = None,
    host: str | None = None,
    timestamp: str | None = None,
    window_minutes: int = 60,
) -> dict:
    """Assemble the reverse kill chain for a case around an anchor event.

    Provide either ``fo_id`` (the anchor event is fetched from ES) or
    ``host`` + ``timestamp``. Pulls same-host events in a ``window_minutes``
    window on each side of the anchor, ordered chronologically, tags each with
    a MITRE tactic / kill-chain phase, and returns the assembled chain.

    Returns ``{anchor, steps, tactics_covered}``.
    """
    anchor_event: dict | None = None
    if fo_id:
        anchor_event = get_event_by_id(case_id, fo_id)
        if anchor_event is None:
            return {"anchor": None, "steps": [], "tactics_covered": [], "error": "anchor not found"}
        host = host or (anchor_event.get("host") or {}).get("hostname")
        timestamp = timestamp or anchor_event.get("timestamp")

    if not host or not timestamp:
        return {
            "anchor": None,
            "steps": [],
            "tactics_covered": [],
            "error": "host and timestamp (or a resolvable fo_id) are required",
        }

    center = _parse_ts(timestamp)
    if center is None:
        return {
            "anchor": None,
            "steps": [],
            "tactics_covered": [],
            "error": f"unparseable timestamp: {timestamp!r}",
        }

    window = timedelta(minutes=max(1, int(window_minutes)))
    gte = (center - window).isoformat()
    lte = (center + window).isoformat()

    must = [{"term": {"host.hostname.keyword": host}}]
    filt = [{"range": {"timestamp": {"gte": gte, "lte": lte}}}]
    body = {
        "size": 5000,
        "query": build_bool_query(must=must, filter=filt),
        "sort": [
            {"timestamp": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}},
        ],
        "_source": _SOURCE_FIELDS,
    }

    try:
        res = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
    except Exception as exc:
        logger.warning("killchain window query failed: %s", exc)
        res = {}

    events = [h.get("_source", {}) for h in res.get("hits", {}).get("hits", [])]

    # Process ancestry: for any process events in the window, pull parent-PID
    # ancestors for the same host (they may sit just outside the window but are
    # part of the execution lineage that led to the anchor).
    ancestor_events = _fetch_process_ancestry(case_id, host, events)
    if ancestor_events:
        events = _dedup_events(events + ancestor_events)

    chain = order_tactics(events)

    if anchor_event is None:
        # Synthesize a minimal anchor from host+timestamp.
        anchor_event = {
            "host": {"hostname": host},
            "timestamp": timestamp,
        }

    chain["anchor"] = {
        "fo_id": anchor_event.get("fo_id"),
        "ts": anchor_event.get("timestamp", timestamp),
        "host": host,
        "user": (anchor_event.get("user") or {}).get("name", ""),
        "summary": anchor_event.get("message") or (anchor_event.get("mitre") or {}).get("technique")
        or "",
        "window_minutes": int(window_minutes),
    }
    return chain


def _dedup_events(events: list[dict]) -> list[dict]:
    """Drop duplicate events by fo_id (keep first), preserving order."""
    seen: set = set()
    out: list[dict] = []
    for e in events:
        key = e.get("fo_id") or id(e)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _fetch_process_ancestry(case_id: str, host: str, events: list[dict]) -> list[dict]:
    """Walk parent-PID lineage for process events, fetching ancestors by ppid.

    Bounded breadth/depth to keep it cheap. Returns extra event dicts (may be
    empty). Best-effort — any ES error yields []."""
    # Collect parent PIDs we don't already have a creation event for.
    have_pids: set = set()
    want_ppids: set = set()
    for e in events:
        proc = e.get("process") or {}
        pid = proc.get("pid")
        ppid = proc.get("ppid") or proc.get("parent_pid")
        if pid is not None and str(pid).isdigit():
            have_pids.add(int(pid))
        if ppid is not None and str(ppid).isdigit():
            want_ppids.add(int(ppid))

    collected: list[dict] = []
    depth = 0
    while want_ppids - have_pids and depth < 6:
        depth += 1
        targets = list(want_ppids - have_pids)[:50]
        body = {
            "size": len(targets) * 2 or 1,
            "query": build_bool_query(
                must=[{"term": {"host.hostname.keyword": host}}],
                filter=[{"terms": {"process.pid": targets}}],
            ),
            "sort": [
                {"timestamp": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}}
            ],
            "_source": _SOURCE_FIELDS,
        }
        try:
            res = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
        except Exception:
            break
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            break
        new_ppids: set = set()
        for h in hits:
            src = h.get("_source", {})
            collected.append(src)
            proc = src.get("process") or {}
            pid = proc.get("pid")
            ppid = proc.get("ppid") or proc.get("parent_pid")
            if pid is not None and str(pid).isdigit():
                have_pids.add(int(pid))
            if ppid is not None and str(ppid).isdigit():
                new_ppids.add(int(ppid))
        want_ppids |= new_ppids

    return collected
