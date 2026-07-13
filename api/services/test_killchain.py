"""
Unit tests for the PURE kill-chain mapping helpers (no live ES).

Covers: tactic mapping (from mitre.tactic, artifact_type, event-id heuristics),
chronological ordering, and tactics_covered ordering.
"""

from __future__ import annotations

from services.killchain import (
    TACTIC_ORDER,
    event_to_phase,
    normalize_tactic,
    order_tactics,
)


def test_normalize_tactic_variants():
    assert normalize_tactic("Initial Access") == "initial-access"
    assert normalize_tactic("initial-access") == "initial-access"
    assert normalize_tactic("PrivilegeEscalation") == "privilege-escalation"
    assert normalize_tactic("priv-esc") == "privilege-escalation"
    assert normalize_tactic("C2") == "command-and-control"
    assert normalize_tactic("Command and Control") == "command-and-control"
    assert normalize_tactic("exfil") == "exfiltration"
    assert normalize_tactic("TA0040") == "impact"
    assert normalize_tactic("") is None
    assert normalize_tactic(None) is None
    assert normalize_tactic("nonsense") is None


def test_event_to_phase_from_mitre_tactic():
    ev = {
        "timestamp": "2026-06-13T10:00:00Z",
        "mitre": {"tactic": "Persistence", "technique": "Registry Run Keys", "id": "T1547.001"},
        "host": {"hostname": "WIN-1"},
        "user": {"name": "admin"},
        "message": "reg add ...run key",
        "fo_id": "abc",
    }
    step = event_to_phase(ev)
    assert step["tactic"] == "persistence"
    assert step["phase"] == "Persistence"
    assert step["technique"] == "Registry Run Keys"
    assert step["host"] == "WIN-1"
    assert step["user"] == "admin"
    assert step["fo_id"] == "abc"


def test_event_to_phase_artifact_fallback():
    ev = {"timestamp": "t", "artifact_type": "registry", "host": {}, "user": {}}
    assert event_to_phase(ev)["tactic"] == "persistence"

    ev2 = {"timestamp": "t", "artifact_type": "login_event"}
    assert event_to_phase(ev2)["tactic"] == "credential-access"

    ev3 = {"timestamp": "t", "artifact_type": "network"}
    assert event_to_phase(ev3)["tactic"] == "command-and-control"


def test_event_to_phase_security_event_ids():
    proc = {"timestamp": "t", "evtx": {"event_id": 4688}}
    assert event_to_phase(proc)["tactic"] == "execution"

    logon = {"timestamp": "t", "evtx": {"event_id": 4624}}
    assert event_to_phase(logon)["tactic"] == "lateral-movement"

    failed_logon = {"timestamp": "t", "evtx": {"event_id": 4625}}
    assert event_to_phase(failed_logon)["tactic"] == "credential-access"

    kerberoast = {"timestamp": "t", "evtx": {"event_id": 4769}}
    assert event_to_phase(kerberoast)["tactic"] == "credential-access"

    svc = {"timestamp": "t", "evtx": {"event_id": 7045}}
    assert event_to_phase(svc)["tactic"] == "persistence"

    log_cleared = {"timestamp": "t", "evtx": {"event_id": 1102}}
    assert event_to_phase(log_cleared)["tactic"] == "defense-evasion"

    priv = {"timestamp": "t", "evtx": {"event_id": 4672}}
    assert event_to_phase(priv)["tactic"] == "privilege-escalation"

    # ECS event.code is honoured when the evtx block is absent.
    ecs_proc = {"timestamp": "t", "event": {"code": "4688"}}
    assert event_to_phase(ecs_proc)["tactic"] == "execution"


def test_event_to_phase_sysmon_event_ids():
    # Sysmon IDs only resolve when the channel/provider says Sysmon.
    netconn = {
        "timestamp": "t",
        "evtx": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational"},
    }
    assert event_to_phase(netconn)["tactic"] == "command-and-control"

    lsass = {"timestamp": "t", "evtx": {"event_id": 10, "provider": "Microsoft-Windows-Sysmon"}}
    assert event_to_phase(lsass)["tactic"] == "credential-access"

    dns = {
        "timestamp": "t",
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational"},
        "evtx": {"event_id": 22},
    }
    assert event_to_phase(dns)["tactic"] == "command-and-control"

    # Same low ID with no Sysmon hint is NOT treated as Sysmon → falls through.
    ambiguous = {"timestamp": "t", "evtx": {"event_id": 3}}
    assert event_to_phase(ambiguous)["tactic"] == "execution"


def test_event_to_phase_summary_truncation():
    ev = {"timestamp": "t", "message": "x" * 400}
    s = event_to_phase(ev)["summary"]
    assert len(s) == 280 and s.endswith("...")


def test_order_tactics_chronological():
    events = [
        {"timestamp": "2026-06-13T12:00:00Z", "mitre": {"tactic": "Impact"}, "fo_id": "3"},
        {"timestamp": "2026-06-13T10:00:00Z", "mitre": {"tactic": "Initial Access"}, "fo_id": "1"},
        {"timestamp": "2026-06-13T11:00:00Z", "mitre": {"tactic": "Execution"}, "fo_id": "2"},
    ]
    chain = order_tactics(events)
    fo_order = [s["fo_id"] for s in chain["steps"]]
    assert fo_order == ["1", "2", "3"], "steps must be chronological"


def test_order_tactics_empty_ts_sorts_last():
    events = [
        {"timestamp": "", "mitre": {"tactic": "Execution"}, "fo_id": "nots"},
        {"timestamp": "2026-06-13T10:00:00Z", "mitre": {"tactic": "Execution"}, "fo_id": "withts"},
    ]
    chain = order_tactics(events)
    assert [s["fo_id"] for s in chain["steps"]] == ["withts", "nots"]


def test_tactics_covered_canonical_order():
    # Provided out of order; tactics_covered must follow TACTIC_ORDER.
    events = [
        {"timestamp": "2026-06-13T10:03:00Z", "mitre": {"tactic": "Impact"}},
        {"timestamp": "2026-06-13T10:01:00Z", "mitre": {"tactic": "Execution"}},
        {"timestamp": "2026-06-13T10:00:00Z", "mitre": {"tactic": "Initial Access"}},
        {"timestamp": "2026-06-13T10:02:00Z", "mitre": {"tactic": "Persistence"}},
    ]
    covered = order_tactics(events)["tactics_covered"]
    assert covered == ["initial-access", "execution", "persistence", "impact"]
    # And they appear in the same relative order as the canonical list.
    idxs = [TACTIC_ORDER.index(t) for t in covered]
    assert idxs == sorted(idxs)


def test_tactics_covered_dedup():
    events = [
        {"timestamp": "2026-06-13T10:00:00Z", "mitre": {"tactic": "Execution"}},
        {"timestamp": "2026-06-13T10:05:00Z", "mitre": {"tactic": "Execution"}},
    ]
    assert order_tactics(events)["tactics_covered"] == ["execution"]


def test_order_tactics_empty():
    chain = order_tactics([])
    assert chain == {"steps": [], "tactics_covered": []}
