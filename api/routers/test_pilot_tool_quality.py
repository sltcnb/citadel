"""Tool defects that starved a real investigation (case 0a1b2c3d4e5f): the
agent called a Veeam server "unidentified" because every pivot on its IP
returned nothing, host_profile reported no data for a 309k-event host, and the
one event it inspected was rendered without its network fields."""
import io
import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pilot import service as s  # noqa: E402


def test_message_wildcards_also_search_structured_fields():
    assert s._widen_message_terms("message:*10.20.30.40*") == (
        "(message:*10.20.30.40* OR *10.20.30.40*)"
    )
    q = "host.hostname:ws1 AND message:*jdoe*"
    assert s._widen_message_terms(q) == "host.hostname:ws1 AND (message:*jdoe* OR *jdoe*)"
    # grouped / multi-term forms are left alone rather than mangled
    assert s._widen_message_terms("message:(*a* AND *b*)") == "message:(*a* AND *b*)"
    assert s._widen_message_terms("user.name:bob") == "user.name:bob"


def test_numeric_aggregation_does_not_send_a_string_placeholder(monkeypatch):
    import services.elasticsearch as es

    sent = []

    def fake_req(method, path, body):
        sent.append(body)
        return {
            "hits": {"total": {"value": 5}},
            "aggregations": {
                "terms": {"buckets": [{"key": 4624, "doc_count": 3}]},
                "absent": {"doc_count": 2},
            },
        }

    monkeypatch.setattr(es, "_request", fake_req)
    out = s._tool_aggregate("c1", {"agg_field": "evtx.event_id", "agg_query": "*"})
    assert "missing" not in json.dumps(sent[0]["aggs"]["terms"])
    assert out["agg_buckets"] == [{"value": 4624, "count": 3}, {"value": "(none)", "count": 2}]


def test_es_error_reason_reaches_the_model():
    body = json.dumps({"error": {"root_cause": [{"reason": "failed to parse [(none)] as long"}]}})
    exc = urllib.error.HTTPError("u", 400, "Bad Request", {}, io.BytesIO(body.encode()))
    assert "failed to parse [(none)] as long" in s._es_error_text(exc)


def test_host_profile_adapter_reads_the_aggregate_tool_output(monkeypatch):
    monkeypatch.setattr(
        s,
        "_tool_aggregate",
        lambda cid, step: {
            "query_status": "ok",
            "agg_buckets": [{"value": "evtx", "count": 298024}, {"value": "(none)", "count": 3}],
        },
    )
    assert s._skill_aggregate_adapter("c1")("artifact_type", "*", 12) == ["evtx (298024)"]


def test_inspect_shows_where_a_logon_came_from():
    ev = {
        "timestamp": "2026-10-21T08:23:27Z",
        "message": "Account logon success on ws1",
        "user": {"name": "svc_backup"},
        "network": {"src_ip": "10.20.30.40", "workstation": "BKP-SRV01"},
        "evtx": {"event_id": 4624, "event_data": {"LogonType": "3", "SubjectUserSid": "S-1-0-0", "IpPort": "-"}},
    }
    fields = dict(s._inspect_fields(ev))
    assert fields["network.workstation"] == "BKP-SRV01"
    assert fields["network.src_ip"] == "10.20.30.40"
    assert fields["event_data.LogonType"] == "3"
    assert "event_data.SubjectUserSid" not in fields and "event_data.IpPort" not in fields
    rendered = s._agent_step_history([{"step": 1, "action": "inspect", "fo_id": "x", "event": ev}])
    assert "BKP-SRV01" in rendered


def test_search_profile_is_rendered_for_the_model():
    step = {
        "step": 2, "action": "search", "query": "q", "result_count": 46,
        "profile": ["workstation: BKP-SRV01 (46)", "seen: … on 18 distinct day(s); typical day 4"],
    }
    out = s._agent_step_history([step])
    assert "BKP-SRV01" in out and "18 distinct day(s)" in out


def test_event_data_fields_are_aliased_to_their_real_path():
    q = s._normalize_agent_query("event_id:4624 AND event_data.TargetUserName:app_x")
    assert q == "evtx.event_id:4624 AND evtx.event_data.TargetUserName:app_x"
    assert s._normalize_agent_query("evtx.event_id:4624") == "evtx.event_id:4624"


def test_broadening_may_not_drop_time_or_event_id_filters():
    q = 'evtx.event_id:4624 AND user.name:bob AND timestamp:[2026-10-21T07:30:00Z TO 2026-10-21T09:00:00Z]'
    keep = s._hard_constraints(q)
    assert "timestamp:[2026-10-21T07:30:00Z TO 2026-10-21T09:00:00Z]" in keep
    assert any(k.startswith("evtx.event_id:4624") for k in keep)
    assert s._hard_constraints("message:*bob*") == []


def test_hour_baseline_flags_the_one_off_hour():
    buckets = [{"key_as_string": f"2026-10-{d:02d}T19:00:00.000Z"} for d in range(4, 21)]
    buckets.append({"key_as_string": "2026-10-21T08:00:00.000Z"})
    line = s._hour_baseline(buckets, 18)
    assert "19h on 17 days" in line
    assert "08h on 1 day only (2026-10-21) ← off-schedule" in line
    assert s._hour_baseline(buckets, 3) == ""  # too little history to call anything


def test_profile_flags_a_spike_instead_of_calling_it_routine(monkeypatch):
    import services.elasticsearch as es

    days = [{"key_as_string": f"2026-10-{d:02d}T00:00:00.000Z", "doc_count": 4} for d in range(4, 21)]
    days.append({"key_as_string": "2026-10-21T00:00:00.000Z", "doc_count": 24})
    monkeypatch.setattr(es, "_request", lambda *a, **k: {"aggregations": {
        "first": {"value_as_string": "2026-10-04T19:00:23Z"},
        "last": {"value_as_string": "2026-10-21T08:23:27Z"},
        "days": {"buckets": days},
    }})
    seen = next(line for line in s._hit_profile("i", "q") if line.startswith("seen:"))
    assert "6× the typical day" in seen and "NOT routine" in seen


def test_zero_hits_says_whether_the_event_type_exists_at_all(monkeypatch):
    import services.elasticsearch as es

    monkeypatch.setattr(es, "_request", lambda *a, **k: {"aggregations": {
        "id5145": {"doc_count": 0},
        "id4624": {"doc_count": 5286},
        "clear": {"doc_count": 0},
        "span_first": {"value_as_string": "2026-10-04T00:00:00Z"},
        "span_last": {"value_as_string": "2026-10-21T15:10:00Z"},
    }})
    note = s._event_id_coverage("i", "evtx.event_id:5145 OR evtx.event_id:4624")
    assert "event 5145 occurs 0 times in the WHOLE case" in note and "VERIFIED collection gap" in note
    assert "no Security log clear (1102)" in note
    assert "event 4624 exists elsewhere in the case (5286×)" in note and "REAL negative" in note


def test_review_blockers_only_when_the_reviewer_says_it_does_not_hold():
    assert s._review_blockers({"holds": True, "issues": ["minor"]}) == []
    assert s._review_blockers(None) == []
    assert s._review_blockers({"holds": False, "issues": ["port not correlated", " "]}) == ["port not correlated"]


def test_scenario_sanitiser_keeps_windows_paths_verbatim():
    for path in (r"C:\Windows\testX.tmp", r"C:\a\new\run", r"\\srv\ADMIN$\t.exe"):
        assert path in s._sanitize_scenario(f"dropped {path} via SMB")


def test_duplicate_detection_ignores_spacing_and_operator_case():
    assert s._canon_arg("a  and   b OR c") == s._canon_arg("a AND b or c")
    assert s._canon_arg(5) == 5


def test_broadening_names_the_filters_it_dropped():
    q = 'user.name:bob AND timestamp:[2026-01-01T00:00:00Z TO 2026-01-02T00:00:00Z] AND network.src_ip:10.0.0.1'
    assert s._dropped_clauses(q, "user.name:bob") == [
        "timestamp:[2026-01-01T00:00:00Z TO 2026-01-02T00:00:00Z]", "network.src_ip:10.0.0.1"]


def test_broadened_result_is_rendered_with_an_unmissable_header():
    step = {"step": 4, "action": "search", "query": "a AND b", "result_count": 0,
            "broadened": {"query": "a", "result_count": 1241, "filters_dropped": ["b"]}}
    out = s._agent_step_history([step])
    assert "FILTERS DROPPED: b" in out and "NOT scoped" in out


def test_inspecting_one_of_n_says_so_and_suggests_the_aggregate():
    transcript = [{"step": 3, "action": "search", "result_count": 6, "sample_ids": ["e1", "e2", "e3"]}]
    step = {"action": "inspect", "fo_id": "e2",
            "event": {"evtx": {"event_data": {"CallerProcessName": r"C:\x\edr.exe", "TargetUserName": "u"}}}}
    note = s._one_of_n_note(step, transcript)
    assert "1 of 6 events from step 3" in note
    assert "evtx.event_data.CallerProcessName.keyword" in note
    assert s._one_of_n_note({"fo_id": "zz", "event": {}}, transcript) == ""


def test_zero_hit_coverage_is_scoped_to_host_and_window(monkeypatch):
    import services.elasticsearch as es

    def fake(method, path, body):
        names = set(body["aggs"])
        assert {"host5145", "case5145", "in_window", "clear_near"} <= names
        return {"aggregations": {
            "case5145": {"doc_count": 0}, "host5145": {"doc_count": 0},
            "case4624": {"doc_count": 900}, "host4624": {"doc_count": 300},
            "in_window": {"doc_count": 42}, "clear_near": {"doc_count": 1},
            "clear_any": {"doc_count": 1}, "span_first": {"value_as_string": "2026-10-01T00:00:00Z"},
            "span_last": {"value_as_string": "2026-10-20T00:00:00Z"},
        }}

    monkeypatch.setattr(es, "_request", fake)
    q = ('host.hostname:srv-x01 AND (evtx.event_id:5145 OR evtx.event_id:4624) AND '
         'timestamp:[2026-10-14T23:00:00Z TO 2026-10-15T00:00:00Z]')
    note = s._zero_hit_coverage("i", q)
    assert "on srv-x01 in the window" in note
    assert "42 evtx event(s) exist" in note
    assert "absence may be ERASURE" in note
    assert "event 5145 occurs 0 times in the WHOLE case" in note
    assert "event 4624 is collected (300× on srv-x01)" in note
