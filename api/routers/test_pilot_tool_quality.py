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
