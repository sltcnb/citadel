import json

from pilot.forensics import coverage_check, logon_id_forms, session_pivot

LOGON = {"fo_id": "e1", "timestamp": "2026-10-21T08:04:14.217Z", "host": {"hostname": "srv-x01"},
         "evtx": {"event_id": 4624, "event_data": {
             "TargetUserName": "svc_a", "TargetLogonId": "0x00000030c73b10cc", "LogonType": "3",
             "WorkstationName": "BKP01", "IpAddress": "10.0.0.5", "IpPort": "51021",
             "AuthenticationPackageName": "NTLM"}}}
SHARE = {"fo_id": "e2", "timestamp": "2026-10-21T08:04:14.300Z", "host": {"hostname": "srv-x01"},
         "evtx": {"event_id": 5145, "event_data": {"SubjectLogonId": "0x30c73b10cc", "ShareName": "\\\\*\\ADMIN$",
                                                   "RelativeTargetName": "testX.tmp"}}}


class FakeES:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.bodies = []

    def __call__(self, method, path, body):
        self.bodies.append(body)
        return self.responses.pop(0)


def hits(*docs, aggs=None):
    return {"hits": {"total": {"value": len(docs)}, "hits": [{"_source": d} for d in docs]},
            "aggregations": aggs or {}}


def test_logon_id_forms_cover_padded_and_short():
    assert logon_id_forms("0x30C73B10CC") == ["0x00000030c73b10cc", "0x30c73b10cc"]
    assert "0x30c73b10cc" in logon_id_forms("0x00000030c73b10cc")


def test_pivot_joins_ip_and_port_then_follows_the_logon_id():
    es = FakeES(hits(LOGON), hits(LOGON, SHARE, aggs={"ids": {"buckets": [
        {"key": 4624, "doc_count": 1}, {"key": 5145, "doc_count": 1}]}}))
    out = session_pivot(es, "idx", ip="10.0.0.5", port=51021, host="srv-x01")
    first = json.dumps(es.bodies[0])
    assert '"evtx.event_data.IpPort.keyword": "51021"' in first and '"network.src_port": 51021' in first
    assert '"10.0.0.5"' in first
    follow = json.dumps(es.bodies[1])
    assert "0x30c73b10cc" in follow and "0x00000030c73b10cc" in follow
    assert out["logons"][0]["TargetUserName"] == "svc_a"
    s = out["sessions"][0]
    assert s["by_event_id"] == {"4624": 1, "5145": 1} and s["logoff"] is None
    text = "\n".join(out["summary"])
    assert "JOIN → fo_id=e1" in text and "account=svc_a" in text and "ShareName" in text


def test_pivot_without_a_match_says_what_absence_does_not_prove():
    out = session_pivot(FakeES(hits()), "idx", ip="10.0.0.5", port="1")
    assert out["result_count"] == 0
    assert "Not proof of absence" in out["summary"][0] and "coverage_check" in out["summary"][0]
    assert "EDR session IDs are not in this data model" in out["summary"][1]


def test_pivot_requires_a_join_key():
    assert session_pivot(FakeES(), "idx", ip="10.0.0.5")["query_status"] == "invalid"


def test_coverage_reports_gaps_clears_and_missing_audit_policy():
    agg = {"channels": {"buckets": [{"key": "Security", "doc_count": 40,
                                      "rmin": {"value": 1001}, "rmax": {"value": 1100}}]},
           "ids": {"buckets": [{"key": 4624, "doc_count": 30}, {"key": 1102, "doc_count": 1}]},
           "cleared": {"doc_count": 1}}
    es = FakeES({"hits": {"total": {"value": 40}}, "aggregations": agg}, {"hits": {"total": {"value": 0}}})
    out = coverage_check(es, "idx", host="srv-x01", start="2026-10-14T23:00:00Z", end="2026-10-15T00:00:00Z")
    assert out["record_gaps"] == ["Security: 60 record number(s) missing between 1001 and 1100"]
    assert out["log_cleared"] == 1 and out["audit_policy_collected"] is False
    text = "\n".join(out["summary"])
    assert "record gap" in text and "log cleared" in text and "audit policy: NOT collected" in text


def test_coverage_needs_a_window():
    assert coverage_check(FakeES(), "idx", host="h")["query_status"] == "invalid"
