"""Unit tests for the findings triage queue (router + service).

Mirrors the existing router test style: no live Elasticsearch — the service's
``es_req`` alias is monkeypatched with a fake that captures the request body
and returns canned ES responses, and route functions are called directly with
``_acl={}`` to bypass the auth dependency.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import HTTPException  # noqa: E402
from services import findings as fnd  # noqa: E402

from routers import findings as fr  # noqa: E402

# ── service: set_triage_status ───────────────────────────────────────────────


def test_set_triage_status_uses_update_by_query(monkeypatch):
    calls: list[tuple[str, str, dict]] = []

    def fake(method, path, body=None):
        calls.append((method, path, body))
        return {"updated": 3}

    monkeypatch.setattr(fnd, "es_req", fake)
    n = fnd.set_triage_status("c1", ["f1", "f2", "f3"], "reviewed")
    assert n == 3
    method, path, body = calls[0]
    assert method == "POST"
    assert path.startswith("/fo-case-c1-finding/_update_by_query")
    assert "refresh=true" in path
    assert body["query"] == {"terms": {"finding_id": ["f1", "f2", "f3"]}}
    assert body["script"]["params"] == {"status": "reviewed"}


def test_set_triage_status_rejects_unknown_status():
    with pytest.raises(ValueError):
        fnd.set_triage_status("c1", ["f1"], "bogus")


def test_set_triage_status_empty_ids_is_noop(monkeypatch):
    monkeypatch.setattr(
        fnd, "es_req", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no ES call"))
    )
    assert fnd.set_triage_status("c1", [], "open") == 0


def test_set_triage_status_es_failure_returns_zero(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("ES down")

    monkeypatch.setattr(fnd, "es_req", boom)
    assert fnd.set_triage_status("c1", ["f1"], "reviewed") == 0


# ── service: triage_list ─────────────────────────────────────────────────────


def _agg_response(total=2):
    return {
        "hits": {
            "total": {"value": total},
            "hits": [
                {"_id": "f1", "_source": {"finding_id": "f1", "severity": "high"}},
                {"_id": "f2", "_source": {"finding_id": "f2", "severity": "low"}},
            ],
        },
        "aggregations": {
            "queue": {
                "by_status": {
                    "buckets": [
                        {
                            "key": "open",
                            "doc_count": 5,
                            "by_severity": {"buckets": [{"key": "high", "doc_count": 2}]},
                        },
                        {
                            "key": "false_positive",
                            "doc_count": 1,
                            "by_severity": {"buckets": []},
                        },
                    ]
                },
                "by_kind": {"buckets": [{"key": "ioc", "doc_count": 6}]},
                "by_source": {"buckets": [{"key": "ioc-extract", "doc_count": 6}]},
            }
        },
    }


def test_triage_list_returns_findings_and_counts(monkeypatch):
    monkeypatch.setattr(fnd, "es_req", lambda *a, **k: _agg_response())
    out = fnd.triage_list("c1")
    assert out["total"] == 2
    assert [f["finding_id"] for f in out["findings"]] == ["f1", "f2"]
    assert out["counts"]["by_status"] == {"open": 5, "reviewed": 0, "false_positive": 1}
    assert out["counts"]["by_status_severity"]["open"] == {"high": 2}
    assert out["counts"]["by_kind"] == {"ioc": 6}
    assert out["counts"]["by_source"] == {"ioc-extract": 6}


def test_triage_list_sorts_severity_then_timestamp_desc(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(fnd, "es_req", lambda m, p, body=None: calls.append(body) or _agg_response())
    fnd.triage_list("c1")
    assert calls[0]["sort"] == [
        {"severity_int": {"order": "desc", "unmapped_type": "integer"}},
        {"timestamp": {"order": "desc", "unmapped_type": "date"}},
    ]


def test_triage_list_open_filter_matches_missing_status(monkeypatch):
    """Backwards compat: findings written before triage have no status field."""
    calls: list[dict] = []
    monkeypatch.setattr(fnd, "es_req", lambda m, p, body=None: calls.append(body) or _agg_response())
    fnd.triage_list("c1", status="open")
    status_filter = calls[0]["query"]["bool"]["filter"][-1]
    should = status_filter["bool"]["should"]
    assert {"term": {"triage_status.keyword": "open"}} in should
    assert {"bool": {"must_not": {"exists": {"field": "triage_status"}}}} in should


def test_triage_list_other_status_is_plain_term(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(fnd, "es_req", lambda m, p, body=None: calls.append(body) or _agg_response())
    fnd.triage_list("c1", status="false_positive")
    assert {"term": {"triage_status.keyword": "false_positive"}} in calls[0]["query"]["bool"]["filter"]


def test_triage_list_filters_use_keyword_subfields(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(fnd, "es_req", lambda m, p, body=None: calls.append(body) or _agg_response())
    fnd.triage_list("c1", severity="high", kind="ioc", source="ioc-extract")
    filters = calls[0]["query"]["bool"]["filter"]
    assert {"term": {"severity.keyword": "high"}} in filters
    assert {"term": {"kind.keyword": "ioc"}} in filters
    assert {"term": {"source_feature.keyword": "ioc-extract"}} in filters


def test_triage_list_counts_ignore_status_filter_but_keep_others(monkeypatch):
    """Faceted-search contract: selecting a status must not collapse the other
    status buckets, while severity/kind/source filters still scope the counts."""
    calls: list[dict] = []
    monkeypatch.setattr(fnd, "es_req", lambda m, p, body=None: calls.append(body) or _agg_response())
    fnd.triage_list("c1", status="open", severity="high")
    queue_filter = calls[0]["aggs"]["queue"]["filter"]
    assert queue_filter == {"bool": {"filter": [{"term": {"severity.keyword": "high"}}]}}


def test_triage_list_caps_size(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(fnd, "es_req", lambda m, p, body=None: calls.append(body) or _agg_response())
    fnd.triage_list("c1", size=500)
    assert calls[0]["size"] == 500


def test_triage_list_es_failure_is_legit_empty(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no such index")

    monkeypatch.setattr(fnd, "es_req", boom)
    out = fnd.triage_list("c1")
    assert out["findings"] == [] and out["total"] == 0
    assert out["counts"]["by_status"] == {"open": 0, "reviewed": 0, "false_positive": 0}


# ── router: endpoints ────────────────────────────────────────────────────────


def test_post_triage_bulk_sets_status(monkeypatch):
    seen: list[tuple] = []
    monkeypatch.setattr(
        fnd, "set_triage_status", lambda c, ids, s: seen.append((c, ids, s)) or 2
    )
    out = fr.set_findings_triage(
        "c1", fr.TriageIn(finding_ids=["f1", "f2"], status="reviewed"), _acl={}
    )
    assert out == {"updated": 2, "status": "reviewed"}
    assert seen == [("c1", ["f1", "f2"], "reviewed")]


def test_post_triage_rejects_bad_status():
    with pytest.raises(HTTPException) as exc_info:
        fr.set_findings_triage("c1", fr.TriageIn(finding_ids=["f1"], status="nope"), _acl={})
    assert exc_info.value.status_code == 400


def test_post_triage_rejects_empty_ids():
    with pytest.raises(HTTPException) as exc_info:
        fr.set_findings_triage("c1", fr.TriageIn(finding_ids=[], status="open"), _acl={})
    assert exc_info.value.status_code == 400


def test_get_triage_passes_filters_through(monkeypatch):
    seen: dict = {}

    def fake(case_id, **kwargs):
        seen.update(kwargs)
        return {"findings": [], "total": 0, "size": 500, "counts": {}}

    monkeypatch.setattr(fnd, "triage_list", fake)
    out = fr.triage_case_findings(
        "c1", _acl={}, status="open", severity="high", kind="ioc", source="mod", size=500
    )
    assert out["total"] == 0
    assert seen == {
        "status": "open",
        "severity": "high",
        "kind": "ioc",
        "source": "mod",
        "size": 500,
    }


def test_get_triage_rejects_bad_status():
    with pytest.raises(HTTPException) as exc_info:
        fr.triage_case_findings(
            "c1", _acl={}, status="weird", severity=None, kind=None, source=None, size=500
        )
    assert exc_info.value.status_code == 400
