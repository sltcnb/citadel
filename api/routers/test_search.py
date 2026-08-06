"""Unit tests for the search/timeline router with a mocked Elasticsearch layer.

Covers the behaviours fixed in the timeline & search audit:
  - field filters use the fields the live template actually maps
    (``evtx.channel`` / ``http.method`` are plain keywords — no ``.keyword``),
  - the domain filter spans the DNS fields parsers really emit,
  - an Elasticsearch 400 surfaces as an HTTP 400 instead of "0 results",
  - pinned events come back newest-first,
  - shallow ``page`` paging past the 10k window is rejected (use search_after).
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import HTTPException  # noqa: E402
from services import elasticsearch as es  # noqa: E402

from routers import search as sr  # noqa: E402


@pytest.fixture(autouse=True)
def _case_exists(monkeypatch):
    monkeypatch.setattr(sr, "get_case", lambda case_id: {"case_id": case_id})


@pytest.fixture
def captured_search(monkeypatch):
    """Stub es.search_events; returns the kwargs it was called with."""
    calls: list[dict] = []

    def fake(**kwargs):
        calls.append(kwargs)
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(es, "search_events", fake)
    return calls


def _search_kwargs(**overrides):
    kw = {
        "case_id": "c1",
        "_acl": {},
        "q": "",
        "artifact_type": None,
        "from_ts": None,
        "to_ts": None,
        "hostname": None,
        "username": None,
        "event_id": None,
        "channel": None,
        "src_ip": None,
        "dest_ip": None,
        "status_code": None,
        "http_method": None,
        "domain": None,
        "flagged": None,
        "tags": None,
        "regexp": False,
        "sort_field": "timestamp",
        "sort_order": "asc",
        "page": 0,
        "size": 50,
        "search_after": None,
    }
    kw.update(overrides)
    return kw


def _http_error(code: int, body: dict | None = None) -> urllib.error.HTTPError:
    payload = json.dumps(body or {}).encode()
    return urllib.error.HTTPError(
        "http://es:9200/x", code, f"HTTP {code}", {}, io.BytesIO(payload)
    )


# ── keyword-field filters (#1, #2, #3) ───────────────────────────────────────


def test_channel_filter_uses_plain_keyword_field(captured_search):
    sr.search(**_search_kwargs(channel="Security"))
    filters = captured_search[0]["extra_filters"]
    assert {"term": {"evtx.channel": "Security"}} in filters
    assert not any("evtx.channel.keyword" in json.dumps(f) for f in filters)


def test_http_method_filter_uses_plain_keyword_field(captured_search):
    sr.search(**_search_kwargs(http_method="GET"))
    filters = captured_search[0]["extra_filters"]
    assert {"term": {"http.method": "GET"}} in filters
    assert not any("http.method.keyword" in json.dumps(f) for f in filters)


def test_domain_filter_spans_real_parser_fields(captured_search):
    """No parser emits dns.question.name — the filter must match the fields
    pcap / suricata / zeek actually emit."""
    sr.search(**_search_kwargs(domain="evil.example.com"))
    filters = captured_search[0]["extra_filters"]
    domain_filter = next(f for f in filters if "should" in f.get("bool", {}))
    should = domain_filter["bool"]["should"]
    assert domain_filter["bool"]["minimum_should_match"] == 1
    assert should == [{"term": {f: "evil.example.com"}} for f in es.DNS_NAME_KEYWORD_FIELDS]
    assert "dns.question.name" not in json.dumps(filters)


# ── ES 400 surfacing (#5) ────────────────────────────────────────────────────


def test_search_400_surfaces_as_http_400(monkeypatch):
    def boom(**kwargs):
        raise es.SearchError("Elasticsearch rejected the search query: bad")

    monkeypatch.setattr(es, "search_events", boom)
    with pytest.raises(HTTPException) as exc_info:
        sr.search(**_search_kwargs(q="foo AND"))
    assert exc_info.value.status_code == 400


def test_timeline_400_surfaces_as_http_400(monkeypatch):
    def boom(**kwargs):
        raise es.SearchError("Elasticsearch rejected the search query: bad")

    monkeypatch.setattr(es, "search_events", boom)
    with pytest.raises(HTTPException) as exc_info:
        sr.get_timeline(
            "c1",
            _acl={},
            artifact_type=None,
            from_ts=None,
            to_ts=None,
            page=0,
            size=100,
            search_after=None,
        )
    assert exc_info.value.status_code == 400


def test_search_events_400_raises_search_error(monkeypatch):
    monkeypatch.setattr(
        es, "_request", lambda *a, **k: (_ for _ in ()).throw(_http_error(400, {"error": {"reason": "bad query"}}))
    )
    with pytest.raises(es.SearchError):
        es.search_events("c1", query="broken:query:syntax")


def test_search_events_404_is_legit_empty(monkeypatch):
    monkeypatch.setattr(es, "_request", lambda *a, **k: (_ for _ in ()).throw(_http_error(404)))
    result = es.search_events("c1")
    assert result["hits"]["total"]["value"] == 0
    assert result["hits"]["hits"] == []


def test_search_events_missing_index_400_is_legit_empty(monkeypatch):
    body = {"error": {"root_cause": [{"reason": "no such index [fo-case-c1-evtx]"}]}}
    monkeypatch.setattr(es, "_request", lambda *a, **k: (_ for _ in ()).throw(_http_error(400, body)))
    result = es.search_events("c1")
    assert result["hits"]["hits"] == []


def test_facets_400_raises_and_query_is_slash_escaped(monkeypatch):
    calls: list[dict] = []

    def fake(method, path, body=None):
        calls.append(body or {})
        return {"aggregations": {}}

    monkeypatch.setattr(es, "_request", fake)
    es.get_search_facets("c1", query="message:HTTP/2")
    qs = calls[0]["query"]["bool"]["must"][0]["query_string"]["query"]
    assert qs == "message:HTTP\\/2"

    monkeypatch.setattr(
        es, "_request", lambda *a, **k: (_ for _ in ()).throw(_http_error(400, {"error": {"reason": "bad"}}))
    )
    with pytest.raises(es.SearchError):
        es.get_search_facets("c1", query="x")


# ── pinned newest-first (#8) ─────────────────────────────────────────────────


def test_pinned_sorted_newest_first(monkeypatch):
    calls: list[dict] = []

    def fake(method, path, body=None):
        calls.append(body or {})
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(es, "es_request", fake)
    out = sr.list_pinned("c1", _acl={}, size=100)
    assert out == {"events": [], "total": 0}
    assert calls[0]["sort"][0]["timestamp"]["order"] == "desc"


# ── page overflow rejection (#6) ─────────────────────────────────────────────


def test_page_beyond_window_raises(monkeypatch):
    def fake(*a, **k):  # ES must not even be hit
        raise AssertionError("ES should not be queried for an out-of-window page")

    monkeypatch.setattr(es, "_request", fake)
    with pytest.raises(es.SearchError, match="search_after"):
        es.search_events("c1", page=100, size=100)  # 100*100 + 100 > 10000


def test_last_in_window_page_still_works(monkeypatch):
    calls: list[dict] = []

    def fake(method, path, body=None):
        calls.append(body or {})
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(es, "_request", fake)
    es.search_events("c1", page=99, size=100)  # 9900 + 100 == 10000 → allowed
    assert calls[0]["from"] == 9900


def test_page_overflow_surfaces_as_http_400(monkeypatch):
    def fake(*a, **k):  # ES must not even be hit
        raise AssertionError("ES should not be queried for an out-of-window page")

    monkeypatch.setattr(es, "_request", fake)  # real search_events → real overflow error
    with pytest.raises(HTTPException) as exc_info:
        sr.search(**_search_kwargs(page=100, size=100))
    assert exc_info.value.status_code == 400
    assert "search_after" in exc_info.value.detail


def test_search_after_skips_window_check(monkeypatch):
    calls: list[dict] = []

    def fake(method, path, body=None):
        calls.append(body or {})
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(es, "_request", fake)
    es.search_events("c1", page=500, size=100, search_after=["2026-01-01", 1])
    assert "from" not in calls[0]
    assert calls[0]["search_after"] == ["2026-01-01", 1]


# ── write failures (#10) ─────────────────────────────────────────────────────


def test_flag_failure_raises_500(monkeypatch):
    monkeypatch.setattr(
        es, "get_event_by_id", lambda c, f: {"_id": "1", "_index": "idx", "is_flagged": False}
    )
    monkeypatch.setattr(es, "update_event", lambda *a: False)
    with pytest.raises(HTTPException) as exc_info:
        sr.flag_event("c1", "fo1", _acl={})
    assert exc_info.value.status_code == 500


def test_note_failure_raises_500(monkeypatch):
    monkeypatch.setattr(es, "get_event_by_id", lambda c, f: {"_id": "1", "_index": "idx"})
    monkeypatch.setattr(es, "update_event", lambda *a: False)
    with pytest.raises(HTTPException) as exc_info:
        sr.note_event("c1", "fo1", sr.NoteUpdate(note="x"), _acl={})
    assert exc_info.value.status_code == 500
