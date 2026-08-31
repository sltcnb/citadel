"""Tests for the telemetry read path and the browser error intake.

The endpoints are called directly rather than through the app: importing
main.py pulls in native deps (yara, pytsk3, python-magic) that these tests do
not need, which is the same reason api/conftest.py avoids it.
"""

from __future__ import annotations

import fakeredis
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from routers import telemetry as tel


@pytest.fixture
def fake_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(tel, "get_redis", lambda: fake)
    return fake


def _request(headers: dict | None = None, client: str = "10.0.0.7") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/telemetry/ui",
            "headers": raw,
            "client": (client, 51000),
            "query_string": b"",
        }
    )


# ── summary, driven by advertisements ────────────────────────────────────────
# The summary has no fixed shape any more: it renders whatever the deployed
# components advertise. These tests therefore feed it a manifest rather than a
# canned Elasticsearch response.

_PILOT = {
    "tool": "pilot",
    "telemetry": {
        "kinds": ["llm"],
        "fields": [
            {"name": "llm.purpose", "type": "keyword"},
            {"name": "llm.total_tokens", "type": "long"},
        ],
        "panels": [
            {
                "key": "llm_by_purpose",
                "label": "LLM by purpose",
                "type": "table",
                "kind": "llm",
                "group_by": "llm.purpose",
                "metrics": [
                    {"op": "count", "label": "Calls"},
                    {"op": "sum", "field": "llm.total_tokens", "label": "Tokens"},
                    {"op": "count", "label": "Failed",
                     "where": {"outcome": "failure"}, "tone": "bad"},
                ],
            }
        ],
    },
}


def _declaring(monkeypatch, *manifests):
    """Point the router at a fixed set of advertisements."""
    merged = tel.contract.merged(list(manifests))
    monkeypatch.setattr(tel, "declaration", lambda: merged)
    return merged


def test_summary_renders_only_what_is_advertised(monkeypatch):
    _declaring(monkeypatch, _PILOT)
    monkeypatch.setattr(tel, "_search", lambda body: {
        "hits": {"total": {"value": 3}},
        "aggregations": {
            "llm_by_purpose": {
                "doc_count": 3,
                "buckets": {"buckets": [
                    {"key": "_agent_run", "doc_count": 2,
                     "m0": {}, "m1": {"value": 1200.0}, "m2": {"doc_count": 1}},
                ]},
            }
        },
    })
    out = tel.telemetry_summary(hours=24)
    assert out["events"] == 3
    assert [p["key"] for p in out["panels"]] == ["llm_by_purpose"]
    panel = out["panels"][0]
    assert panel["tool"] == "pilot"
    assert panel["group_by"] == "llm.purpose"
    assert [c["label"] for c in panel["columns"]] == ["Calls", "Tokens", "Failed"]
    row = panel["rows"][0]
    assert row["key"] == "_agent_run"
    assert row["m0"] == 2          # count -> the bucket's doc_count
    assert row["m1"] == 1200.0     # sum
    assert row["m2"] == 1          # filtered count


def test_removing_a_tool_removes_its_panels(monkeypatch):
    # The whole point of the contract: no orchestrator code mentions Pilot, so
    # undeploying it leaves nothing behind.
    _declaring(monkeypatch)  # nothing advertises anything
    monkeypatch.setattr(tel, "_search", lambda body: {})
    out = tel.telemetry_summary(hours=24)
    assert out["panels"] == []
    assert out["warnings"]  # says so rather than rendering an empty page


def test_summary_on_missing_index_returns_empty_not_an_error(monkeypatch):
    # Telemetry going missing must never look like the platform being broken.
    _declaring(monkeypatch, _PILOT)
    monkeypatch.setattr(tel, "_search", lambda body: {})
    out = tel.telemetry_summary(hours=1)
    assert out["events"] == 0
    assert out["panels"][0]["rows"] == []


def test_a_malformed_advertisement_is_reported_not_swallowed(monkeypatch):
    bad = {"tool": "broken", "telemetry": {
        "kinds": ["x"],
        "fields": [{"name": "a", "type": "not-a-type"}],
        "panels": [],
    }}
    merged = _declaring(monkeypatch, bad)
    assert any("not-a-type" in w for w in merged.warnings)


def test_search_swallows_elasticsearch_failures(monkeypatch):
    def _boom(*_a, **_kw):
        raise OSError("connection refused")

    monkeypatch.setattr(tel, "es_request", _boom)
    assert tel._search({"size": 0}) == {}


# ── the query itself ─────────────────────────────────────────────────────────
# The tests above mock _search, so they validate how a response is RESHAPED and
# say nothing about whether Elasticsearch would accept the query. That gap
# shipped a summary endpoint that 400'd on every call: a terms agg ordered by
# "p95" instead of "p95.95". These two tests close it without a live cluster.

_MULTI_VALUE_AGGS = ("percentiles", "percentile_ranks", "stats", "extended_stats")


def _capture_query(monkeypatch, fn, **kw):
    captured = {}
    monkeypatch.setattr(tel, "_search", lambda body: captured.update(body) or {})
    fn(**kw)
    return captured


def _walk_aggs(node, path=""):
    """Yield (path, name, spec) for every aggregation in a search body."""
    for name, spec in (node.get("aggs") or {}).items():
        here = f"{path}.{name}" if path else name
        yield here, name, spec
        yield from _walk_aggs(spec, here)


def test_summary_never_orders_a_terms_agg_by_a_bare_multi_value_metric(monkeypatch):
    body = _capture_query(monkeypatch, tel.telemetry_summary, hours=24)
    for path, _name, spec in _walk_aggs(body):
        order = (spec.get("terms") or {}).get("order")
        if not isinstance(order, dict):
            continue
        siblings = spec.get("aggs") or {}
        for key in order:
            target = key.split(".", 1)[0]
            sibling = siblings.get(target) or {}
            kind = next((k for k in _MULTI_VALUE_AGGS if k in sibling), None)
            if kind:
                assert "." in key, (
                    f"{path} orders by {key!r}, a {kind} agg. Elasticsearch rejects "
                    f"the whole search with invalid_path unless the metric is named "
                    f"(e.g. {key}.95)."
                )


def test_every_aggregated_field_is_declared_by_some_manifest(monkeypatch):
    """A typo in a group_by does not 400 — it silently returns no buckets,
    which reads exactly like "nothing happened". Cross-check every field the
    real shipped manifests aggregate on against the fields they declare."""
    from pathlib import Path

    import yaml
    from citadel_contracts.telemetry import _TEMPLATE_BODY

    envelope: set[str] = set()

    def flatten(props, prefix=""):
        for key, spec in (props or {}).items():
            full = f"{prefix}{key}"
            if "properties" in spec:
                flatten(spec["properties"], full + ".")
            else:
                envelope.add(full)

    flatten(_TEMPLATE_BODY["template"]["mappings"]["properties"])

    root = Path(__file__).resolve().parents[2] / "tools"
    manifests = [
        yaml.safe_load(p.read_text())
        for p in sorted(root.glob("*/capabilities.yaml"))
    ]
    merged = tel.contract.merged([m for m in manifests if m])
    assert not merged.warnings, merged.warnings
    known = set(merged.fields) | envelope

    for panel in merged.panels:
        where = panel.get("where") or {}
        referenced = [panel.get("group_by")] + list(where)
        for metric in panel.get("metrics") or []:
            referenced.append(metric.get("field"))
            referenced.extend((metric.get("where") or {}).keys())
        for name in filter(None, referenced):
            assert name in known, (
                f"panel '{panel['key']}' (from {panel['tool']}) aggregates on "
                f"'{name}', which no manifest declares — it would silently "
                f"return no buckets."
            )


# ── event drill-down ─────────────────────────────────────────────────────────


def test_events_builds_the_expected_filters(monkeypatch):
    captured = {}

    def _capture(body):
        captured.update(body)
        return {"hits": {"total": {"value": 1}, "hits": [{"_source": {"kind": "error"}}]}}

    monkeypatch.setattr(tel, "_search", _capture)
    # Called directly, FastAPI's Query(...) defaults are never resolved, so
    # every optional argument has to be passed explicitly here.
    out = tel.telemetry_events(
        hours=6, kind="error", service="api", outcome="failure", signature=None,
        correlation_id="c0ffee", q="timeout", field=None, value=None, limit=10,
    )
    filters = captured["query"]["bool"]["filter"]
    assert {"term": {"kind": "error"}} in filters
    assert {"term": {"correlation_id": "c0ffee"}} in filters
    assert filters[0] == {"range": {"@timestamp": {"gte": "now-6h"}}}
    assert captured["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert captured["size"] == 10
    assert out["count"] == 1


def test_events_rejects_a_kind_no_component_advertises(monkeypatch):
    _declaring(monkeypatch, _PILOT)
    with pytest.raises(HTTPException) as exc:
        tel.telemetry_events(hours=24, kind="nonsense", service=None, outcome=None,
                             signature=None, correlation_id=None, q=None,
                             field=None, value=None, limit=10)
    assert exc.value.status_code == 400
    assert "llm" in exc.value.detail


def test_drilldown_is_restricted_to_advertised_fields(monkeypatch):
    _declaring(monkeypatch, _PILOT)
    captured = {}
    monkeypatch.setattr(tel, "_search", lambda b: captured.update(b) or {})

    # An advertised field is accepted...
    tel.telemetry_events(hours=24, kind=None, service=None, outcome=None,
                         signature=None, correlation_id=None, q=None,
                         field="llm.purpose", value="_agent_run", limit=10)
    assert {"term": {"llm.purpose": "_agent_run"}} in captured["query"]["bool"]["filter"]

    # ...anything else is refused, so this cannot become a free-form query API.
    with pytest.raises(HTTPException) as exc:
        tel.telemetry_events(hours=24, kind=None, service=None, outcome=None,
                             signature=None, correlation_id=None, q=None,
                             field="secret.field", value="x", limit=10)
    assert exc.value.status_code == 400


# ── browser intake ───────────────────────────────────────────────────────────


def test_ui_report_is_recorded(monkeypatch, fake_redis):
    recorded = []
    monkeypatch.setattr(tel, "record_ui_event", lambda ev, **kw: recorded.append((ev, kw)))
    body = tel.UIErrorReport(
        event="render_crash", message="x is not a function", component="Timeline"
    )
    out = tel.report_ui_error(body, _request({"User-Agent": "Mozilla/5.0"}))
    assert out == {"recorded": True}
    event, kwargs = recorded[0]
    assert event == "render_crash"
    assert kwargs["component"] == "Timeline"
    assert kwargs["user_agent"] == "Mozilla/5.0"


def test_ui_report_is_rate_limited_per_ip(monkeypatch, fake_redis):
    monkeypatch.setattr(tel.settings, "TELEMETRY_UI_RATE_LIMIT", 3)
    monkeypatch.setattr(tel, "record_ui_event", lambda *a, **kw: None)
    body = tel.UIErrorReport(message="loop")
    results = [tel.report_ui_error(body, _request()) for _ in range(5)]
    assert [r["recorded"] for r in results] == [True, True, True, False, False]
    assert results[-1]["reason"] == "rate_limited"


def test_rate_limit_is_per_ip_not_global(monkeypatch, fake_redis):
    monkeypatch.setattr(tel.settings, "TELEMETRY_UI_RATE_LIMIT", 1)
    monkeypatch.setattr(tel, "record_ui_event", lambda *a, **kw: None)
    body = tel.UIErrorReport(message="loop")
    assert tel.report_ui_error(body, _request(client="10.0.0.1"))["recorded"] is True
    assert tel.report_ui_error(body, _request(client="10.0.0.2"))["recorded"] is True
    assert tel.report_ui_error(body, _request(client="10.0.0.1"))["recorded"] is False


def test_rate_limit_fails_open_when_redis_is_down(monkeypatch):
    def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr(tel, "get_redis", _boom)
    # Losing an error report is worse than accepting a few extra.
    assert tel._ui_rate_limited(_request()) is False


def test_ui_report_never_raises_on_a_bad_token(monkeypatch, fake_redis):
    monkeypatch.setattr(tel, "record_ui_event", lambda *a, **kw: None)
    out = tel.report_ui_error(
        tel.UIErrorReport(message="boom"),
        _request({"Authorization": "Bearer not-a-real-jwt"}),
    )
    assert out["recorded"] is True


def test_ui_report_payload_is_bounded():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        tel.UIErrorReport(message="x" * 3000)
    with pytest.raises(ValidationError):
        tel.UIErrorReport(stack="x" * 9000)
