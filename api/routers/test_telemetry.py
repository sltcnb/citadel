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


# ── summary shaping ──────────────────────────────────────────────────────────

_AGGS = {
    "hits": {"total": {"value": 42}},
    "aggregations": {
        "by_kind": {
            "buckets": [
                {
                    "key": "request",
                    "doc_count": 30,
                    "outcome": {
                        "buckets": [
                            {"key": "success", "doc_count": 28},
                            {"key": "failure", "doc_count": 2},
                        ]
                    },
                }
            ]
        },
        "by_service": {"buckets": [{"key": "api", "doc_count": 40}]},
        "over_time": {
            "buckets": [
                {
                    "key_as_string": "2026-08-31T10:00:00.000Z",
                    "doc_count": 12,
                    "failures": {"doc_count": 2},
                }
            ]
        },
        "top_errors": {
            "doc_count": 2,
            "signatures": {
                "buckets": [
                    {
                        "key": "ValueError: case <id> not found",
                        "doc_count": 2,
                        "last_seen": {"value_as_string": "2026-08-31T10:12:00.000Z"},
                        "services": {"buckets": [{"key": "api", "doc_count": 2}]},
                        "sample": {
                            "hits": {
                                "hits": [
                                    {"_source": {"message": "case abc not found"}}
                                ]
                            }
                        },
                    }
                ]
            },
        },
        "requests": {
            "doc_count": 30,
            "status": {"buckets": [{"key": 500, "doc_count": 2}]},
            "failing_routes": {
                "doc_count": 2,
                "routes": {
                    "buckets": [
                        {
                            "key": "/api/v1/cases/{case_id}/search",
                            "doc_count": 2,
                            "codes": {"buckets": [{"key": 500, "doc_count": 2}]},
                        }
                    ]
                },
            },
            "slowest_routes": {
                "buckets": [
                    {
                        "key": "/api/v1/search",
                        "doc_count": 10,
                        "p95": {"values": {"95.0": 2412.77}},
                        "avg_ms": {"value": 880.45},
                        "max_ms": {"value": 3000.0},
                    }
                ]
            },
        },
        "tasks": {
            "doc_count": 8,
            "by_name": {
                "buckets": [
                    {
                        "key": "parse",
                        "doc_count": 8,
                        "outcome": {
                            "buckets": [
                                {"key": "success", "doc_count": 6},
                                {"key": "failure", "doc_count": 2},
                            ]
                        },
                        "avg_ms": {"value": 1500.0},
                    }
                ]
            },
            "by_artifact_type": {
                "buckets": [
                    {
                        "key": "evtx",
                        "doc_count": 8,
                        "outcome": {"buckets": [{"key": "failure", "doc_count": 2}]},
                        "avg_ms": {"value": 1500.0},
                        "events": {"value": 91234.0},
                    }
                ]
            },
        },
        "llm": {
            "doc_count": 4,
            "calls": {"value": 4},
            "tokens": {"value": 12000},
            "cost_usd": {"value": 0.1234567},
            "avg_ms": {"value": 2100.0},
            "outcome": {"buckets": [{"key": "success", "doc_count": 3},
                                    {"key": "failure", "doc_count": 1}]},
            "by_model": {
                "buckets": [
                    {
                        "key": "claude-opus-5",
                        "doc_count": 4,
                        "tokens": {"value": 12000},
                        "cost_usd": {"value": 0.1234567},
                        "avg_ms": {"value": 2100.0},
                        "failures": {"doc_count": 1},
                    }
                ]
            },
            "by_purpose": {
                "buckets": [
                    {
                        "key": "investigate_case",
                        "doc_count": 4,
                        "tokens": {"value": 12000},
                        "avg_ms": {"value": 2100.0},
                        "failures": {"doc_count": 1},
                    }
                ]
            },
        },
        "ui": {
            "doc_count": 3,
            "routes": {"buckets": [{"key": "/cases/abc/timeline", "doc_count": 3}]},
            "components": {"buckets": [{"key": "GET /cases/{id}", "doc_count": 3}]},
            "sources": {"buckets": [{"key": "api", "doc_count": 3}]},
        },
    },
}


def test_summary_reshapes_every_section(monkeypatch):
    monkeypatch.setattr(tel, "_search", lambda body: _AGGS)
    out = tel.telemetry_summary(hours=24)

    assert out["events"] == 42
    assert out["by_kind"][0] == {
        "kind": "request",
        "count": 30,
        "outcomes": {"success": 28, "failure": 2},
    }
    assert out["over_time"][0]["failures"] == 2
    assert out["top_errors"][0]["signature"] == "ValueError: case <id> not found"
    assert out["top_errors"][0]["sample"]["message"] == "case abc not found"
    assert out["requests"]["failing_routes"][0]["codes"] == {"500": 2}
    assert out["requests"]["slowest_routes"][0]["p95_ms"] == 2412.8
    assert out["tasks"]["by_artifact_type"][0]["events"] == 91234
    assert out["llm"]["cost_usd"] == 0.1235
    assert out["llm"]["by_purpose"][0]["failures"] == 1
    assert out["ui"]["routes"][0]["count"] == 3


def test_summary_on_missing_index_returns_empty_not_an_error(monkeypatch):
    # Telemetry going missing must never look like the platform being broken.
    monkeypatch.setattr(tel, "_search", lambda body: {})
    out = tel.telemetry_summary(hours=1)
    assert out["events"] == 0
    assert out["by_kind"] == []
    assert out["requests"]["slowest_routes"] == []
    assert out["llm"]["calls"] == 0


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


def test_every_aggregated_field_exists_in_the_index_template(monkeypatch):
    """A typo in a field name does not 400 — it silently returns no buckets,
    which reads exactly like "nothing happened". Cross-check the query against
    the mapping the sink actually installs."""
    from citadel_contracts.telemetry import _TEMPLATE_BODY

    mapped: set[str] = set()

    def flatten(props, prefix=""):
        for key, spec in (props or {}).items():
            full = f"{prefix}{key}"
            if "properties" in spec:
                flatten(spec["properties"], full + ".")
            else:
                mapped.add(full)

    flatten(_TEMPLATE_BODY["template"]["mappings"]["properties"])

    def fields_of(node):
        """Every field name referenced anywhere in a query/agg fragment."""
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "field" and isinstance(value, str):
                    yield value
                elif key in ("term", "terms", "range") and isinstance(value, dict):
                    for name in value:
                        if name not in ("field", "size", "order", "percents"):
                            yield name
                else:
                    yield from fields_of(value)
        elif isinstance(node, list):
            for item in node:
                yield from fields_of(item)

    for body in (
        _capture_query(monkeypatch, tel.telemetry_summary, hours=24),
        _capture_query(monkeypatch, tel.telemetry_events, hours=24, kind="error",
                       service="api", outcome="failure", signature="x",
                       correlation_id="y", q="z", limit=10),
    ):
        for field in fields_of(body):
            base = field[:-8] if field.endswith(".keyword") else field
            assert base in mapped, (
                f"query aggregates on {field!r}, which the telemetry index "
                f"template does not map — it would return no buckets, silently."
            )


# ── event drill-down ─────────────────────────────────────────────────────────


def test_events_builds_the_expected_filters(monkeypatch):
    captured = {}

    def _capture(body):
        captured.update(body)
        return {"hits": {"total": {"value": 1}, "hits": [{"_source": {"kind": "error"}}]}}

    monkeypatch.setattr(tel, "_search", _capture)
    out = tel.telemetry_events(
        hours=6, kind="error", service="api", outcome="failure",
        correlation_id="c0ffee", q="timeout", limit=10,
    )
    filters = captured["query"]["bool"]["filter"]
    assert {"term": {"kind": "error"}} in filters
    assert {"term": {"correlation_id": "c0ffee"}} in filters
    assert filters[0] == {"range": {"@timestamp": {"gte": "now-6h"}}}
    assert captured["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert captured["size"] == 10
    assert out["count"] == 1


def test_events_rejects_an_unknown_kind():
    with pytest.raises(HTTPException) as exc:
        tel.telemetry_events(kind="nonsense")
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
