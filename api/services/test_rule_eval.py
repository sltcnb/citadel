"""Unit tests for the shared rule evaluator (services/rule_eval.py).

The Elasticsearch transport is stubbed so these run in CI without a cluster; the
behaviour they pin was first verified against a real Elasticsearch 8.13 with a
spray corpus (25 distinct accounts from one source inside 15 minutes, alongside
40 failures against a single account, 30 accounts spread over 20 hours, and
machine-account noise): a plain ``threshold: 10`` matched 95 events and could not
tell those apart, while the correlation rule qualified only the spraying source.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.rule_eval as rule_eval  # noqa: E402


@pytest.fixture
def captured(monkeypatch):
    """Record the bodies sent to ES and return canned responses."""
    calls: list[tuple[str, str, dict]] = []
    responses: list[dict] = []

    def fake(method, path, body=None):
        calls.append((method, path, body or {}))
        return responses.pop(0) if responses else {}

    monkeypatch.setattr(rule_eval, "es_req", fake)
    return {"calls": calls, "responses": responses}


# ── index selection ──────────────────────────────────────────────────────────


def test_index_defaults_to_every_artifact_type():
    assert rule_eval.index_for("c1", {}) == "fo-case-c1-*"
    assert rule_eval.index_for("c1", {"artifact_type": "  "}) == "fo-case-c1-*"


def test_index_scopes_to_one_artifact_type():
    assert rule_eval.index_for("c1", {"artifact_type": "evtx"}) == "fo-case-c1-evtx"


def test_index_accepts_a_list_of_artifact_types():
    """Registry-derived evidence lands in -persistence/-shimcache/-bam/…, so a
    rule keying off registry.key_path must be able to name them all rather than
    picking one index and silently missing the rest."""
    got = rule_eval.index_for("c1", {"artifact_type": "persistence, shimcache ,bam"})
    assert got == "fo-case-c1-persistence,fo-case-c1-shimcache,fo-case-c1-bam"


# ── windows ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("window", ["30s", "15m", "6h", "7d", "1m"])
def test_valid_windows(window):
    assert rule_eval.parse_window(window) == window


@pytest.mark.parametrize("window", ["15", "m", "15min", "-5m", "1w", "abc", "15 m"])
def test_invalid_windows_are_rejected(window):
    with pytest.raises(rule_eval.RuleEvalError):
        rule_eval.parse_window(window)


def test_absent_window_is_allowed():
    assert rule_eval.parse_window(None) is None


# ── aggregation field resolution ─────────────────────────────────────────────


def test_analyzed_fields_get_the_keyword_subfield():
    """Aggregating on analyzed text buckets individual tokens, not values."""
    assert rule_eval._keyword("user.name") == "user.name.keyword"
    assert rule_eval._keyword("evtx.event_data.TargetUserName") == (
        "evtx.event_data.TargetUserName.keyword"
    )


def test_exact_fields_are_used_directly():
    """network.src_ip is an `ip` field — appending .keyword would not resolve."""
    assert rule_eval._keyword("network.src_ip") == "network.src_ip"
    assert rule_eval._keyword("evtx.event_id") == "evtx.event_id"
    assert rule_eval._keyword("already.done.keyword") == "already.done.keyword"


# ── plain threshold ──────────────────────────────────────────────────────────


def _hits(total, n=1):
    return {"hits": {"total": {"value": total},
                     "hits": [{"_source": {"fo_id": f"e{i}"}} for i in range(n)]}}


def test_threshold_fires_at_the_boundary(captured):
    captured["responses"].append(_hits(10))
    match = rule_eval.evaluate("c1", {"query": "a:b", "threshold": 10})
    assert match and match["match_count"] == 10


def test_threshold_does_not_fire_below(captured):
    captured["responses"].append(_hits(9))
    assert rule_eval.evaluate("c1", {"query": "a:b", "threshold": 10}) is None


def test_total_hits_are_tracked(captured):
    """Without track_total_hits ES stops counting at 10 000, so a rule with a
    higher threshold could never fire and every large detection reported exactly
    10 000. Three of the five call sites this replaced omitted it."""
    captured["responses"].append(_hits(50000))
    rule_eval.evaluate("c1", {"query": "a:b", "threshold": 20000})
    assert captured["calls"][0][2]["track_total_hits"] is True


def test_missing_index_is_not_a_match(monkeypatch):
    """A case may simply not have that artifact type — not an error."""

    def boom(method, path, body=None):
        raise type("HTTPError", (Exception,), {"code": 404})()

    monkeypatch.setattr(rule_eval, "es_req", boom)
    assert rule_eval.evaluate("c1", {"query": "a:b", "threshold": 1}) is None


# ── correlation ──────────────────────────────────────────────────────────────

_SPRAY = {
    "query": "evtx.event_id:4625",
    "artifact_type": "evtx",
    "threshold": 1,
    "correlation": {
        "group_by": "network.src_ip",
        "distinct": "evtx.event_data.TargetUserName",
        "min_distinct": 20,
        "window": "15m",
    },
}


def _grouped(buckets, windowed=True):
    out = []
    for key, distinct, docs in buckets:
        if windowed:
            out.append({"key": key, "doc_count": docs,
                        "w": {"buckets": [{"key_as_string": "2026-07-01T10:00:00Z",
                                           "n": {"value": distinct}}]}})
        else:
            out.append({"key": key, "doc_count": docs, "n": {"value": distinct}})
    return {"aggregations": {"g": {"buckets": out}}, "hits": {"total": {"value": 0}, "hits": []}}


def test_correlation_qualifies_only_the_fanned_out_entity(captured):
    captured["responses"].append(_grouped([("10.0.0.66", 25, 25), ("10.0.0.5", 1, 40)]))
    captured["responses"].append(_hits(25, 2))
    match = rule_eval.evaluate("c1", _SPRAY)
    assert match is not None
    assert match["match_count"] == 1, "only the spraying source should qualify"
    assert match["correlation"]["groups"][0]["key"] == "10.0.0.66"
    assert "10.0.0.66" in match["correlation"]["summary"]
    assert "25 distinct" in match["correlation"]["summary"]


def test_high_volume_against_one_account_does_not_fire(captured):
    """40 failures against a single account is a volume problem, not a spray —
    the exact case a plain threshold cannot distinguish."""
    captured["responses"].append(_grouped([("10.0.0.5", 1, 40)]))
    assert rule_eval.evaluate("c1", _SPRAY) is None


def test_groups_are_ranked_by_variety(captured):
    captured["responses"].append(
        _grouped([("a", 21, 21), ("b", 99, 99), ("c", 30, 30)])
    )
    captured["responses"].append(_hits(0, 0))
    match = rule_eval.evaluate("c1", _SPRAY)
    assert [g["distinct"] for g in match["correlation"]["groups"]] == [99, 30, 21]


def test_case_wide_correlation_needs_no_group_by(captured):
    captured["responses"].append(
        {"aggregations": {"n": {"value": 50}}, "hits": {"total": {"value": 0}, "hits": []}}
    )
    rule = {"query": "a:b", "threshold": 1,
            "correlation": {"distinct": "user.name", "min_distinct": 50}}
    match = rule_eval.evaluate("c1", rule)
    assert match and match["match_count"] == 1
    assert match["correlation"]["groups"][0]["key"] == "(case-wide)"
    # A case-wide question needs a cardinality agg, not a terms agg.
    assert "n" in captured["calls"][0][2]["aggs"]
    assert "g" not in captured["calls"][0][2]["aggs"]


def test_window_produces_a_date_histogram(captured):
    captured["responses"].append(_grouped([("x", 25, 25)]))
    captured["responses"].append(_hits(0, 0))
    rule_eval.evaluate("c1", _SPRAY)
    aggs = captured["calls"][0][2]["aggs"]
    hist = aggs["g"]["aggs"]["w"]["date_histogram"]
    assert hist["fixed_interval"] == "15m"
    assert hist["field"] == "timestamp"


def test_windowless_correlation_has_no_histogram(captured):
    captured["responses"].append(_grouped([("x", 25, 25)], windowed=False))
    captured["responses"].append(_hits(0, 0))
    rule = {"query": "a:b", "threshold": 1,
            "correlation": {"group_by": "host.hostname", "distinct": "user.name",
                            "min_distinct": 5}}
    assert rule_eval.evaluate("c1", rule) is not None
    assert "w" not in captured["calls"][0][2]["aggs"]["g"].get("aggs", {})


def test_samples_are_scoped_to_qualifying_entities(captured):
    """Evidence shown must be the detection, not an arbitrary slice of the
    rule's raw matches."""
    captured["responses"].append(_grouped([("10.0.0.66", 25, 25)]))
    captured["responses"].append(_hits(25, 3))
    rule_eval.evaluate("c1", _SPRAY)
    sample_query = captured["calls"][1][2]["query"]
    terms = sample_query["bool"]["filter"][0]["terms"]
    assert terms["network.src_ip"] == ["10.0.0.66"]


@pytest.mark.parametrize(
    "corr",
    [
        {"min_distinct": 5},                              # no distinct field
        {"distinct": "user.name"},                        # no min_distinct
        {"distinct": "user.name", "min_distinct": 0},      # not positive
        {"distinct": "user.name", "min_distinct": -1},
    ],
)
def test_incomplete_correlation_is_an_error(captured, corr):
    with pytest.raises(rule_eval.RuleEvalError):
        rule_eval.evaluate("c1", {"query": "a:b", "threshold": 1, "correlation": corr})


def test_bad_window_is_an_error(captured):
    with pytest.raises(rule_eval.RuleEvalError):
        rule_eval.evaluate("c1", {"query": "a:b", "threshold": 1, "correlation": {
            "distinct": "user.name", "min_distinct": 5, "window": "fortnight"}})
