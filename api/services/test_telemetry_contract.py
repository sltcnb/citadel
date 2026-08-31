"""Telemetry derived from advertisements.

The property under test throughout: the orchestrator holds no knowledge of any
particular tool. Everything — kinds, indexed fields, panels, the aggregations
behind them — comes from manifests, so these tests build manifests rather than
mocking Elasticsearch.
"""

from __future__ import annotations

import pytest

from services import telemetry_contract as c

PILOT = {
    "tool": "pilot",
    "telemetry": {
        "kinds": ["llm"],
        "fields": [
            {"name": "llm.purpose", "type": "keyword"},
            {"name": "llm.total_tokens", "type": "long"},
        ],
        "panels": [{
            "key": "llm_by_purpose", "label": "LLM by purpose", "type": "table",
            "kind": "llm", "group_by": "llm.purpose",
            "metrics": [
                {"op": "count", "label": "Calls"},
                {"op": "sum", "field": "llm.total_tokens", "label": "Tokens"},
            ],
        }],
    },
}

SLUICE = {
    "tool": "sluice",
    "telemetry": {
        "kinds": ["task"],
        "fields": [{"name": "task.artifact_type", "type": "keyword"}],
        "panels": [{
            "key": "parsers", "type": "table", "kind": "task",
            "group_by": "task.artifact_type",
            "metrics": [{"op": "count", "label": "Runs"},
                        {"op": "count", "label": "Failed",
                         "where": {"outcome": "failure"}, "tone": "bad"}],
        }],
    },
}

# Anvil adds ONE field to another tool's event kind and declares no kind of its
# own — the cross-tool composition the contract has to support.
ANVIL = {
    "tool": "anvil",
    "telemetry": {
        "fields": [{"name": "task.module", "type": "keyword"}],
        "panels": [{
            "key": "modules", "type": "table", "kind": "task",
            "group_by": "task.module",
            "metrics": [{"op": "avg", "field": "duration_ms", "label": "Avg", "unit": "ms"}],
        }],
    },
}


# ── merging ──────────────────────────────────────────────────────────────────


def test_kinds_and_panels_are_the_union_of_what_is_advertised():
    m = c.merged([PILOT, SLUICE, ANVIL])
    assert sorted(m.kinds) == ["llm", "task"]
    assert [p["key"] for p in m.panels] == ["llm_by_purpose", "parsers", "modules"]
    assert {p["tool"] for p in m.panels} == {"pilot", "sluice", "anvil"}


def test_a_component_that_advertises_nothing_contributes_nothing():
    m = c.merged([{"tool": "scribe"}, {"tool": "babel", "telemetry": None}])
    assert m.kinds == [] and m.panels == [] and m.fields == {}


def test_one_tool_can_extend_another_tools_kind():
    m = c.merged([SLUICE, ANVIL])
    props = m.index_properties()
    # Both fields land under the same `task` object.
    assert set(props["task"]["properties"]) == {"artifact_type", "module"}
    assert m.fields["task.module"]["tool"] == "anvil"


def test_removing_a_tool_removes_its_fields_and_panels():
    with_pilot = c.merged([PILOT, SLUICE])
    without = c.merged([SLUICE])
    assert "llm.purpose" in with_pilot.fields
    assert "llm.purpose" not in without.fields
    assert [p["key"] for p in without.panels] == ["parsers"]


def test_conflicting_field_types_are_reported_and_the_first_wins():
    other = {"tool": "rogue", "telemetry": {
        "fields": [{"name": "llm.total_tokens", "type": "keyword"}], "panels": []}}
    m = c.merged([PILOT, other])
    assert m.fields["llm.total_tokens"]["type"] == "long"
    assert any("llm.total_tokens" in w for w in m.warnings)


def test_a_malformed_block_is_skipped_with_a_warning_not_an_exception():
    bad = {"tool": "broken", "telemetry": {
        "fields": [{"name": "x", "type": "nonsense"}], "panels": []}}
    m = c.merged([bad, PILOT])
    assert any("nonsense" in w for w in m.warnings)
    assert "llm.purpose" in m.fields  # the good manifest still applied


# ── mapping ──────────────────────────────────────────────────────────────────


def test_dotted_names_become_a_nested_properties_tree():
    props = c.merged([PILOT]).index_properties()
    assert props == {"llm": {"properties": {
        "purpose": {"type": "keyword"},
        "total_tokens": {"type": "long"},
    }}}


# ── query construction ───────────────────────────────────────────────────────


def test_a_table_panel_becomes_a_filtered_terms_aggregation():
    aggs = c.build_aggs(c.merged([PILOT]).panels, "1h")
    agg = aggs["llm_by_purpose"]
    assert agg["filter"] == {"bool": {"filter": [{"term": {"kind": "llm"}}]}}
    terms = agg["aggs"]["buckets"]["terms"]
    assert terms["field"] == "llm.purpose"
    # An unfiltered count needs no sub-agg; the sum does.
    assert "m0" not in agg["aggs"]["buckets"]["aggs"]
    assert agg["aggs"]["buckets"]["aggs"]["m1"] == {"sum": {"field": "llm.total_tokens"}}


def test_a_filtered_metric_becomes_a_filter_sub_aggregation():
    aggs = c.build_aggs(c.merged([SLUICE]).panels, "1h")
    m1 = aggs["parsers"]["aggs"]["buckets"]["aggs"]["m1"]
    assert m1 == {"filter": {"bool": {"filter": [{"term": {"outcome": "failure"}}]}}}


def test_a_range_in_where_becomes_a_range_query():
    panel = {"key": "failing", "type": "table", "kind": "request",
             "where": {"http.status_code": {"gte": 400}},
             "group_by": "http.route", "metrics": [], "tool": "citadel"}
    agg = c.build_aggs([panel], "1h")["failing"]
    assert {"range": {"http.status_code": {"gte": 400}}} in agg["filter"]["bool"]["filter"]


def test_ordering_by_a_percentile_names_the_percentile():
    # Elasticsearch rejects the entire search with invalid_path if the metric
    # is not named — this is the bug that took the whole summary endpoint down.
    panel = {"key": "slow", "type": "table", "kind": "request",
             "group_by": "http.route", "order_by": "p95", "tool": "citadel",
             "metrics": [{"op": "p95", "field": "duration_ms", "label": "p95"}]}
    order = c.build_aggs([panel], "1h")["slow"]["aggs"]["buckets"]["terms"]["order"]
    assert order == {"m0.95": "desc"}
    # and never a bare float key, which reads as a nested path
    assert "95.0" not in next(iter(order))


def test_a_timeseries_panel_becomes_a_date_histogram():
    panel = {"key": "activity", "type": "timeseries", "interval": "", "tool": "citadel",
             "metrics": [{"op": "count", "label": "Events"}]}
    agg = c.build_aggs([panel], "6h")["activity"]
    assert agg["aggs"]["buckets"]["date_histogram"]["fixed_interval"] == "6h"


# ── shaping ──────────────────────────────────────────────────────────────────


def test_an_unfiltered_count_reads_the_buckets_own_doc_count():
    panels = c.merged([PILOT]).panels
    shaped = c.shape(panels, {"llm_by_purpose": {"doc_count": 5, "buckets": {"buckets": [
        {"key": "_agent_run", "doc_count": 4, "m1": {"value": 900.0}},
    ]}}})
    row = shaped[0]["rows"][0]
    assert row["m0"] == 4        # count == the bucket
    assert row["m1"] == 900.0


def test_a_percentile_is_unwrapped_to_a_single_number():
    panel = {"key": "slow", "type": "table", "group_by": "http.route", "tool": "citadel",
             "metrics": [{"op": "p95", "field": "duration_ms", "label": "p95"}]}
    shaped = c.shape([panel], {"slow": {"doc_count": 1, "buckets": {"buckets": [
        {"key": "/x", "doc_count": 1, "m0": {"values": {"95.0": 2412.77}}},
    ]}}})
    assert shaped[0]["rows"][0]["m0"] == 2412.8


def test_columns_carry_the_unit_and_tone_the_manifest_declared():
    shaped = c.shape(c.merged([SLUICE]).panels, {})
    cols = shaped[0]["columns"]
    assert cols[1]["label"] == "Failed" and cols[1]["tone"] == "bad"


def test_shaping_an_absent_aggregation_yields_an_empty_panel_not_a_crash():
    shaped = c.shape(c.merged([PILOT]).panels, {})
    assert shaped[0]["rows"] == [] and shaped[0]["total"] == 0


@pytest.mark.parametrize("ptype", ["table", "stat", "timeseries"])
def test_every_declared_panel_type_can_be_built_and_shaped(ptype):
    panel = {"key": "p", "type": ptype, "tool": "t",
             "group_by": "kind" if ptype == "table" else "",
             "metrics": [{"op": "count", "label": "N"}]}
    aggs = c.build_aggs([panel], "1h")
    assert "p" in aggs
    assert c.shape([panel], {})[0]["type"] == ptype
