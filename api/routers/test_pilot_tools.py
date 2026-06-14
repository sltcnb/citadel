"""Tests for the new Pilot agent tools (entity_graph / stack_rare / cti_seen_before):
registration + input validation. The ES/Redis-backed happy paths are covered by
the services' own tests; here we lock the agent-facing contract."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers import llm_config as lc  # noqa: E402


def test_new_tools_registered():
    for name in ("entity_graph", "stack_rare", "cti_seen_before"):
        assert name in lc.AGENT_TOOLS, f"{name} not registered"


def test_stack_rare_requires_field_and_host():
    r = lc._tool_stack_rare("c1", {"action": "stack_rare"})
    assert r["query_status"] == "invalid"
    assert "field" in r["query_error"] and "host" in r["query_error"]


def test_stack_rare_rejects_unlisted_field():
    r = lc._tool_stack_rare("c1", {"field": "password", "host": "WS01"})
    assert r["query_status"] == "invalid"
    assert "not stackable" in r["query_error"]


def test_cti_seen_before_requires_values():
    r = lc._tool_cti_seen_before("c1", {"action": "cti_seen_before"})
    assert r["query_status"] == "invalid"
    assert "values" in r["query_error"]


def test_cti_seen_before_accepts_single_value(monkeypatch):
    # Stub the service so no Redis is needed; assert the value is threaded through.
    import services.pilot_memory as pm
    captured = {}
    def _fake(values, current_case=None):
        captured["values"] = values; captured["case"] = current_case
        return [{"value": values[0], "count": 3, "cases": ["a", "b", "c"]}]
    monkeypatch.setattr(pm, "seen_before", _fake)
    r = lc._tool_cti_seen_before("c9", {"value": "1.2.3.4"})
    assert r["query_status"] == "ok"
    assert captured["values"] == ["1.2.3.4"] and captured["case"] == "c9"
    assert r["result_count"] == 1
    assert "prior case" in r["sample"][0]


def test_entity_graph_summarizes(monkeypatch):
    import services.entity_graph as eg
    monkeypatch.setattr(eg, "build_graph", lambda case_id, focus=None, limit=40: {
        "nodes": [{"type": "host"}, {"type": "user"}, {"type": "user"}],
        "edges": [{"source": "host:A", "target": "user:x", "type": "host_user", "count": 9}],
    })
    r = lc._tool_entity_graph("c1", {"focus": "A"})
    assert r["query_status"] == "ok"
    assert r["node_counts"] == {"host": 1, "user": 2}
    assert r["edge_count"] == 1
    assert "host:A" in r["sample"][0]
