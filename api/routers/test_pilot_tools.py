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
    def _fake(values, current_case=None, companies=None):
        captured["values"] = values
        captured["case"] = current_case
        captured["companies"] = companies
        return [{"value": values[0], "count": 3, "cases": ["a", "b", "c"]}]
    monkeypatch.setattr(pm, "seen_before", _fake)
    r = lc._tool_cti_seen_before("c9", {"value": "1.2.3.4"})
    assert r["query_status"] == "ok"
    assert captured["values"] == ["1.2.3.4"] and captured["case"] == "c9"
    # company scope is threaded through (case company lookup fails in tests →
    # shared-only scope, but the kwarg must reach the service)
    assert captured["companies"] is not None and "" in captured["companies"]
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


def test_escape_value_colons_fixes_wildcard_colon():
    # `message:*client:*` is the #1 HTTP-400 cause — the trailing colon must be
    # escaped while real field separators and date ranges stay intact.
    q = ("artifact_type:access_log AND message:*malloc* AND message:*client:* "
         "AND timestamp:[2026-06-09T07:12:00Z TO 2026-06-09T07:22:00Z]")
    out = lc._escape_value_colons(q)
    assert "message:*client\\:*" in out
    assert "artifact_type:access_log" in out          # field separator preserved
    assert "[2026-06-09T07:12:00Z TO" in out          # range colons untouched


def test_escape_value_colons_leaves_clean_queries():
    for q in ("message:*powershell*",
              "network.src_ip:1.2.3.4",
              'http.protocol.keyword:"HTTP/2.0"',
              "message:(*IPC$* OR *ADMIN$*)"):
        assert lc._escape_value_colons(q) == q


# ── catalog / settings drift ─────────────────────────────────────────────────


def test_findings_tools_are_toggleable():
    # findings / save_finding are real AGENT_TOOLS — they must appear in
    # KNOWN_TOOLS or an admin can never disable them.
    from routers import pilot_settings as ps
    assert "findings" in ps.KNOWN_TOOLS
    assert "save_finding" in ps.KNOWN_TOOLS
    # sanity: everything in KNOWN_TOOLS (minus control-flow) is dispatchable
    for name in ps.KNOWN_TOOLS:
        assert name in lc.AGENT_TOOLS, f"{name} in KNOWN_TOOLS but not AGENT_TOOLS"


def test_web_search_provider_default_matches_defaults():
    # A GET→PUT round trip built from PilotConfigIn's defaults must not
    # silently switch the effective provider.
    from routers import pilot_settings as ps
    assert ps.PilotConfigIn().web_search_provider == ps._defaults()["web_search_provider"]


def test_agent_prompt_action_enum_covers_dispatchable_tools():
    # The static prompt's action enum drifted from the real tool set — keep
    # every dispatchable tool listed so the model knows it exists.
    enum_line = next(
        line for line in lc._AGENT_PROMPT.splitlines() if '"action":' in line
    )
    for name in (
        "set_hypotheses", "detection_rules", "watchlist", "module_runs",
        "list_modules", "launch_module", "read_module_result",
        "findings", "save_finding", "conclude",
    ):
        assert f'"{name}"' in enum_line, f"{name} missing from prompt action enum"


def test_agent_prompt_has_no_hardcoded_step_cap():
    # The budget is admin-configurable; the static prompt must not state a
    # fixed number that contradicts it.
    assert "50-step" not in lc._AGENT_PROMPT


# ── cancel flag TTL ──────────────────────────────────────────────────────────


def test_cancel_flag_ttl_outlives_worst_case_step(monkeypatch):
    # A single step can take >120s (90s LLM timeout + broaden ladder) — the
    # cancel flag's TTL must comfortably exceed that or it evaporates before
    # the worker's next inter-step check.
    import fakeredis
    import pilot.service as psvc

    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(psvc, "_redis", lambda: fake)

    assert lc._AGENT_CANCEL_TTL >= 600
    out = lc.ai_agent_cancel("case1", "run1")
    assert out == {"cancelling": True, "run_id": "run1"}
    key = "case:case1:ai:agent_cancel:run1"
    assert fake.get(key) == "1"
    assert fake.ttl(key) == lc._AGENT_CANCEL_TTL
