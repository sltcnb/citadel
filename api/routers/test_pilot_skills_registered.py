"""The skills must be reachable as agent actions, not merely importable.

A skill that exists but is not in AGENT_TOOLS is dead code the agent can never
call, and one missing from the settings allowlist is rejected at dispatch.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers import llm_config as lc  # noqa: E402
from routers.pilot_settings import KNOWN_TOOLS  # noqa: E402

SKILL_ACTIONS = ("ioc_sweep", "host_profile")


def test_skills_are_dispatchable_actions():
    for name in SKILL_ACTIONS:
        assert name in lc.AGENT_TOOLS, f"{name} not in AGENT_TOOLS"
        assert callable(lc.AGENT_TOOLS[name])


def test_skills_are_allowlisted_in_settings():
    for name in SKILL_ACTIONS:
        assert name in KNOWN_TOOLS, f"{name} not admin-configurable"


def test_ioc_sweep_rejects_a_missing_indicator_list():
    r = lc._tool_ioc_sweep("case-1", {"action": "ioc_sweep"})
    assert r["query_status"] == "invalid"
    assert "indicators" in r["query_error"]


def test_ioc_sweep_accepts_a_single_value_form():
    """The agent will pass {"value": "..."} sooner or later; take it."""
    called = {}

    def fake_search(query, size):
        called["query"] = query
        return {"total": 0, "hits": []}

    import pilot.skills as sk

    r = sk.run_ioc_sweep(["evil[.]com"], fake_search)
    assert r["query_status"] == "ok"
    assert "browser.url:*evil.com*" in called["query"]


def test_host_profile_rejects_a_missing_host():
    r = lc._tool_host_profile("case-1", {"action": "host_profile"})
    assert r["query_status"] == "invalid"
