"""Regression tests for the Pilot's module-run tools.

Both tools were broken in a way that compounded. ``module_runs`` scanned a key
pattern that does not exist ("fo:case:{id}:module-run:*" — runs actually live in
the SET "fo:case:{id}:module_runs" pointing at HASHes "fo:module_run:{id}"), so
it returned an empty list on every case and the agent could never learn a real
run_id. ``read_module_result`` then called ``routers.modules.get_module_run``
in-process — a FastAPI endpoint whose ``current_user`` default is a
``Depends(...)`` marker — so the ACL check raised
"'Depends' object has no attribute 'get'" every single time.

In one real run the agent burned 15 of its 40 steps alternating between those
two tools and concluded "inconclusive — no determinative evidence" about data
it had never actually read.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers import llm_config as lc  # noqa: E402


class _FakeRunService:
    """Stands in for services.module_runs with the real record shape."""

    def __init__(self, runs):
        self._runs = {r["run_id"]: r for r in runs}

    def get_module_run(self, run_id):
        return self._runs.get(run_id)

    def list_case_module_runs(self, case_id):
        return [r for r in self._runs.values() if r.get("case_id") == case_id]


def _install(monkeypatch, runs):
    """Point the real services.module_runs at an in-memory run store.

    Patch the module's own functions rather than swapping the module out of
    sys.modules: the tools do `from services import module_runs`, which reads
    the attribute off the already-imported package and never consults
    sys.modules again.
    """
    import services.module_runs as real

    fake = _FakeRunService(runs)
    monkeypatch.setattr(real, "get_module_run", fake.get_module_run)
    monkeypatch.setattr(real, "list_case_module_runs", fake.list_case_module_runs)
    return fake


def _run(**over):
    run = {
        "run_id": "d1149f9a417e40f39af95a8353769b4b",
        "case_id": "case-1",
        "module_id": "cti_match",
        "status": "COMPLETED",
        "started_at": "2026-08-25T09:00:00Z",
        "total_hits": 2,
        "hits_by_level": {"high": 1, "medium": 1},
        # NOTE: the field is results_preview. The tool used to read "hits",
        # which never existed on the record.
        "results_preview": [
            {
                "level": "high",
                "rule_name": "IOC domain match",
                "message": "dntds.shop seen in browser history",
                "evidence": "https://dntds.shop/download",
            },
            {"level": "medium", "rule": "IOC ip match", "message": "178.16.53.137"},
        ],
    }
    run.update(over)
    return run


# ── read_module_result ────────────────────────────────────────────────────────


def test_read_module_result_returns_hits_instead_of_raising(monkeypatch):
    _install(monkeypatch, [_run()])
    r = lc._tool_read_module_result("case-1", {"run_id": "d1149f9a417e40f39af95a8353769b4b"})
    assert r["query_status"] == "ok", r
    assert r["total_hits"] == 2
    assert len(r["sample_hits"]) == 2
    assert r["sample_hits"][0]["rule"] == "IOC domain match"
    # The second hit uses "rule" rather than "rule_name"; both must resolve.
    assert r["sample_hits"][1]["rule"] == "IOC ip match"
    assert "dntds.shop" in r["sample_hits"][0]["message"]


def test_read_module_result_requires_a_run_id():
    r = lc._tool_read_module_result("case-1", {})
    assert r["query_status"] == "invalid"
    assert "run_id required" in r["query_error"]


def test_unknown_run_id_points_the_agent_at_module_runs(monkeypatch):
    _install(monkeypatch, [])
    r = lc._tool_read_module_result("case-1", {"run_id": "invented"})
    assert r["query_status"] == "invalid"
    assert "module_runs" in r["query_error"]
    assert "do NOT invent" in r["query_error"]


def test_run_from_another_case_is_refused(monkeypatch):
    _install(monkeypatch, [_run(case_id="someone-elses-case")])
    r = lc._tool_read_module_result("case-1", {"run_id": "d1149f9a417e40f39af95a8353769b4b"})
    assert r["query_status"] == "invalid"
    assert "different case" in r["query_error"]


def test_in_flight_run_says_absence_is_not_evidence(monkeypatch):
    """An empty hit list off a still-running scan is not a negative result —
    reading it as one is exactly how the real run reached "inconclusive"."""
    _install(monkeypatch, [_run(status="RUNNING", total_hits=0, results_preview=[])])
    r = lc._tool_read_module_result("case-1", {"run_id": "d1149f9a417e40f39af95a8353769b4b"})
    assert r["query_status"] == "ok"
    assert r["status"] == "RUNNING"
    assert "NOT evidence of absence" in r["note"]


def test_failed_run_surfaces_its_error(monkeypatch):
    _install(
        monkeypatch,
        [_run(status="FAILED", total_hits=0, results_preview=[], error="worker lost")],
    )
    r = lc._tool_read_module_result("case-1", {"run_id": "d1149f9a417e40f39af95a8353769b4b"})
    assert r["status"] == "FAILED"
    assert "worker lost" in r["note"]


def test_results_preview_stored_as_json_string_is_decoded(monkeypatch):
    """Redis hands back strings; only the service layer's deserializer expands
    them, and a raw hgetall path would skip it."""
    import json

    _install(
        monkeypatch,
        [_run(results_preview=json.dumps([{"level": "high", "rule": "r", "message": "m"}]))],
    )
    r = lc._tool_read_module_result("case-1", {"run_id": "d1149f9a417e40f39af95a8353769b4b"})
    assert r["query_status"] == "ok"
    assert len(r["sample_hits"]) == 1


def test_preview_cap_is_stated_not_silent(monkeypatch):
    _install(
        monkeypatch,
        [
            _run(
                total_hits=500,
                results_preview=[{"level": "low", "rule": "r", "message": str(i)} for i in range(60)],
            )
        ],
    )
    r = lc._tool_read_module_result("case-1", {"run_id": "d1149f9a417e40f39af95a8353769b4b"})
    assert len(r["sample_hits"]) == 40
    assert "of 500 hits" in r["note"]


# ── module_runs ───────────────────────────────────────────────────────────────


def test_module_runs_lists_real_runs(monkeypatch):
    """The tool that must hand the agent a valid run_id in the first place."""
    _install(monkeypatch, [_run(), _run(run_id="other", module_id="hayabusa", total_hits=9)])
    r = lc._tool_module_runs("case-1", {})
    assert r["query_status"] == "ok"
    assert r["total"] == 2
    # Sorted by hit count, most first.
    assert r["runs"][0]["run_id"] == "other"
    assert {x["run_id"] for x in r["runs"]} == {"other", "d1149f9a417e40f39af95a8353769b4b"}


def test_module_runs_scopes_to_the_case(monkeypatch):
    _install(monkeypatch, [_run(), _run(run_id="elsewhere", case_id="case-2")])
    r = lc._tool_module_runs("case-1", {})
    assert [x["run_id"] for x in r["runs"]] == ["d1149f9a417e40f39af95a8353769b4b"]


def test_module_runs_flags_runs_still_in_flight(monkeypatch):
    _install(monkeypatch, [_run(status="RUNNING")])
    r = lc._tool_module_runs("case-1", {})
    assert "still in flight" in r["note"]


def test_the_two_tools_compose(monkeypatch):
    """The loop the agent is supposed to run: list runs, then read one."""
    _install(monkeypatch, [_run()])
    listing = lc._tool_module_runs("case-1", {})
    run_id = listing["runs"][0]["run_id"]
    detail = lc._tool_read_module_result("case-1", {"run_id": run_id})
    assert detail["query_status"] == "ok"
    assert detail["total_hits"] == 2
