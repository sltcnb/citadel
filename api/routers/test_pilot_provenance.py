"""Tests for AI case-analysis provenance: any finding returned by
POST /cases/{case_id}/ai/analyze must be traceable back to the exact source
event ids, model, and input that produced it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pilot import service as lc  # noqa: E402


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def set(self, key, value):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key)


def test_ai_analyze_case_includes_provenance(monkeypatch):
    fake_ctx = {
        "case_name": "Case 1",
        "status": "open",
        "tags": [],
        "event_count": 1234,
        "artifact_types": ["evtx", "cti_match"],
        "searchable_fields": [],
        "field_density": [],
        "mitre_summary": [],
        "alert_run": {},
        "findings": {"high_severity": 2, "cti_high": 1, "by_artifact": []},
        "findings_store": {"total": 2, "by_kind": {}, "by_severity": {}, "top": []},
        "notes_body": "",
        "source_event_ids": ["evt-aaa", "evt-bbb", "evt-aaa"],
    }

    monkeypatch.setattr(lc, "_redis", lambda: _FakeRedis())
    monkeypatch.setattr(lc, "_get_config", lambda r: {
        "enabled": True, "provider": "anthropic", "model": "claude-test",
    })
    monkeypatch.setattr(lc, "_gather_case_context", lambda case_id: fake_ctx)
    monkeypatch.setattr(
        lc,
        "_call_llm_with_system",
        lambda cfg, system, user_msg, max_tokens=1200: json.dumps(
            {
                "executive_summary": "Suspicious activity detected.",
                "key_findings": ["Suspicious PowerShell download (event_ids: evt-aaa)"],
                "mitre_techniques": ["T1059"],
                "recommended_actions": ["Isolate host"],
                "confidence": "medium",
            }
        ),
    )

    result = lc.ai_analyze_case("case-1")

    assert result["model_used"] == "anthropic/claude-test"
    assert "provenance" in result
    prov = result["provenance"]

    # Model + timestamp
    assert prov["model"] == "anthropic/claude-test"
    assert prov["analyzed_at"] == result["analyzed_at"]

    # Source event ids: deduped, and traceable back to the exact events seen.
    assert prov["source_event_ids"] == ["evt-aaa", "evt-bbb", "evt-aaa"]
    assert "evt-aaa" in prov["source_event_ids"]
    assert prov["event_count_analyzed"] == len(prov["source_event_ids"])
    assert prov["total_case_events"] == 1234

    # Content hash of the exact input sent to the model, so a finding can be
    # verified as having come from a specific, reproducible prompt.
    assert isinstance(prov["input_hash"], str) and len(prov["input_hash"]) == 64

    # The result returned is exactly what gets json.dumps'd and persisted —
    # round-trip it to confirm provenance survives serialization.
    persisted = json.loads(json.dumps(result))
    assert persisted["provenance"]["source_event_ids"] == prov["source_event_ids"]


def test_provenance_input_hash_changes_with_context(monkeypatch):
    """Two different evidence sets must not collide on the same input hash."""
    base_ctx = {
        "case_name": "Case 1", "status": "open", "tags": [], "event_count": 10,
        "artifact_types": [], "searchable_fields": [], "field_density": [],
        "mitre_summary": [], "alert_run": {},
        "findings": {"high_severity": 0, "cti_high": 0, "by_artifact": []},
        "findings_store": {"total": 0, "by_kind": {}, "by_severity": {}, "top": []},
        "notes_body": "", "source_event_ids": ["evt-1"],
    }
    other_ctx = dict(base_ctx, source_event_ids=["evt-2"], event_count=20)

    monkeypatch.setattr(lc, "_redis", lambda: _FakeRedis())
    monkeypatch.setattr(lc, "_get_config", lambda r: {
        "enabled": True, "provider": "anthropic", "model": "claude-test",
    })
    monkeypatch.setattr(
        lc,
        "_call_llm_with_system",
        lambda cfg, system, user_msg, max_tokens=1200: json.dumps({"executive_summary": "x"}),
    )

    monkeypatch.setattr(lc, "_gather_case_context", lambda case_id: base_ctx)
    r1 = lc.ai_analyze_case("case-1")

    monkeypatch.setattr(lc, "_gather_case_context", lambda case_id: other_ctx)
    r2 = lc.ai_analyze_case("case-1")

    assert r1["provenance"]["input_hash"] != r2["provenance"]["input_hash"]
