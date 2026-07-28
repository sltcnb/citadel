"""The report's AI section must reflect the AI work that actually happened.

Only a *written* AI report used to count, so a case with a risk assessment,
autopilot runs and investigation sessions still exported a report whose manifest
said "No AI narrative" — the analyst's AI analysis was invisible in the
deliverable. These tests pin the fallback and the precedence between the two.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("scribe", reason="report rendering engine not installed")

import routers.reports as rp  # noqa: E402


@pytest.fixture
def fake(monkeypatch):
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(rp, "get_redis", lambda: client)
    return client


_ANALYSIS = {
    "risk_level": "high",
    "risk_score": 7,
    "executive_summary": "Suspicious lateral movement from master2.",
    "key_findings": ["4625 spray against svc_backup"],
    "recommended_actions": ["Reset svc_backup"],
    "mitre_techniques": ["T1110"],
    "analyzed_at": "2026-07-20T10:00:00+00:00",
    "model_used": "ollama/qwen",
}


def test_no_ai_work_returns_none(fake):
    assert rp._fetch_ai_report("c1") is None


def test_written_report_wins(fake):
    fake.set("case:c1:ai:report", json.dumps({"content": "# Final report", "source": "manual"}))
    fake.set("case:c1:ai:analysis", json.dumps(_ANALYSIS))

    doc = rp._fetch_ai_report("c1")

    assert doc["content"] == "# Final report"
    assert doc["source"] == "manual"


def test_empty_written_report_falls_back_to_analysis(fake):
    fake.set("case:c1:ai:report", json.dumps({"content": "   ", "source": "manual"}))
    fake.set("case:c1:ai:analysis", json.dumps(_ANALYSIS))

    doc = rp._fetch_ai_report("c1")

    assert doc["source"] == "derived"
    assert "Risk assessment" in doc["content"]
    assert "lateral movement" in doc["content"]
    assert "T1110" in doc["content"]
    assert doc["model_used"] == "ollama/qwen"
    assert doc["generated_at"] == "2026-07-20T10:00:00+00:00"


def test_derived_from_autopilot_and_investigations(fake):
    fake.lpush(
        "case:c1:ai:agent_runs",
        json.dumps(
            {
                "circumstance": "Was svc_backup compromised?",
                "stopped_reason": "concluded",
                "analyzed_at": "2026-07-21T09:00:00+00:00",
                "model_used": "ollama/qwen",
                "final": {
                    "incident_confirmed": "yes",
                    "verdict": "Credential stuffing succeeded.",
                    "evidence": ["4624 from 10.0.0.9"],
                    "indicators": ["10.0.0.9"],
                },
            }
        ),
    )
    fake.lpush(
        "case:c1:ai:investigations",
        json.dumps(
            {
                "circumstance": "Any persistence?",
                "narrative": "No scheduled-task creation observed.",
                "indicators": ["svchost.exe"],
                "analyzed_at": "2026-07-21T11:00:00+00:00",
            }
        ),
    )

    doc = rp._fetch_ai_report("c1")

    assert doc["source"] == "derived"
    assert "Autopilot investigation — Was svc_backup compromised?" in doc["content"]
    assert "Credential stuffing succeeded." in doc["content"]
    assert "Investigation session — Any persistence?" in doc["content"]
    assert doc["derived_from"] == {
        "risk_assessment": False,
        "autopilot_runs": 1,
        "investigation_sessions": 1,
    }
    # Newest artifact timestamp wins so the report is dated by its latest input.
    assert doc["generated_at"] == "2026-07-21T11:00:00+00:00"


def test_incomplete_autopilot_run_is_labelled(fake):
    fake.lpush(
        "case:c1:ai:agent_runs",
        json.dumps({"circumstance": "?", "stopped_reason": "max_steps_reached", "final": {}}),
    )

    content = rp._fetch_ai_report("c1")["content"]

    assert "Incomplete: max steps reached" in content


def test_manifest_marks_derived_narrative(fake, monkeypatch):
    """The manifest must say the narrative is derived — claiming a generated
    report the analyst never produced would be worse than saying nothing."""
    fake.set("case:c1:ai:analysis", json.dumps(_ANALYSIS))
    for name in (
        "_fetch_events",
        "_fetch_saved_searches",
        "_fetch_killchains",
        "_fetch_mitre",
    ):
        monkeypatch.setattr(rp, name, lambda *a, **k: [])
    monkeypatch.setattr(rp, "_fetch_aggregates", lambda *a, **k: {})
    monkeypatch.setattr(
        rp, "_fetch_findings", lambda *a, **k: {"items": [], "total": 0, "by_kind": {}}
    )
    monkeypatch.setattr(rp, "_fetch_module_runs", lambda *a, **k: [])

    data = rp._build_report_data({"name": "case one"}, "c1")

    assert data["manifest"]["has_ai"] is True
    assert data["manifest"]["ai_source"] == "derived"
    assert data["manifest"]["ai_model"] == "ollama/qwen"
