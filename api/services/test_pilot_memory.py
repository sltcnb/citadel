"""Unit tests for services.pilot_memory.

Cross-case memory + watermark logic run against a fakeredis client patched into
the module (same approach as api/conftest.py). The confidence scorer is pure so
it's tested directly. ES is stubbed by monkeypatching pilot_memory.es_request.
"""

import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import pilot_memory as pm  # noqa: E402


@pytest.fixture
def fake_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(pm, "get_redis", lambda: fake, raising=True)
    return fake


# --------------------------------------------------------------------------- #
# #5  Cross-case memory
# --------------------------------------------------------------------------- #


def test_remember_dedups_and_tracks_multiple_cases(fake_redis):
    pm.remember("caseA", "ioc", "1.2.3.4")
    pm.remember("caseB", "ioc", "1.2.3.4", meta={"tag": "c2"})
    # same case again — should not duplicate the case but should bump count
    pm.remember("caseB", "ioc", "1.2.3.4")

    recs = pm.recall("ioc", "1.2.3.4")
    assert len(recs) == 1
    rec = recs[0]
    assert rec["first_case"] == "caseA"
    assert rec["last_case"] == "caseB"
    assert sorted(rec["cases"]) == ["caseA", "caseB"]
    assert rec["count"] == 3  # three sightings
    assert rec["meta"]["tag"] == "c2"


def test_remember_normalises_value_for_dedup(fake_redis):
    pm.remember("caseA", "ioc", "Evil.EXE")
    pm.remember("caseB", "ioc", "evil.exe")
    recs = pm.recall("ioc", "evil.exe")
    assert len(recs) == 1
    assert sorted(recs[0]["cases"]) == ["caseA", "caseB"]


def test_remember_rejects_bad_kind(fake_redis):
    with pytest.raises(ValueError):
        pm.remember("caseA", "bogus", "x")


def test_remember_rejects_empty_value(fake_redis):
    with pytest.raises(ValueError):
        pm.remember("caseA", "ioc", "   ")


def test_recall_all_kinds(fake_redis):
    pm.remember("c1", "ioc", "1.1.1.1")
    pm.remember("c1", "ttp", "T1059")
    pm.remember("c1", "verdict", "malware confirmed")
    assert len(pm.recall()) == 3
    assert len(pm.recall("ttp")) == 1


def test_recall_ioc_count(fake_redis):
    pm.remember("c1", "ioc", "9.9.9.9")
    pm.remember("c2", "ioc", "9.9.9.9")
    pm.remember("c3", "ioc", "9.9.9.9")
    out = pm.recall_ioc("9.9.9.9")
    assert out["seen"] is True
    assert out["count"] == 3
    assert sorted(out["cases"]) == ["c1", "c2", "c3"]
    assert "3 prior cases" in out["message"]


def test_recall_ioc_unseen(fake_redis):
    out = pm.recall_ioc("0.0.0.0")
    assert out["seen"] is False
    assert out["count"] == 0
    assert out["record"] is None


def test_seen_before_returns_only_cross_case_hits(fake_redis):
    # value seen ONLY in the current case → not a cross-case hit
    pm.remember("caseX", "ioc", "1.1.1.1")
    # value seen in another case too → IS a cross-case hit
    pm.remember("caseX", "ioc", "2.2.2.2")
    pm.remember("caseY", "ioc", "2.2.2.2")

    hits = pm.seen_before(["1.1.1.1", "2.2.2.2", "never-seen"], current_case="caseX")
    values = {h["value"] for h in hits}
    assert values == {"2.2.2.2"}
    hit = hits[0]
    assert hit["other_cases"] == ["caseY"]
    assert hit["count"] == 1


def test_seen_before_no_current_case_returns_any_known(fake_redis):
    pm.remember("caseX", "ioc", "3.3.3.3")
    hits = pm.seen_before(["3.3.3.3"], current_case=None)
    assert len(hits) == 1
    assert hits[0]["other_cases"] == ["caseX"]


# --------------------------------------------------------------------------- #
# #8  Confidence calibration (pure — no fixtures needed)
# --------------------------------------------------------------------------- #


def test_confidence_strong_for_is_high():
    out = pm.confidence_score(
        {"for_evidence": ["a", "b", "c", "d"], "against_evidence": []}
    )
    assert out["band"] == "high"
    assert out["score"] >= 0.66
    assert out["for_count"] == 4
    assert out["against_count"] == 0


def test_confidence_balanced_is_low():
    out = pm.confidence_score(
        {"for_evidence": ["a", "b", "c"], "against_evidence": ["x", "y", "z"]}
    )
    assert out["band"] == "low"
    assert out["score"] <= 0.5  # balanced sits at the uncertain midpoint


def test_confidence_empty_is_low():
    out = pm.confidence_score({"for_evidence": [], "against_evidence": []})
    assert out["band"] == "low"
    assert out["score"] == 0.0


def test_confidence_empty_dict_is_low():
    out = pm.confidence_score({})
    assert out["band"] == "low"


def test_confidence_strong_against_is_low_score():
    out = pm.confidence_score(
        {"for_evidence": [], "against_evidence": ["a", "b", "c", "d"]}
    )
    # strongly refuted — score near 0
    assert out["score"] < 0.4
    assert out["band"] == "low"


def test_confidence_ignores_blank_evidence():
    out = pm.confidence_score(
        {"for_evidence": ["real", "  ", ""], "against_evidence": [None]}
    )
    assert out["for_count"] == 1
    assert out["against_count"] == 0


# --------------------------------------------------------------------------- #
# calibrate_verdict
# --------------------------------------------------------------------------- #


def test_calibrate_verdict_flags_low_confidence_top():
    verdict = {
        "verdict": "unclear",
        "hypotheses": [
            {
                "id": "H1",
                "claim": "compromise",
                "for_evidence": ["one"],
                "against_evidence": ["counter"],
            },
            {
                "id": "H2",
                "claim": "benign",
                "for_evidence": ["a"],
                "against_evidence": ["b"],
            },
        ],
    }
    out = pm.calibrate_verdict(verdict)
    assert out["calibration"]["low_confidence"] is True
    assert out["calibration"]["needs_more_data"] is True
    # each hypothesis annotated
    assert all("confidence" in h for h in out["hypotheses"])


def test_calibrate_verdict_high_confidence_not_flagged():
    verdict = {
        "hypotheses": [
            {
                "id": "H1",
                "claim": "compromise",
                "for_evidence": ["a", "b", "c", "d", "e"],
                "against_evidence": [],
            },
            {
                "id": "H2",
                "claim": "benign",
                "for_evidence": [],
                "against_evidence": ["a", "b", "c"],
            },
        ],
    }
    out = pm.calibrate_verdict(verdict)
    assert out["calibration"]["low_confidence"] is False
    assert out["calibration"]["top_band"] == "high"
    assert out["calibration"]["top_hypothesis"] == "H1"


def test_calibrate_verdict_no_hypotheses():
    out = pm.calibrate_verdict({"verdict": "x"})
    assert out["calibration"]["needs_more_data"] is True
    assert out["calibration"]["top_hypothesis"] is None


def test_calibrate_verdict_does_not_mutate_input():
    verdict = {"hypotheses": [{"id": "H1", "for_evidence": ["a"], "against_evidence": []}]}
    pm.calibrate_verdict(verdict)
    assert "confidence" not in verdict["hypotheses"][0]
    assert "calibration" not in verdict


# --------------------------------------------------------------------------- #
# #6  Continuous co-pilot — watermark mark/compare
# --------------------------------------------------------------------------- #


def test_watch_status_never_reviewed(fake_redis, monkeypatch):
    monkeypatch.setattr(pm, "es_request", lambda *a, **k: {"count": 42})
    status = pm.case_watch_status("case1")
    assert status["new_events"] == 42
    assert status["since"] is None
    assert status["reviewed"] is False
    assert status["suggestions"]  # non-empty


def test_mark_and_compare(fake_redis, monkeypatch):
    counts = {"n": 10}
    monkeypatch.setattr(pm, "es_request", lambda *a, **k: {"count": counts["n"]})

    wm = pm.mark_reviewed("case1")
    assert wm["count"] == 10

    # no new events yet
    status = pm.case_watch_status("case1")
    assert status["new_events"] == 0
    assert status["reviewed"] is True
    assert status["suggestions"] == []

    # 5 new events arrive
    counts["n"] = 15
    status = pm.case_watch_status("case1")
    assert status["new_events"] == 5
    assert status["since"] == wm["at"]
    assert status["suggestions"]


def test_watch_status_degrades_on_es_error(fake_redis, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("ES down")

    monkeypatch.setattr(pm, "es_request", boom)
    status = pm.case_watch_status("case1")
    assert status["new_events"] == 0


def test_count_never_goes_negative(fake_redis, monkeypatch):
    counts = {"n": 100}
    monkeypatch.setattr(pm, "es_request", lambda *a, **k: {"count": counts["n"]})
    pm.mark_reviewed("case1")
    # events deleted/reindexed → current < watermark
    counts["n"] = 50
    status = pm.case_watch_status("case1")
    assert status["new_events"] == 0
