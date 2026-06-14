"""Regression tests for _compute_risk_score — guards the bug where a case with
many high/critical detections + CTI matches but no fired alert-rule scored 0/10.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routers.llm_config import _compute_risk_score  # noqa: E402


def test_no_signal_is_zero():
    r = _compute_risk_score({"alert_run": {"matches": []}, "findings": {}})
    assert r["score"] == 0 and r["level"] == "none"


def test_mass_high_severity_detections_without_rules_is_high():
    # The reported bug: 1.3M high/critical detections, zero fired rules → must NOT be 0.
    ctx = {"alert_run": {"matches": []}, "findings": {"high_severity": 1_300_000, "cti_high": 0}}
    r = _compute_risk_score(ctx)
    assert r["score"] >= 8, r
    assert r["level"] == "critical"
    assert "1,300,000 high/critical detection(s)" in r["basis"]


def test_cti_match_floors_the_score():
    ctx = {"alert_run": {"matches": []}, "findings": {"high_severity": 0, "cti_high": 5}}
    r = _compute_risk_score(ctx)
    assert r["score"] >= 5  # confirmed external bad → at least medium/high
    assert "confirmed CTI match" in r["basis"]


def test_fired_rules_still_count():
    ctx = {"alert_run": {"matches": [{"rule": {"level": "critical"}}, {"rule": {"level": "high"}}]},
           "findings": {}}
    r = _compute_risk_score(ctx)
    assert r["score"] >= 5  # 4 + 2 = 6
    assert r["by_severity"].get("critical") == 1


def test_takes_max_not_sum():
    # A few rules but huge detections → detection path wins; score is bounded at 10.
    ctx = {"alert_run": {"matches": [{"rule": {"level": "low"}}]},
           "findings": {"high_severity": 5_000_000, "cti_high": 200}}
    r = _compute_risk_score(ctx)
    assert r["score"] == 10 and r["level"] == "critical"


def test_modest_detection_count_is_proportionate():
    # A single high detection shouldn't scream critical.
    ctx = {"alert_run": {"matches": []}, "findings": {"high_severity": 1, "cti_high": 0}}
    r = _compute_risk_score(ctx)
    assert 1 <= r["score"] <= 4
