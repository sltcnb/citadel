"""Cross-source confidence scoring tests."""

from __future__ import annotations

from augur.models import SourceVerdict
from augur.scoring import fuse


def _v(source, mal, conf=1.0, error=None):
    return SourceVerdict(source=source, malicious=mal, confidence=conf, error=error)


def test_no_usable_verdicts_is_unknown():
    score, sev, _ = fuse([_v("a", 0.0, 0.0, error="boom")])
    assert score == 0.0
    assert sev == "unknown"


def test_single_high_source_scores_but_no_agreement_bonus():
    score, sev, _ = fuse([_v("urlhaus", 0.9, 0.95)])
    assert 0.85 <= score <= 0.9
    assert sev in ("high", "critical")


def test_multiple_agreeing_sources_get_bonus():
    one = fuse([_v("a", 0.7, 1.0)])[0]
    two = fuse([_v("a", 0.7, 1.0), _v("b", 0.7, 1.0)])[0]
    assert two > one  # agreement bonus pushes it higher


def test_weights_favor_trusted_source():
    verdicts = [_v("urlhaus", 1.0, 1.0), _v("otx", 0.0, 1.0)]
    weighted = fuse(verdicts, weights={"urlhaus": 2.0, "otx": 1.0})[0]
    flat = fuse(verdicts, weights={"urlhaus": 1.0, "otx": 1.0})[0]
    assert weighted > flat


def test_errored_source_contributes_no_weight():
    clean = fuse([_v("a", 0.8, 1.0)])[0]
    withErr = fuse([_v("a", 0.8, 1.0), _v("b", 0.0, 0.0, error="x")])[0]
    assert clean == withErr


def test_severity_bands():
    assert fuse([_v("a", 0.95, 1.0)])[1] == "critical"
    assert fuse([_v("a", 0.05, 1.0)])[1] == "benign"


def test_labels_deduped_across_sources():
    _, _, labels = fuse(
        [
            SourceVerdict("a", 0.5, 1.0, labels=["emotet", "trojan"]),
            SourceVerdict("b", 0.5, 1.0, labels=["emotet", "c2"]),
        ]
    )
    assert labels == ["emotet", "trojan", "c2"]
