"""Cross-source confidence scoring.

Fuses per-source verdicts into a single 0.0–1.0 score using a
confidence-and-weight-weighted mean of each source's maliciousness:

    score = Σ(malicious_i · confidence_i · weight_i) / Σ(confidence_i · weight_i)

Sources that errored (no usable data) contribute zero weight. A small
agreement bonus rewards multiple independent sources concurring on "bad",
which is the whole point of cross-source enrichment.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import EnrichedIOC, SourceVerdict

# Severity thresholds applied to the fused score.
_SEVERITY_BANDS = (
    (0.85, "critical"),
    (0.60, "high"),
    (0.35, "medium"),
    (0.10, "low"),
    (0.0, "benign"),
)

_MALICIOUS_THRESHOLD = 0.5  # a verdict "agrees on bad" above this


def fuse(
    verdicts: list[SourceVerdict], weights: dict[str, float] | None = None
) -> tuple[float, str, list[str]]:
    """Return (score, severity, deduped labels) for a list of source verdicts."""
    weights = weights or {}
    usable = [v for v in verdicts if v.error is None and v.confidence > 0]

    if not usable:
        return 0.0, "unknown", _collect_labels(verdicts)

    num = 0.0
    den = 0.0
    agreeing = 0
    for v in usable:
        w = weights.get(v.source, 1.0)
        eff = v.confidence * w
        num += v.malicious * eff
        den += eff
        if v.malicious >= _MALICIOUS_THRESHOLD:
            agreeing += 1

    base = num / den if den else 0.0

    # Agreement bonus: each extra source beyond the first that flags the IOC
    # as malicious nudges the score up, capped so a single source can't max it.
    if agreeing >= 2:
        bonus = min(0.15, 0.05 * (agreeing - 1))
        base = min(1.0, base + bonus)

    return round(base, 4), _severity(base), _collect_labels(verdicts)


def _severity(score: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "benign"


def _collect_labels(verdicts: Iterable[SourceVerdict]) -> list[str]:
    seen: list[str] = []
    for v in verdicts:
        for lbl in v.labels:
            if lbl and lbl not in seen:
                seen.append(lbl)
    return seen


def score_enriched(enriched: EnrichedIOC, weights: dict[str, float] | None = None) -> EnrichedIOC:
    """Populate ``score``/``severity``/``labels`` in place and return it."""
    enriched.score, enriched.severity, enriched.labels = fuse(enriched.verdicts, weights)
    return enriched
