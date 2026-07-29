#!/usr/bin/env python3
"""Score one Pilot autopilot run against a scenario rubric.

Why this exists
---------------
``_AGENT_PROMPT`` is 344 lines and roughly 5,300 tokens, and a large part of it is
a patch log of past failures written as instructions — "queries are LUCENE, NOT
Splunk SPL", "do NOT escape forward slashes", "if a field:value query returns 0
twice the FIELD is probably wrong", "DON'T LOOP". Each line encodes a real
failure someone hit. None of them can be evaluated, so none can ever be removed:
the prompt only grows, and a change that makes the agent worse is invisible.

This module makes an agent run *measurable*. It is deliberately pure — stdlib
only, no network, no Elasticsearch, no LLM — so the scoring itself can be tested
offline and trusted before it is used to judge anything.

It consumes the agent run document the service already persists to
``case:{id}:ai:agent_runs`` (steps / final / stopped_reason / step_count), so
nothing new has to be recorded to score a run.

Metrics
-------
Chosen so that each one fails for exactly one reason, and so that "the agent
looked at a lot of things" is never mistaken for quality:

evidence_recall
    Of the fo_ids the scenario planted as the answer, how many did the run
    actually surface (sample_ids, inspected events, or cited evidence)? This is
    the "did it find it" question and the primary metric.
citation_grounding
    Of the fo_ids the run CITES in its conclusion, how many really exist in the
    corpus? Detects a verdict supported by invented evidence — the failure the
    report prompt currently tries to prevent with prose.
verdict
    Does ``final.incident_confirmed`` match the rubric? Scored separately from
    evidence because finding the events and drawing the right conclusion are
    different skills, and a harness that blends them cannot tell you which broke.
technique_recall
    Fraction of the rubric's ATT&CK techniques present in the conclusion.
efficiency
    Steps used against the rubric's budget. Not a pass/fail on its own — an agent
    that answers correctly in 40 steps is better than one that fails in 10.
termination
    Did it conclude, or run out of budget? ``max_steps_reached`` with a correct
    answer still counts as a partial failure: it means the analyst waited for a
    conclusion the agent never committed to.
waste
    Steps that returned nothing AND repeated an earlier action signature. The
    prompt's "DON'T LOOP" paragraph exists because of this; now it has a number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Weights for the composite. Finding the evidence and not inventing evidence
# dominate; efficiency is a tiebreaker, never a gate.
_WEIGHTS = {
    "evidence_recall": 0.35,
    "citation_grounding": 0.25,
    "verdict": 0.20,
    "technique_recall": 0.10,
    "termination": 0.05,
    "efficiency": 0.05,
}

_VERDICT_VALUES = {"yes", "no", "partial", "inconclusive"}


@dataclass
class Metric:
    name: str
    value: float          # 0.0 – 1.0
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"[{mark}] {self.name:20} {self.value:5.2f}  {self.detail}"


@dataclass
class Scorecard:
    scenario: str
    metrics: list[Metric] = field(default_factory=list)
    composite: float = 0.0
    passed: bool = False

    def get(self, name: str) -> Metric | None:
        return next((m for m in self.metrics if m.name == name), None)

    def as_dict(self) -> dict:
        return {
            "scenario": self.scenario,
            "composite": round(self.composite, 4),
            "passed": self.passed,
            "metrics": [
                {"name": m.name, "value": round(m.value, 4), "passed": m.passed,
                 "detail": m.detail}
                for m in self.metrics
            ],
        }

    def __str__(self) -> str:
        head = f"{self.scenario}  composite={self.composite:.2f}  " \
               f"{'PASS' if self.passed else 'FAIL'}"
        return "\n".join([head, *(f"  {m}" for m in self.metrics)])


# ── run-document readers ─────────────────────────────────────────────────────
# The agent run doc is written by pilot/service.py; these helpers isolate every
# assumption about its shape so a change there breaks in one place.


def surfaced_ids(run: dict) -> set[str]:
    """Every fo_id the run actually saw — search samples plus inspected events.

    Mirrors service.py::_ids_surfaced_in_run, but as a set and uncapped: a
    scorer must not inherit a display cap.
    """
    out: set[str] = set()
    for step in run.get("steps") or []:
        for fid in step.get("sample_ids") or []:
            if fid:
                out.add(str(fid))
        if step.get("action") == "inspect" and step.get("fo_id"):
            out.add(str(step["fo_id"]))
    return out


def cited_ids(run: dict) -> set[str]:
    """fo_ids the conclusion offers as evidence.

    ``final.evidence`` is free text per item, so ids are extracted rather than
    assumed to be bare — the agent writes things like
    "ev-3 — vssadmin delete shadows".
    """
    final = run.get("final") or {}
    out: set[str] = set()
    for item in final.get("evidence") or []:
        text = item if isinstance(item, str) else json.dumps(item)
        for token in _ID_TOKENS(text):
            out.add(token)
    for fid in final.get("evidence_ids") or []:  # if a future version emits them
        if fid:
            out.add(str(fid))
    return out


def _ID_TOKENS(text: str) -> list[str]:
    """Candidate fo_ids in free text: uuid-ish or fixture-style ``ev-…`` tokens.

    The fixture pattern must accept internal hyphens: without them
    ``ev-shadow-1`` truncated to ``ev-shadow``, which does not exist in the
    corpus, so a correctly-cited run was reported as citing invented evidence —
    a false accusation, and the worst possible failure for this metric.
    """
    import re

    return re.findall(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b|\bev-[0-9a-zA-Z_-]+\b", text)


def techniques(run: dict) -> set[str]:
    final = run.get("final") or {}
    out = set()
    for t in final.get("mitre_techniques") or []:
        if isinstance(t, str) and t.strip():
            out.add(t.strip().upper())
    return out


def wasted_steps(run: dict) -> list[int]:
    """Steps that returned nothing AND repeated an earlier action signature.

    A zero-hit step is legitimate — ruling something out is progress. It only
    counts as waste when the same (action, query/field) shape has already come
    back empty, which is the looping behaviour the prompt asks the model to avoid.
    """
    seen: set[tuple] = set()
    waste: list[int] = []
    for step in run.get("steps") or []:
        sig = (
            step.get("action"),
            (step.get("query") or step.get("agg_field") or step.get("fo_id") or "").strip().lower(),
        )
        count = step.get("result_count")
        empty = count == 0 or count is None
        if empty and sig in seen and sig[1]:
            waste.append(int(step.get("step", 0)))
        if empty:
            seen.add(sig)
    return waste


# ── scoring ──────────────────────────────────────────────────────────────────


def score(run: dict, rubric: dict, corpus_ids: set[str] | None = None) -> Scorecard:
    """Score *run* against *rubric*.

    ``corpus_ids`` is every fo_id that exists in the scenario's seeded data. It is
    what makes citation_grounding meaningful: without it a fabricated id cannot be
    told from a real one, so the metric is skipped rather than guessed.
    """
    card = Scorecard(scenario=str(rubric.get("id") or rubric.get("scenario") or "?"))
    surfaced = surfaced_ids(run)
    cited = cited_ids(run)

    # ── evidence_recall ──
    key = {str(k) for k in (rubric.get("key_evidence") or [])}
    if key:
        found = key & (surfaced | cited)
        need = rubric.get("min_key_evidence")
        recall = len(found) / len(key)
        threshold = (need / len(key)) if isinstance(need, int) and need > 0 else 1.0
        card.metrics.append(Metric(
            "evidence_recall", recall, recall + 1e-9 >= threshold,
            f"{len(found)}/{len(key)} planted id(s) surfaced"
            + (f"; missed {sorted(key - found)}" if key - found else ""),
        ))
    else:
        card.metrics.append(Metric("evidence_recall", 1.0, True, "no key_evidence in rubric"))

    # ── citation_grounding ──
    if corpus_ids is None:
        card.metrics.append(Metric(
            "citation_grounding", 1.0, True, "skipped — corpus ids unknown"))
    elif not cited:
        # Concluding without citing anything is not "perfectly grounded"; it is a
        # different defect, and the rubric decides whether it is tolerated.
        ok = not rubric.get("require_citations", True)
        card.metrics.append(Metric(
            "citation_grounding", 0.0 if not ok else 1.0, ok,
            "conclusion cited no fo_id"))
    else:
        real = {c for c in cited if c in corpus_ids}
        grounded = len(real) / len(cited)
        card.metrics.append(Metric(
            "citation_grounding", grounded, grounded == 1.0,
            f"{len(real)}/{len(cited)} cited id(s) exist"
            + (f"; INVENTED {sorted(cited - real)}" if cited - real else ""),
        ))

    # ── verdict ──
    want = str(rubric.get("incident_confirmed") or "").strip().lower()
    got = str((run.get("final") or {}).get("incident_confirmed") or "").strip().lower()
    if want:
        if want not in _VERDICT_VALUES:
            raise ValueError(
                f"rubric incident_confirmed={want!r} must be one of {sorted(_VERDICT_VALUES)}"
            )
        hit = got == want
        # A "partial" answer to a "yes" scenario is closer than a flat "no".
        near = {("yes", "partial"), ("partial", "yes")}
        val = 1.0 if hit else (0.5 if (want, got) in near else 0.0)
        card.metrics.append(Metric(
            "verdict", val, hit, f"expected {want!r}, got {got or '(none)'!r}"))
    else:
        card.metrics.append(Metric("verdict", 1.0, True, "no expected verdict"))

    # ── technique_recall ──
    want_t = {t.upper() for t in (rubric.get("techniques") or [])}
    if want_t:
        got_t = techniques(run)
        # A sub-technique satisfies its parent (T1059.001 answers T1059).
        matched = {w for w in want_t if any(g == w or g.startswith(w + ".") for g in got_t)}
        val = len(matched) / len(want_t)
        card.metrics.append(Metric(
            "technique_recall", val, val + 1e-9 >= float(rubric.get("min_technique_recall", 0.5)),
            f"{sorted(matched)} of {sorted(want_t)}"))
    else:
        card.metrics.append(Metric("technique_recall", 1.0, True, "no techniques in rubric"))

    # ── termination ──
    reason = run.get("stopped_reason") or "?"
    concluded = reason == "concluded"
    card.metrics.append(Metric(
        "termination", 1.0 if concluded else 0.0, concluded, f"stopped_reason={reason}"))

    # ── efficiency ──
    budget = rubric.get("max_steps")
    used = int(run.get("step_count") or len(run.get("steps") or []))
    waste = wasted_steps(run)
    if isinstance(budget, int) and budget > 0:
        val = max(0.0, min(1.0, (budget - used + 1) / budget)) if used else 0.0
        card.metrics.append(Metric(
            "efficiency", val, used <= budget,
            f"{used} step(s), budget {budget}"
            + (f", {len(waste)} wasted (repeat empty: steps {waste})" if waste else "")))
    else:
        card.metrics.append(Metric(
            "efficiency", 1.0, True,
            f"{used} step(s), no budget set"
            + (f", {len(waste)} wasted" if waste else "")))

    card.composite = sum(_WEIGHTS[m.name] * m.value for m in card.metrics if m.name in _WEIGHTS)
    # A scenario passes only when every GATING metric passes. Efficiency is
    # reported but never gates: a correct slow answer beats a fast wrong one.
    card.passed = all(m.passed for m in card.metrics if m.name != "efficiency")
    return card


def score_many(results: list[tuple[dict, dict, set[str] | None]]) -> dict[str, Any]:
    """Score several (run, rubric, corpus_ids) triples into one report."""
    cards = [score(r, ru, ci) for r, ru, ci in results]
    return {
        "scenarios": len(cards),
        "passed": sum(1 for c in cards if c.passed),
        "mean_composite": round(sum(c.composite for c in cards) / len(cards), 4) if cards else 0.0,
        "cards": [c.as_dict() for c in cards],
    }
