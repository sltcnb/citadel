"""
Cross-case Pilot memory, confidence calibration, and continuous co-pilot.

Three loosely-coupled gamechangers that turn the Pilot agent from a per-case
assistant into one with institutional memory and self-awareness:

#5  Cross-case memory  — persist IOCs / TTPs / verdicts across cases in a global
    Redis store, so "this C2 burned us before" can fire proactively on a brand
    new case (remember / recall / recall_ioc / seen_before).

#8  Confidence calibration — a PURE scorer for Pilot hypotheses that weighs
    for- vs against-evidence into a 0..1 score + low/medium/high band, plus a
    helper that annotates a whole conclude payload and flags a low-confidence
    top verdict (confidence_score / calibrate_verdict).

#6  Continuous co-pilot — a watermark (last reviewed event count) per case vs
    the live ES doc count, surfacing cheap "N new events since last review"
    suggestions with NO scheduler (case_watch_status / mark_reviewed).

Redis layout (decode_responses client — values are JSON strings):
    fo:pilot:memory:{kind}      hash  value -> JSON record
    fo:pilot:watermark:{case}   string JSON {count, at}
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from services.elasticsearch import es_request

from config import get_redis

logger = logging.getLogger(__name__)

KINDS = ("ioc", "ttp", "verdict")

_MEM_PREFIX = "fo:pilot:memory:"
_WATERMARK_PREFIX = "fo:pilot:watermark:"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _mem_key(kind: str) -> str:
    return f"{_MEM_PREFIX}{kind}"


def _watermark_key(case_id: str) -> str:
    return f"{_WATERMARK_PREFIX}{case_id}"


def _norm(value: str) -> str:
    """Normalise a memory value for dedup (trim + casefold)."""
    return (value or "").strip().casefold()


# --------------------------------------------------------------------------- #
# #5  Cross-case memory
# --------------------------------------------------------------------------- #


def remember(case_id: str, kind: str, value: str, meta: dict | None = None) -> dict:
    """Append/upsert ``value`` into the global ``kind`` store.

    Dedups by the normalised value. Tracks first/last case, the full case set,
    a sighting count, last_seen, and the latest meta. Returns the stored record.
    """
    if kind not in KINDS:
        raise ValueError(f"invalid kind {kind!r}; expected one of {KINDS}")
    val = (value or "").strip()
    if not val:
        raise ValueError("value must be non-empty")

    r = get_redis()
    key = _mem_key(kind)
    field = _norm(val)
    now = _now_iso()

    raw = r.hget(key, field)
    if raw:
        try:
            rec = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            rec = None
    else:
        rec = None

    if rec is None:
        rec = {
            "value": val,
            "kind": kind,
            "first_case": case_id,
            "last_case": case_id,
            "cases": [case_id],
            "count": 1,
            "first_seen": now,
            "last_seen": now,
            "meta": meta or {},
        }
    else:
        cases = rec.get("cases") or []
        if case_id not in cases:
            cases.append(case_id)
        rec["cases"] = cases
        rec["last_case"] = case_id
        rec["count"] = int(rec.get("count", 0)) + 1
        rec["last_seen"] = now
        if meta:
            merged = dict(rec.get("meta") or {})
            merged.update(meta)
            rec["meta"] = merged

    r.hset(key, field, json.dumps(rec))
    return rec


def recall(kind: str | None = None, value: str | None = None) -> list[dict]:
    """Look up memory records.

    - ``value`` given (with or without ``kind``) → exact records matching it.
    - only ``kind`` → every record of that kind.
    - neither → every record across all kinds.
    """
    r = get_redis()
    kinds = [kind] if kind else list(KINDS)
    out: list[dict] = []
    field = _norm(value) if value else None

    for k in kinds:
        if k not in KINDS:
            continue
        key = _mem_key(k)
        if field is not None:
            raw = r.hget(key, field)
            if raw:
                try:
                    out.append(json.loads(raw))
                except (json.JSONDecodeError, TypeError):
                    pass
        else:
            for raw in (r.hgetall(key) or {}).values():
                try:
                    out.append(json.loads(raw))
                except (json.JSONDecodeError, TypeError):
                    pass
    return out


def recall_ioc(value: str) -> dict:
    """Human-readable recall for a single IOC.

    Returns ``{seen: bool, count: int, cases: [...], message: str, record: {}}``.
    """
    recs = recall("ioc", value)
    if not recs:
        return {
            "seen": False,
            "count": 0,
            "cases": [],
            "message": f"IOC {value!r} not seen in any prior case.",
            "record": None,
        }
    rec = recs[0]
    cases = rec.get("cases") or []
    n = len(cases)
    return {
        "seen": True,
        "count": n,
        "cases": cases,
        "message": (
            f"This IOC appeared in {n} prior case{'s' if n != 1 else ''} {cases}."
        ),
        "record": rec,
    }


def seen_before(values: list[str], current_case: str | None = None) -> list[dict]:
    """Given IOCs from a (new) case, return those seen in OTHER cases.

    The proactive "this C2 burned us before" signal: a value is only returned if
    it appears in at least one case that is NOT ``current_case``. When
    ``current_case`` is None, any previously-remembered value is returned.
    """
    hits: list[dict] = []
    for v in values or []:
        recs = recall("ioc", v)
        if not recs:
            continue
        rec = recs[0]
        cases = rec.get("cases") or []
        other = [c for c in cases if c != current_case] if current_case else list(cases)
        if not other:
            continue
        hits.append(
            {
                "value": rec.get("value", v),
                "other_cases": other,
                "count": len(other),
                "last_seen": rec.get("last_seen"),
                "meta": rec.get("meta") or {},
                "message": (
                    f"{rec.get('value', v)!r} previously seen in "
                    f"{len(other)} other case{'s' if len(other) != 1 else ''}: {other}"
                ),
            }
        )
    return hits


# --------------------------------------------------------------------------- #
# #8  Confidence calibration (PURE)
# --------------------------------------------------------------------------- #


def _band(score: float) -> str:
    # >0.5 means the evidence genuinely leans somewhere; exactly-balanced (0.5)
    # and anything below is "low" — a contested or refuted hypothesis is not a
    # confident verdict.
    if score >= 0.66:
        return "high"
    if score > 0.5:
        return "medium"
    return "low"


def confidence_score(hypothesis: dict) -> dict:
    """Score a hypothesis ``{for_evidence:[...], against_evidence:[...]}``.

    PURE — no I/O. Returns ``{score: 0..1, band, rationale, for_count,
    against_count}``.

    Heuristic:
      • No evidence at all → score 0.0, band 'low'.
      • Otherwise base = for / (for + against): the share of evidence in favour.
      • Near-balanced evidence collapses toward low (the contested middle is the
        least trustworthy place to be).
      • Very thin evidence (1 item total) is damped — one bullet is weak.
    """
    hypothesis = hypothesis or {}
    for_ev = [e for e in (hypothesis.get("for_evidence") or []) if e and str(e).strip()]
    against_ev = [
        e for e in (hypothesis.get("against_evidence") or []) if e and str(e).strip()
    ]
    nf, na = len(for_ev), len(against_ev)
    total = nf + na

    if total == 0:
        return {
            "score": 0.0,
            "band": "low",
            "rationale": "No evidence supplied; cannot assess — treat as low confidence.",
            "for_count": 0,
            "against_count": 0,
        }

    # `score` is confidence in the LEANING (whichever side dominates), not the
    # raw fraction-for: a hypothesis with all-against evidence is *confidently*
    # refuted, but as a verdict it must still read low — see the band note.
    # decisiveness measures how one-sided the evidence is (0 = perfectly
    # balanced → maximally uncertain; 1 = entirely one-sided).
    base = nf / total  # fraction in favour, 0..1
    decisiveness = abs(base - 0.5) * 2.0  # 0..1

    # Thin-evidence damping: a single bullet shouldn't clinch anything.
    if total == 1:
        decisiveness *= 0.5

    # For a SUPPORTED leaning, confidence rises with decisiveness. For a refuted
    # leaning (more against than for), the hypothesis is unlikely → low score so
    # it never bubbles up as a high-confidence verdict.
    if nf > na:
        score = 0.5 + 0.5 * decisiveness
    else:
        score = 0.5 - 0.5 * decisiveness  # balanced → 0.5, all-against → 0.0

    score = max(0.0, min(1.0, round(score, 4)))
    band = _band(score)

    if nf and not na:
        rationale = f"{nf} supporting, 0 contradicting — strongly supported."
    elif na and not nf:
        rationale = f"{na} contradicting, 0 supporting — strongly refuted."
    elif abs(nf - na) <= 1:
        rationale = (
            f"{nf} for vs {na} against — evidence is near-balanced; low confidence."
        )
    elif nf > na:
        rationale = f"{nf} for vs {na} against — leans supported."
    else:
        rationale = f"{nf} for vs {na} against — leans refuted."

    return {
        "score": score,
        "band": band,
        "rationale": rationale,
        "for_count": nf,
        "against_count": na,
    }


def calibrate_verdict(verdict_dict: dict) -> dict:
    """Annotate a Pilot conclude payload's hypotheses with confidence bands.

    Adds a ``confidence`` block to each hypothesis, picks the top (highest-score)
    hypothesis, and flags the verdict if that top hypothesis is low-confidence
    ("needs more data"). Returns a NEW dict (does not mutate the input).

    PURE — no I/O.
    """
    verdict_dict = verdict_dict or {}
    out = dict(verdict_dict)
    hyps = list(verdict_dict.get("hypotheses") or [])

    annotated: list[dict] = []
    scored: list[tuple[float, dict]] = []
    for h in hyps:
        h2 = dict(h)
        conf = confidence_score(h2)
        h2["confidence"] = conf
        annotated.append(h2)
        scored.append((conf["score"], h2))

    out["hypotheses"] = annotated

    if not scored:
        out["calibration"] = {
            "top_hypothesis": None,
            "top_band": "low",
            "low_confidence": True,
            "needs_more_data": True,
            "note": "No hypotheses to calibrate — needs more data.",
        }
        return out

    # Highest score wins; ties resolve to the first declared (H1 stays primary).
    top_score, top = max(scored, key=lambda t: t[0])
    top_conf = top["confidence"]
    low = top_conf["band"] == "low"
    out["calibration"] = {
        "top_hypothesis": top.get("id") or top.get("claim"),
        "top_score": top_score,
        "top_band": top_conf["band"],
        "low_confidence": low,
        "needs_more_data": low,
        "note": (
            "Top verdict is low-confidence — needs more data before relying on it."
            if low
            else f"Top verdict confidence: {top_conf['band']}."
        ),
    }
    return out


# --------------------------------------------------------------------------- #
# #6  Continuous co-pilot (no scheduler)
# --------------------------------------------------------------------------- #


def _live_event_count(case_id: str) -> int:
    """Minimal ES _count across all case indices. Returns 0 on any error."""
    try:
        res = es_request("GET", f"/fo-case-{case_id}-*/_count")
        return int(res.get("count", 0))
    except Exception as exc:  # noqa: BLE001 — degrade gracefully
        logger.debug("watch count failed for %s: %s", case_id, exc)
        return 0


def _read_watermark(case_id: str) -> dict | None:
    r = get_redis()
    raw = r.get(_watermark_key(case_id))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def mark_reviewed(case_id: str) -> dict:
    """Set the 'last reviewed' watermark to the current live event count."""
    count = _live_event_count(case_id)
    rec = {"count": count, "at": _now_iso()}
    get_redis().set(_watermark_key(case_id), json.dumps(rec))
    return rec


def case_watch_status(case_id: str) -> dict:
    """Compare the stored watermark against the current ES count.

    Returns ``{new_events, since, current, suggestions:[...]}``. Degrades to
    ``{new_events: 0, ...}`` on any ES error. Suggestions are cheap heuristics —
    no extra queries beyond the single count.
    """
    current = _live_event_count(case_id)
    wm = _read_watermark(case_id)

    if wm is None:
        # Never reviewed — everything is "new".
        new_events = current
        since = None
    else:
        since = wm.get("at")
        new_events = max(0, current - int(wm.get("count", 0)))

    suggestions: list[str] = []
    if new_events > 0:
        if since is None:
            suggestions.append(
                f"{new_events} events have never been reviewed — run an initial triage."
            )
        else:
            suggestions.append(
                f"{new_events} new events since last review ({since}). "
                "Re-run watchlist / Pilot to triage."
            )
        suggestions.append(
            "Mark reviewed once triaged to reset the watermark."
        )

    return {
        "case_id": case_id,
        "new_events": new_events,
        "since": since,
        "current": current,
        "reviewed": wm is not None,
        "suggestions": suggestions,
    }
