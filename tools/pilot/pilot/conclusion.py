"""Conclusion schema v2: validation and finalisation.

The model writes the conclusion; this module decides whether it may stand.
Prompt rules are unreliable on a mid-size model, so every rule that can be
checked by code is checked here, with a rejection message that says exactly
what to do. ``validate`` returns those messages (the controller sends the
conclusion back with them); ``finalize`` applies the deterministic outcomes
that do not need the model — downgrades, derived fields, the checklist — and
records whatever is still unmet.

v1 consumers (UI, report polish, IOC promotion) read string lists
(``evidence``, ``indicators``, ``next_steps``, hypothesis for/against) and
``incident_confirmed``; ``finalize`` keeps those populated, deriving them from
the v2 structures when the model left them empty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pilot.anchors import JOIN_KEYS, Anchor
from pilot.iocs import normalize_iocs

SCHEMA_VERSION = 2

ENTITY_KINDS = ("ip", "account", "host", "path", "file", "share")
ENTITY_STATUSES = ("confirmed", "contradicted", "unresolved")
HYPOTHESIS_STATUSES = ("supported", "unsupported", "refuted", "partial", "untested")
PROVENANCES = ("collected", "alert", "analyst", "inference")
CONTEXT_STATUSES = ("related", "unrelated", "unchecked")
BASELINE_ANOMALY_RATIO = 3.0

_FO_ID = re.compile(r"\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32}|[a-z]{2,8}-[a-z0-9]{2,}-[0-9a-f]{3,}|[a-z]{2,8}-\d{3,})\b", re.I)
# Against-evidence that only says the actor/source is legitimate never refutes.
_LEGIT_ONLY = re.compile(
    r"legitimate|valid (?:cred|account)|known (?:infra|server|host)|backup server|service account|"
    r"whitelist|approved|routine|authori[sz]ed|internal (?:tool|server|host)|signed", re.I)
_ROUTINE = re.compile(r"\b(routine|baseline|usual|normal activity|regular pattern|habituel|routini)", re.I)
_ABSENCE = re.compile(r"\b(no evidence|not found|absent|absence|never (?:seen|occurs?)|0 hits|collection gap|"
                      r"not collected|no (?:recurrence|execution|other))\b", re.I)
_QUANTIFIER = re.compile(r"\b(all (?:\d+|six|five|four|three|of)|every|each of|tous|toutes)\b", re.I)


@dataclass
class Context:
    """What the controller knows that the conclusion is checked against."""
    anchors: list[Anchor]
    transcript: list[dict]
    prior_confidence: int | None = None
    case_detections: list[dict] = field(default_factory=list)

    @property
    def seen_ids(self) -> set[str]:
        return seen_fo_ids(self.transcript)

    @property
    def alert_entities(self) -> list[Anchor]:
        return [a for a in self.anchors if a.kind in ENTITY_KINDS]

    @property
    def join_keys(self) -> list[Anchor]:
        return [a for a in self.anchors if a.kind in JOIN_KEYS]


# ── transcript facts ────────────────────────────────────────────────────────


def seen_fo_ids(transcript: list[dict]) -> set[str]:
    """fo_ids that tool results actually returned in this run (broadened samples excluded)."""
    ids: set[str] = set()
    for s in transcript:
        ids.update(str(x) for x in s.get("sample_ids") or [])
        if s.get("fo_id") and s.get("action") == "inspect" and s.get("event"):
            ids.add(str(s["fo_id"]))
        for lg in s.get("logons") or []:
            if lg.get("fo_id"):
                ids.add(str(lg["fo_id"]))
        for sess in s.get("sessions") or []:
            ids.update(str(e["fo_id"]) for e in sess.get("events") or [] if e.get("fo_id"))
    return ids


def join_confirmed(ctx: Context) -> bool:
    """Did a join on one of the alert's join keys return the session?"""
    keys = {a.value.lower() for a in ctx.join_keys}
    for s in ctx.transcript:
        if s.get("action") == "session_pivot" and (s.get("result_count") or 0) > 0:
            return True
        if s.get("action") in ("search", "aggregate") and (s.get("result_count") or 0) > 0:
            q = f"{s.get('query', '')} {s.get('agg_query', '')}".lower()
            if any(k in q for k in keys):
                return True
    return False


def _did(ctx: Context, *actions: str) -> bool:
    return any(s.get("action") in actions for s in ctx.transcript)


def _cites(items, seen: set[str]) -> list[str]:
    """fo_ids cited in *items* (strings, lists or dicts with fo_ids) that the run actually saw."""
    found = []
    for it in items if isinstance(items, list) else [items]:
        if isinstance(it, dict):
            found += [str(x) for x in it.get("fo_ids") or [] if str(x) in seen]
            it = " ".join(str(v) for v in it.values())
        found += [m for m in _FO_ID.findall(str(it)) if m in seen]
    return found


def parse_prior_confidence(text: str) -> int | None:
    m = re.search(r"(?:confiance|confidence)[^\d%]{0,30}(\d{1,3})\s*%|(\d{1,3})\s*%\s*(?:de\s+)?(?:confiance|confidence)",
                  text or "", re.I)
    if not m:
        return None
    v = int(m.group(1) or m.group(2))
    return v if 0 <= v <= 100 else None


_TS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)"), lambda m: f"{m[1]}T{m[2]}"),
    (re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}:\d{2}(?::\d{2})?)"), lambda m: f"{m[3]}-{m[2]}-{m[1]}T{m[4]}"),
]
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}
_TS_TEXT = re.compile(r"(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?\s+(\d{4})\s+(\d{2}:\d{2}(?::\d{2})?)")


def alert_time(text: str) -> datetime | None:
    """First timestamp in the alert text (UTC assumed; the ±window absorbs offsets)."""
    for rx, fmt in _TS:
        m = rx.search(text or "")
        if m:
            try:
                return datetime.fromisoformat(fmt(m)).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    m = _TS_TEXT.search(text or "")
    if m and m[2][:3].lower() in _MONTHS:
        try:
            return datetime.fromisoformat(
                f"{m[3]}-{_MONTHS[m[2][:3].lower()]:02d}-{int(m[1]):02d}T{m[4]}").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


# ── validation ──────────────────────────────────────────────────────────────


def validate(c: dict, ctx: Context) -> list[str]:
    """Rejection messages for a proposed conclusion; empty when it may stand."""
    issues: list[str] = []
    seen = ctx.seen_ids
    verdict = str(c.get("incident_confirmed") or "").lower()

    # Join keys from the alert were used.
    if ctx.join_keys and not join_confirmed(ctx) and not _did(ctx, "session_pivot"):
        k = ctx.join_keys[0]
        issues.append(f"The alert gives a join key ({k.kind} {k.value}) and no step joined on it. "
                      f"Run {k.recipe()} before concluding.")

    # Every alert entity has a status, backed by fo_ids when not unresolved.
    entities = [e for e in c.get("entities") or [] if isinstance(e, dict)]
    by_value = {str(e.get("value", "")).lower(): e for e in entities}
    for a in ctx.alert_entities:
        e = by_value.get(a.value.lower())
        if not e:
            issues.append(f'entities: no status for alert {a.kind} "{a.value}". Add '
                          '{"kind","value","status":"confirmed|contradicted|unresolved","fo_ids":[…]}.')
            continue
        st = str(e.get("status", "")).lower()
        if st not in ENTITY_STATUSES:
            issues.append(f'entities: "{a.value}" status must be one of {list(ENTITY_STATUSES)}.')
        elif st != "unresolved" and not _cites(e, seen):
            issues.append(f'entities: "{a.value}" is {st} but cites no fo_id returned in this run — '
                          "cite the joining event(s) or mark it unresolved.")

    # Contradicted entities must be registered as discrepancies.
    disc_text = " ".join(str(d) for d in c.get("discrepancies") or []).lower()
    for e in entities:
        if str(e.get("status", "")).lower() == "contradicted" and str(e.get("value", "")).lower() not in disc_text:
            issues.append(f'discrepancies: "{e.get("value")}" is contradicted by evidence but not listed '
                          "in discrepancies (alert value, evidence value, fo_ids, resolved?).")

    # Provenance on every claim; collected claims cite fo_ids seen in this run.
    for i, cl in enumerate(c.get("claims") or []):
        if not isinstance(cl, dict):
            issues.append(f"claims[{i}] must be an object with text, provenance, fo_ids.")
            continue
        prov = str(cl.get("provenance", "")).lower()
        if prov not in PROVENANCES:
            issues.append(f"claims[{i}] provenance must be one of {list(PROVENANCES)}.")
        elif prov == "collected" and not _cites(cl, seen):
            issues.append(f'claims[{i}] "{str(cl.get("text", ""))[:60]}" is marked collected but cites no '
                          "fo_id returned in this run — cite it, or label it analyst/inference.")

    # Confidence recomputed against the prior.
    conf = c.get("confidence")
    if ctx.prior_confidence is not None:
        if c.get("prior_confidence") is None:
            issues.append(f"prior_confidence: the alert's prior is {ctx.prior_confidence}% — state it.")
        resolved = verdict in ("yes", "no") or any(
            str(h.get("status", "")).lower() == "refuted" for h in c.get("hypotheses") or [] if isinstance(h, dict))
        if isinstance(conf, (int, float)) and int(conf) == ctx.prior_confidence and resolved:
            issues.append(f"confidence: you resolve unknowns / refute hypotheses yet keep exactly the prior "
                          f"{ctx.prior_confidence}%. Recompute it and say what moved it in confidence_rationale.")
    if isinstance(conf, (int, float)) and not str(c.get("confidence_rationale") or "").strip():
        issues.append("confidence_rationale: say which evidence sets the confidence.")

    # Verdict gating: benign/malicious need the alert's action attributed by a join.
    if verdict in ("yes", "no") and ctx.join_keys and not join_confirmed(ctx):
        issues.append(f'verdict "{verdict}" needs the alert\'s action attributed through a confirmed join '
                      "(session_pivot). Join first, or conclude inconclusive with the leading explanation.")

    # Case context: each prior detection near the alert is addressed.
    addressed = {str(x.get("id")): x for x in c.get("case_context") or [] if isinstance(x, dict)}
    for d in ctx.case_detections:
        x = addressed.get(str(d["id"]))
        if not x:
            issues.append(f'case_context: prior detection {d["id"]} ("{d.get("title")}" at {d.get("timestamp")}) '
                          "is not addressed — related / unrelated (with reason) / unchecked.")
        elif str(x.get("status", "")).lower() not in CONTEXT_STATUSES:
            issues.append(f"case_context: {d['id']} status must be one of {list(CONTEXT_STATUSES)}.")
        elif str(x.get("status")).lower() == "unrelated" and not str(x.get("reason") or "").strip():
            issues.append(f"case_context: {d['id']} marked unrelated without a reason.")

    # Baseline: "routine" needs the numbers, and the numbers must agree.
    # The agent's own assertions — analyst / alert claims are inputs, not its findings.
    text = " ".join(str(c.get(k) or "") for k in ("verdict", "linked_summary")) + " " + \
        " ".join(str(cl.get("text", "")) for cl in c.get("claims") or []
                 if isinstance(cl, dict) and str(cl.get("provenance", "")).lower() in ("collected", "inference"))
    baselines = [b for b in c.get("baseline") or [] if isinstance(b, dict)]
    if _ROUTINE.search(text):
        if not baselines:
            issues.append("baseline: you call activity routine/baseline — add baseline entries with metric, "
                          "alert_value, baseline_value (same field, same time-of-day on prior days).")
        for b in baselines:
            r = _ratio(b)
            if r is not None and r >= BASELINE_ANOMALY_RATIO:
                issues.append(f'baseline: "{b.get("metric")}" is {r:.1f}× its baseline — that is not routine. '
                              "Explain what differs, or drop the routine claim.")

    # Absence claims need a coverage check.
    if _ABSENCE.search(text) and not (_did(ctx, "coverage_check") or any(s.get("coverage_note") for s in ctx.transcript)):
        issues.append("absence: you claim something is absent / not collected without a coverage check — run "
                      "coverage_check on the host and window first.")

    # Generalisations need an aggregate or several inspected events.
    if _QUANTIFIER.search(text):
        inspected = sum(1 for s in ctx.transcript if s.get("action") == "inspect")
        if not _did(ctx, "aggregate") and inspected < 3:
            issues.append('generalisation: a claim about "all/every" events rests on fewer than 3 inspected '
                          "events and no aggregate — aggregate them on the field you generalise.")

    # Next steps are executable and tied to something open.
    for i, na in enumerate(c.get("next_actions") or []):
        if not isinstance(na, dict):
            issues.append(f"next_actions[{i}] must be an object.")
            continue
        runnable = na.get("tool") and isinstance(na.get("params"), dict)
        askable = na.get("owner") and na.get("question")
        if not (runnable or askable):
            issues.append(f"next_actions[{i}] needs either tool+params or owner+question.")
        if not str(na.get("addresses") or "").strip():
            issues.append(f"next_actions[{i}] must name the open question or entity it resolves (addresses).")
    if (c.get("open_questions") or any(str(e.get("status")) == "unresolved" for e in entities)) \
            and not c.get("next_actions"):
        issues.append("next_actions: open questions remain but no executable next action resolves them.")
    return issues


def _ratio(b: dict) -> float | None:
    if isinstance(b.get("ratio"), (int, float)):
        return float(b["ratio"])
    try:
        base = float(b.get("baseline_value"))
        return float(b.get("alert_value")) / base if base else None
    except (TypeError, ValueError):
        return None


# ── finalisation ────────────────────────────────────────────────────────────


def finalize(c: dict, ctx: Context, unmet: list[str] | None = None) -> dict:
    """Apply deterministic outcomes, derive v1 fields, attach the checklist."""
    c = dict(c)
    c["schema_version"] = SCHEMA_VERSION
    seen = ctx.seen_ids
    notes: list[str] = []

    # Hypothesis semantics: refuted needs contradicting fo_ids, not legitimacy.
    hyps = []
    for h in c.get("hypotheses") or []:
        if not isinstance(h, dict):
            continue
        h = dict(h)
        if str(h.get("status", "")).lower() == "refuted":
            against = h.get("against_evidence") or []
            cited = _cites(against, seen)
            legit_only = all(_LEGIT_ONLY.search(str(a)) for a in against) if against else True
            if not cited or legit_only:
                h["status"] = "unsupported"
                h["downgraded_from"] = "refuted"
                notes.append(f"{h.get('id', '?')}: refuted → unsupported "
                             f"({'no contradicting fo_id' if not cited else 'legitimacy is not a refutation'})")
        hyps.append(h)
    if hyps:
        c["hypotheses"] = hyps

    # Verdict gating.
    verdict = str(c.get("incident_confirmed") or "").lower()
    if verdict in ("yes", "no") and ctx.join_keys and not join_confirmed(ctx):
        c["leading_explanation"] = c.get("verdict")
        c["incident_confirmed"] = "inconclusive"
        notes.append(f'verdict "{verdict}" → inconclusive: the alert\'s action was not attributed through a join')

    # Unresolved discrepancies and entities surface as open questions.
    oq = [str(q) for q in c.get("open_questions") or []]
    for d in c.get("discrepancies") or []:
        if isinstance(d, dict) and not (d.get("resolved") and _cites(d, seen)):
            q = f"Discrepancy: {d.get('field', 'field')} — alert says {d.get('alert_value')}, evidence shows {d.get('evidence_value')}"
            if q not in oq:
                oq.append(q)
    for e in c.get("entities") or []:
        if isinstance(e, dict) and str(e.get("status")) == "unresolved":
            q = f"Unresolved {e.get('kind', 'entity')}: {e.get('value')}"
            if q not in oq:
                oq.append(q)
    if oq:
        c["open_questions"] = oq

    # Baseline ratios and flags.
    bl = []
    for b in c.get("baseline") or []:
        if isinstance(b, dict):
            b = dict(b)
            r = _ratio(b)
            if r is not None:
                b["ratio"] = round(r, 2)
                b["anomalous"] = r >= BASELINE_ANOMALY_RATIO
            bl.append(b)
    if bl:
        c["baseline"] = bl

    # IOCs: refang, de-duplicate, withhold damaged paths.
    clean, warnings = normalize_iocs(c.get("indicators") or [])
    c["indicators"] = clean
    if warnings:
        c["ioc_warnings"] = warnings

    # v1 derivations for existing consumers.
    if not c.get("evidence") and c.get("claims"):
        c["evidence"] = [
            f"[{cl.get('provenance', '?')}] {cl.get('text', '')}"
            + (f" (fo_id {', '.join(cl['fo_ids'])})" if cl.get("fo_ids") else "")
            for cl in c["claims"] if isinstance(cl, dict)
        ]
    if not c.get("next_steps") and c.get("next_actions"):
        c["next_steps"] = [_next_step_text(na) for na in c["next_actions"] if isinstance(na, dict)]

    c["checklist"] = checklist(c, ctx)
    c["validation"] = {"unmet": list(unmet or []), "adjustments": notes}
    return c


def _next_step_text(na: dict) -> str:
    if na.get("tool"):
        params = ", ".join(f"{k}={v}" for k, v in (na.get("params") or {}).items())
        head = f"{na['tool']}({params})"
    else:
        head = f"Ask {na.get('owner')}: {na.get('question')}"
    return head + (f" — resolves: {na['addresses']}" if na.get("addresses") else "")


def checklist(c: dict, ctx: Context) -> dict:
    entities = {str(e.get("value", "")).lower() for e in c.get("entities") or [] if isinstance(e, dict)}
    addressed = {str(x.get("id")) for x in c.get("case_context") or [] if isinstance(x, dict)}
    zero_steps = [s for s in ctx.transcript if s.get("action") == "search" and s.get("result_count") == 0]
    return {
        "join_keys_used": (not ctx.join_keys) or join_confirmed(ctx) or _did(ctx, "session_pivot"),
        "alert_entities_have_status": all(a.value.lower() in entities for a in ctx.alert_entities),
        "discrepancies_resolved_or_listed": all(
            str(e.get("value", "")).lower() in " ".join(map(str, c.get("discrepancies") or [])).lower()
            for e in c.get("entities") or [] if isinstance(e, dict) and e.get("status") == "contradicted"),
        "zero_hits_classified": all(s.get("coverage_note") or s.get("broadened") for s in zero_steps),
        "coverage_checked_for_absence": _did(ctx, "coverage_check") or any(s.get("coverage_note") for s in ctx.transcript),
        "case_context_addressed": all(str(d["id"]) in addressed for d in ctx.case_detections),
        "confidence_reconciled": ctx.prior_confidence is None or (
            c.get("prior_confidence") is not None and bool(str(c.get("confidence_rationale") or "").strip())),
        "iocs_normalized": True,
    }
