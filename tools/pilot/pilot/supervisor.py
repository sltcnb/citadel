"""Run control for the Pilot agent — direction, hypothesis lifecycle, stopping.

The agent currently grades its own homework. It decides which hypothesis is
still worth pursuing, when a line of inquiry is dead, and when it has enough to
conclude. A run that went 40 steps hunting artifacts that were never collected,
and then self-certified "inconclusive" at 40% confidence, is what that looks
like: nothing in the loop was empowered to say *stop, this cannot be answered,
report the gap instead.*

The existing guards are all loop detection — "are you repeating yourself". That
is a different question from "is this line of inquiry still productive", and it
cannot answer it: an agent issuing genuinely varied queries against evidence
that does not exist never repeats itself and never trips them.

This module supervises. It is deliberately split in two:

  Tier 1 (here, :func:`assess`) is deterministic, free, and runs every step. It
  reads the transcript for evidence progress, hypothesis coverage and lens
  coverage, and issues a directive. Most control decisions need no judgment at
  all — a case whose every domain lens is blocked is unanswerable at step 1, and
  saying so does not require a model.

  Tier 2 is an LLM adjudicator, invoked ONLY when tier 1 returns
  ``needs_judgment``. Keeping it behind a deterministic gate is what stops a
  supervisor from doubling the cost of every run.

Pure functions over the transcript: no Elasticsearch, no LLM, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# A step that fetched events and surfaced at least one fo_id nobody had seen
# before is the only thing that counts as progress. Everything else — a zero-hit
# search, a rejected query, a re-read of the same population — is motion.
_FETCH_ACTIONS = frozenset(
    {
        "search",
        "aggregate",
        "time_window",
        "correlate",
        "mitre_hits",
        "inspect",
        "entity_graph",
        "stack_rare",
        "ioc_sweep",
        "host_profile",
        "read_module_result",
        "findings",
        "detection_rules",
        "watchlist",
        "cti_seen_before",
    }
)

# Directive kinds.
CONTINUE = "continue"
REDIRECT = "redirect"
CLOSE_HYPOTHESIS = "close_hypothesis"
CONCLUDE = "conclude"
NEEDS_JUDGMENT = "needs_judgment"


@dataclass
class Directive:
    """What the supervisor tells the run to do next."""

    action: str
    reason: str
    target: str | None = None
    guidance: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.action == CONCLUDE

    def as_prompt(self) -> str:
        """Text injected into the agent's next turn. Empty when nothing to say."""
        if self.action == CONTINUE:
            return ""
        head = {
            REDIRECT: "SUPERVISOR — REDIRECT",
            CLOSE_HYPOTHESIS: "SUPERVISOR — CLOSE HYPOTHESIS",
            CONCLUDE: "SUPERVISOR — CONCLUDE NOW",
            NEEDS_JUDGMENT: "SUPERVISOR — REVIEW",
        }[self.action]
        return f"\n{head}: {self.reason}\n{self.guidance}\n"


@dataclass
class Progress:
    """What the transcript says has actually been established."""

    steps: int = 0
    fetches: int = 0
    productive_steps: list[int] = field(default_factory=list)
    evidence_ids: set[str] = field(default_factory=set)
    idle_steps: int = 0
    lenses_touched: set[str] = field(default_factory=set)

    @property
    def last_advance(self) -> int:
        return self.productive_steps[-1] if self.productive_steps else 0


def measure(transcript: list[dict]) -> Progress:
    """Reduce a transcript to the few signals control actually needs.

    Progress is *new* evidence, not activity. An agent can issue thirty
    well-formed, non-repeating queries that all return the same population, or
    nothing at all, and be no closer to an answer than at step one.
    """
    p = Progress()
    seen: set[str] = set()
    for i, step in enumerate(transcript, start=1):
        p.steps = i
        action = step.get("action") or ""
        if action not in _FETCH_ACTIONS:
            continue
        p.fetches += 1
        if step.get("query_status") != "ok":
            continue
        ids = [x for x in (step.get("sample_ids") or []) if x]
        fresh = [x for x in ids if x not in seen]
        # A tool that establishes something without returning event ids
        # (ioc_sweep with matches, host_profile on a real host) still counts.
        counted = bool(fresh) or (
            not ids and (step.get("result_count") or step.get("matched") or 0) > 0
        )
        if counted:
            p.productive_steps.append(i)
            seen.update(fresh)
        for t in _lenses_in_step(step):
            p.lenses_touched.add(t)
    p.evidence_ids = seen
    p.idle_steps = p.steps - p.last_advance if p.steps else 0
    return p


# Which specialist lens a step was probing, inferred from the artifact types it
# constrained on. Approximate by design — it drives a nudge, not a hard gate.
_LENS_TYPES: dict[str, frozenset[str]] = {
    "execution": frozenset(
        {"process", "evtx", "prefetch", "hayabusa", "shell_history", "auditd"}
    ),
    "persistence": frozenset(
        {
            "persistence",
            "registry",
            "scheduled_task",
            "service",
            "plist",
            "cron_job",
            "startup_item",
        }
    ),
    "network": frozenset(
        {"network_conn", "pcap", "zeek", "suricata", "access_log", "firewall_log", "browser"}
    ),
    "identity": frozenset(
        {"login_event", "logged_user", "auth_log", "utmp", "lastlog", "user_account"}
    ),
    "malware": frozenset({"yara", "antivirus", "module_finding", "cti_match", "file"}),
}


def _lenses_in_step(step: dict) -> set[str]:
    blob = " ".join(
        str(step.get(k) or "") for k in ("query", "agg_query", "agg_field", "action")
    ).lower()
    out = set()
    for lens, types in _LENS_TYPES.items():
        if any(t in blob for t in types):
            out.add(lens)
    return out


def hypothesis_states(transcript: list[dict], progress: Progress) -> list[dict]:
    """Per-hypothesis lifecycle, derived from the transcript.

    A hypothesis is *stalled* when nothing has advanced since it was declared
    and the run has kept working. Stalled is not refuted — it means the run is
    spending budget without moving, which is the moment to redirect or close it
    rather than the moment to keep going.
    """
    declared: list[dict] = []
    declared_at = 0
    for i, step in enumerate(transcript, start=1):
        if step.get("action") == "set_hypotheses" and step.get("hypotheses"):
            declared = step["hypotheses"]
            declared_at = i

    if not declared:
        return []

    advances_since = [s for s in progress.productive_steps if s > declared_at]
    out = []
    for h in declared:
        if not isinstance(h, dict):
            continue
        hid = str(h.get("id") or "")
        # Evidence explicitly tied to this hypothesis: a saved finding naming
        # it, or a step that declared which hypothesis it was testing.
        tied = sum(
            1
            for s in transcript
            if str(s.get("hypothesis") or "") == hid and s.get("query_status") == "ok"
        )
        out.append(
            {
                "id": hid,
                "claim": h.get("claim") or "",
                "tied_steps": tied,
                "advances_since_declared": len(advances_since),
                "status": "open" if (tied or advances_since) else "untested",
            }
        )
    return out


def assess(
    transcript: list[dict],
    *,
    step_no: int,
    max_steps: int,
    plan_answerable: bool = True,
    viable_lenses: list[str] | None = None,
    idle_limit: int = 6,
    min_steps_before_stop: int = 4,
) -> Directive:
    """Decide what the run should do next.

    ``plan_answerable`` comes from the specialist plan: False means no domain
    lens has the artifact types it needs, so no amount of searching can settle
    the question. That is the single most valuable thing this function knows,
    and it knows it before the first query.
    """
    progress = measure(transcript)
    viable = [x for x in (viable_lenses or []) if x != "timeline"]

    # 1. Unanswerable by construction. The run that motivated this module spent
    #    its entire budget here. Let it establish what IS present first — a few
    #    steps — then stop it.
    if not plan_answerable and step_no > min_steps_before_stop:
        return Directive(
            action=CONCLUDE,
            reason=(
                "no domain lens is viable on this case — the question cannot be "
                "settled from the data present"
            ),
            guidance=(
                "Conclude NOW with the collection gap as the finding. State which "
                "artifact types would be needed and are absent. Do NOT report the "
                "absence of those artifacts as evidence that nothing happened, and "
                "do NOT spend further steps searching for them."
            ),
        )

    # 2. Budget. Past the ceiling there is no decision left to make.
    if step_no >= max_steps:
        return Directive(
            action=CONCLUDE,
            reason=f"step budget exhausted ({step_no}/{max_steps})",
            guidance=(
                "Conclude with what is established and mark every unresolved "
                "hypothesis untested."
            ),
        )

    # 3. Nothing has moved for a while. This is the case the loop detectors
    #    miss: varied, well-formed, non-repeating queries against evidence that
    #    is not there never trip a repetition guard.
    if progress.idle_steps >= idle_limit and step_no > min_steps_before_stop:
        untouched = [x for x in viable if x not in progress.lenses_touched]
        if untouched:
            return Directive(
                action=REDIRECT,
                reason=(
                    f"{progress.idle_steps} steps with no new evidence, and "
                    f"{len(untouched)} viable lens(es) never probed"
                ),
                target=untouched[0],
                guidance=(
                    f"Stop the current line. Probe the {untouched[0]} lens instead — "
                    f"it has the artifact types this case holds and has not been "
                    f"queried. Untouched: {', '.join(untouched)}."
                ),
            )
        return Directive(
            action=NEEDS_JUDGMENT,
            reason=(
                f"{progress.idle_steps} steps with no new evidence and every viable "
                "lens already probed"
            ),
            guidance=(
                "Either you have enough to conclude, or the remaining questions "
                "cannot be answered from this data. Decide which, and say so "
                "explicitly — do not keep searching."
            ),
        )

    # 4. Approaching the ceiling with nothing recent. Stop before the cap so the
    #    conclusion is written deliberately rather than truncated.
    near_cap = step_no >= max(min_steps_before_stop + 1, int(max_steps * 0.8))
    if near_cap and progress.idle_steps >= 3:
        return Directive(
            action=CONCLUDE,
            reason=f"at {step_no}/{max_steps} steps with no new evidence for {progress.idle_steps}",
            guidance="Conclude now, while there is budget to write it properly.",
        )

    return Directive(action=CONTINUE, reason="run is still producing evidence")


def summarise(transcript: list[dict], directive: Directive) -> dict:
    """Compact control state, for the run record and the UI."""
    p = measure(transcript)
    return {
        "steps": p.steps,
        "fetches": p.fetches,
        "productive_steps": len(p.productive_steps),
        "evidence_seen": len(p.evidence_ids),
        "idle_steps": p.idle_steps,
        "lenses_touched": sorted(p.lenses_touched),
        "directive": directive.action,
        "reason": directive.reason,
    }
