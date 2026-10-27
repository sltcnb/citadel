# Pilot harness — plan

Failure classes (from the reference review) → change → enforcement point → test.
"Controller" = `_agent_run`; "schema" = conclusion schema v2 + `pilot/conclusion.py`.

| # | Failure class | Change | Enforced in | Test |
|---|---|---|---|---|
| 1 | Attribution by time proximity | `session_pivot` tool: IP+port or logon ID → the 4624/4625, its TargetLogonId, every event sharing the logon ID. Join keys (port, logon ID, PID, session/correlation ID) extracted from the alert as anchors; untested anchors block conclude | tool + controller | unit (pivot query/shape), loop (anchor gate), eval |
| 2 | Discrepancy dropped | Entity attribution ledger (`entities[]`: confirmed / contradicted / unresolved + fo_ids) required for every alert entity; `discrepancies[]` required for each contradicted entity; contradicted-unresolved items surface in `open_questions` | schema + controller | validator accept/reject |
| 3 | Legit infra = exculpatory | Hypothesis semantics: `refuted` requires contradicting fo_ids and is downgraded to `unsupported` when its against-evidence is only legitimacy / valid-credential claims or carries no fo_id | schema (deterministic downgrade) | validator |
| 4 | Case context ignored | Controller injects prior detections within ±T (default 24 h, pilot setting) of the alert time; `case_context[]` must give each one related / unrelated(reason) / unchecked | controller + schema | validator, eval |
| 5 | Absence misread | `coverage_check` tool (event IDs/channels present, record-ID gaps, 1102/104, audit policy if collected); 0-hit searches carry host/window coverage; absence claims must cite a coverage result | tool + schema | unit, validator |
| 6 | Baseline contradicted | Search profile flags ≥3× spikes and one-off hours (done); `baseline[]` entries required when the verdict calls something routine/baseline, with alert value, baseline value and ratio; ratio > threshold flagged `anomalous` | schema | validator |
| 7 | One sample generalised | Inspect of 1 of N hits says so and names discriminating fields to aggregate; profile shows caller process (done); quantified claims ("all", "every") need an aggregate step or ≥3 inspected fo_ids | tool + schema | unit, validator |
| 8 | Silent broadening | Zero stays the answer; broader query is a flagged suggestion with `filters_dropped`; rungs dropping time/event-ID filters never run (done); controller counts broadened results the model cites | tool + controller | unit |
| 9 | Waste | Normalised dedup (whitespace/case/operator), duplicates counted and warned; empty steps rejected; back-to-back `findings` without new evidence rejected; reasoning language enforced (CJK in an en/fr run → re-ask) | controller | loop tests |
| 10 | Confidence not recomputed | `prior_confidence` parsed from the alert; conclude must state prior, new and drivers; equal-to-prior while claiming resolved unknowns / refuted hypotheses → rejected | schema + controller | validator |
| 11 | IOC corruption | Round-trip tests (\t \n \r \\ UNC) through sanitisation, anchors and storage; IOC normaliser flags paths with control characters or a missing separator after the drive (`C:Windows`) instead of emitting them | ingestion + schema | unit |
| 12 | Analyst claims laundered | `claims[]` with provenance collected(fo_id) / alert / analyst / inference; collected claims must cite fo_ids seen in this run; analyst claims stay labelled | schema | validator |
| 13 | Generic next steps | `next_actions[]`: each is {tool, params} or {owner, question} and names the open question / entity it resolves | schema | validator |
| — | Verdict gating | benign ("no") / malicious ("yes") require a confirmed join on the alert's action; otherwise forced to "inconclusive" with the leading explanation kept | schema (deterministic) | validator |

## Conclusion schema v2

Additive. v1 fields (`incident_confirmed`, `verdict`, `evidence[]`, `indicators[]`,
`next_steps[]`, `hypotheses[].for_evidence/against_evidence` strings, `confidence`)
stay and are derived from v2 fields when the model omits them, so the UI, report
polish, reports router and IOC promotion keep working. New: `schema_version: 2`,
`entities`, `discrepancies`, `open_questions`, `claims`, `case_context`,
`baseline`, `prior_confidence`, `confidence_rationale`, `next_actions`,
`checklist` (computed), `validation` (computed). Runs stored before v2 have no
`schema_version` and are read as v1.

## Validation flow

`pilot/conclusion.py` holds pure functions: `validate(conclusion, ctx) → issues`
and `finalize(conclusion, ctx) → conclusion` (deterministic downgrades + legacy
field derivation + checklist). The controller sends a conclusion back with the
issues as the next turn's instruction (bounded); after the bound, `finalize`
applies the downgrades and records the unmet checks in `validation`.

## Prompt

Replace the accumulated discipline bullets that the controller now enforces with
a short rules block (join, legit-is-a-pivot, absence-needs-coverage, provenance,
calibrated confidence). Rejection messages carry the detail.

## Evaluation

Extend `eval/`: five scenarios (reference-equivalent, synthetic and anonymised,
plus counter-fixtures a–d), rubric fields for attribution, discrepancy, refuted
justification, case context, exact IOC strings and calibration; an in-process
runner mode for running inside the API container (no session token). Before =
the harness at the commit preceding this plan; after = HEAD.

## Commits

1. eval: scenarios + scorer metrics + in-process runner (baseline first)
2. ingestion: escape round-trip tests, join-key anchors, IOC normaliser (#11)
3. tools: dedup normalisation, broadening suggestion, zero-hit coverage, inspect 1-of-N (#7 #8 #9 #5)
4. tools: session_pivot + coverage_check (#1 #5)
5. schema v2 + validator + controller gates (#1–#4 #6 #10 #12 #13, verdict gating)
6. controller hygiene: findings back-to-back, reasoning language (#9)
7. prompt: rules block, remove superseded bullets
8. docs: NOTES.md results + limitations
