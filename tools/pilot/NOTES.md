# Pilot harness — working notes

Map of the autopilot harness as it stands, written before changing it, then
updated with what changed. Paths are relative to `tools/pilot/`.

## Where things live

| Concern | Location |
|---|---|
| System prompt | `pilot/service.py` `_AGENT_PROMPT` (~360 lines): action catalogue, conclude schema, tool playbook, field guide, discipline rules |
| Per-step prompt | `_agent_run` assembles `user_msg` each turn: `base_intro` (scenario, case context, evidence pack, field list) + `_render_ledger` + `_agent_step_history` (compact transcript) + focus/drift/stale nudges + anchors + review/supervisor note + "step N of M" |
| Tools | `AGENT_TOOLS` dict → `_tool_*` functions in `service.py`; skills (`ioc_sweep`, `host_profile`) in `pilot/skills.py` behind adapters |
| Query rewriting | `_normalize_agent_query` (field aliases, value-colon escaping), `_normalize_hash_terms`, `_widen_message_terms` (`message:*X*` also searches all fields), `escape_lucene_query` |
| Auto-broadening | `pilot/query_strategy.py` `broaden_ladder`; applied in `_agent_run` after a 0-hit search |
| What the model sees | `_agent_step_history`: per-action rendering (search: query, hits, profile; aggregate: buckets; inspect: identity fields + event_data) — the full tool result is stored in the transcript but only this rendering reaches the model |
| Loop / controller | `_agent_run`: supervisor (`pilot/supervisor.py`), stale/invalid/focus streak guards, duplicate cache (`query_cache`, `_CACHEABLE`), failure blocking (`failed_sigs`), unusable-reply handling, conclude branch (evidence regate → `_verify_conclusion` → review gate → hypothesis reconciliation), forced conclude on cap / LLM error |
| Conclusion | free JSON from the model (schema in the prompt). Post-processing: hypothesis reconciliation, `verification` from the reviewer, `calibration` from the memory hook after the run. Confidence is the model's number, adjusted only by the reviewer's `adjusted_confidence` |
| Alert parsing | none before this work: the scenario is free text (`_sanitize_scenario` only defangs fences/role tags). `pilot/anchors.py` (added) extracts observables |
| Consumers of the run doc | `frontend/src/components/CaseAiPanel.jsx` (incident_confirmed enum, verdict, hypotheses[].status/for_evidence/against_evidence strings, evidence/indicators/next_steps string lists, confidence number), `_polish_report`, `api/routers/reports.py`, `ai_agent_promote_iocs` (indicators strings) |
| Tests | `api/routers/test_pilot_*.py` (loop, tools, budget, provenance), `tools/pilot/tests/*` (skills, supervisor, query strategy, scorer) |
| Evals | `eval/`: YAML scenarios (seed docs + rubric), `scoring.py` (pure), `pilot_eval.py` (seed ES + drive the live agent over HTTP, save/replay) |

## Data model facts that constrain the design

- Windows logons are `evtx` docs: `evtx.event_id`, `evtx.event_data.{TargetUserName,TargetLogonId,IpAddress,IpPort,WorkstationName,LogonType,SubjectLogonId}`, mirrored into `user.name`, `network.src_ip`, `network.src_port`, `network.workstation`. Port and logon ID are ingested, so a port → session → activity join is possible.
- `evtx.record_id` and `evtx.channel` are present: record-number gaps per channel are computable.
- Audit policy is not parsed: `registry_hive` docs are one summary per hive file, not values, so `PolAdtEv` is never visible. The coverage tool looks for `auditpol` output collected as text and otherwise says "audit policy not collected" instead of guessing.
- Prior detections: `artifact_type: detection` (rule name, level, match_count, timestamp = when the sweep ran, not when it matched), `finding` and `hayabusa` (per-event, with `timestamp` of the matched event and a level). Only the latter two can be correlated in time.
- EDR session IDs: no EDR telemetry type in the data model. The session pivot covers Windows logon IDs only; the gap is reported at runtime.
- The reference case's corrupted path (`C:Windows estIs…`) arrived already corrupted in the pasted alert text; Citadel performs no escape decoding. Round-trip is pinned by tests; damaged paths are flagged, not "repaired".

## Changes (see PLAN.md for the mapping to failure classes)

_Filled in as commits land._
