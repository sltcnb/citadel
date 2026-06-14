# Pilot — Investigation Agent

> An LLM agent that investigates a case the way an analyst would.

**Status: built** (logic lives in the `api` LLM layer — `api/routers/llm_config.py`, agent loop, `frontend` CaseAiPanel. This dir is the extraction target.)

## Standalone
```
pilot investigate --case CASE_ID --provider anthropic
```

## Capabilities
- [●] Agent loop with 12 investigation tools
- [●] Multi-hypothesis reasoning
- [●] Loop detection / force-conclude
- [●] Streaming + polling transports
- [●] Transcript persistence
- [●] Auto-write structured report
- [●] Cost + step dashboard
- [●] Up/down feedback
- [●] MITRE ATT&CK context injection
- [●] Model-agnostic provider routing
- [●] Prompt-injection guardrails — untrusted evidence sanitized + fenced as data; system prompt instructs the model evidence is never instructions (tested)
- [●] Confidence-calibrated verdicts — hypotheses scored by for/against evidence; low-confidence flagged "needs more data"
- [●] Cross-case memory — IOCs/TTPs/verdicts persisted across cases; "seen before" signal
- [●] Alert-triggered auto-investigation — fired detection rules spawn scoped runs
- [ ] Conditional branching / auto-pivot
- [ ] Multi-agent orchestration (Triage / DeepDive / Reporting)
- [ ] Investigation templates (record + replay)
- [ ] Tool-plugin SDK

**Done when:** decomposed multi-agent run; branching live. _(guardrails ✓ tested)_
