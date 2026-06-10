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
- [ ] Conditional branching / auto-pivot
- [ ] Multi-agent orchestration (Triage / DeepDive / Reporting)
- [ ] Investigation templates (record + replay)
- [ ] Tool-plugin SDK
- [ ] Prompt-injection / tool-abuse guardrails

**Done when:** decomposed multi-agent run; branching live; guardrails tested.
