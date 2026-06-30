# Pilot — Investigation Agent

> An LLM agent that investigates a case the way an analyst would.

**Status: active** — the engine lives HERE (`pilot/service.py`): LLM client, agent
loop, the investigation tools, prompts, ledger/sample/whitelist/auto-launch
helpers, loop guards, and the run lifecycle. It's pip-installed into the API
image; `api/routers/llm_config.py` is a thin re-export shim so existing routes
and imports keep working. The agent reaches Elasticsearch/Redis/modules through
the API app on `PYTHONPATH=/app` (same model as the other in-image tools).

(Still in `api/routers/` for now, as they're thin HTTP layers: `pilot_settings.py`,
`pilot_memory.py`. Frontend: `CaseAiPanel.jsx`.)

## Pipeline position

```
timeline / detections / findings ──▶ Pilot (LLM agent loop) ──▶ structured investigation report
```

Pilot reasons over a finished case the way an analyst would, driving the other tools mid-investigation.

- **Inputs** — a Citadel case or an ES index (the normalized timeline, detections, module findings, intel).
- **Outputs** — an autonomous, structured investigation report + findings (`artifact_type: investigation_report`), with cost/step accounting.
- **Dependencies** — Elasticsearch, Sluice, Sigil, Anvil, Augur; an LLM provider (Anthropic / OpenAI / Ollama / OpenRouter).

## Run / use

```bash
pilot --version            # health check
pilot investigate --case ID
```

Model-agnostic provider routing; prompt-injection guardrails fence untrusted evidence as data.

## Capabilities
- [●] Agent loop with 17 investigation tools
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
