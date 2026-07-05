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

## Contracts

| Direction | Contract | Schema |
|---|---|---|
| Consumes | ForensicEvent v1 (`application/x-ndjson` — an ES index or a Citadel case) | `https://citadel.dfir/contracts/forensic_event/v1.json` |
| Produces | ForensicEvent v1, `artifact_type: investigation_report` | `https://citadel.dfir/contracts/forensic_event/v1.json` |

Contracts are versioned in [citadel-contracts](https://github.com/sltcnb/citadel-contracts)
(Python package `citadel_contracts` — Pilot imports `Finding` and `logship` from it).

## Install

Normally installed into the Citadel API image. Standalone clone:

```bash
git clone https://github.com/sltcnb/citadel-pilot && cd citadel-pilot
pip install git+https://github.com/sltcnb/citadel-contracts   # citadel_contracts
pip install -e .
```

`pyproject.toml` declares no runtime dependencies on purpose: fastapi, redis, the
ES client and the platform modules (`config`, `redis_keys`) are provided by the
API app on `PYTHONPATH=/app`. Pilot does not run against a bare filesystem —
it needs that platform context.

## Configuration

No environment variables — verified: no `os.environ`/`getenv` in the package.
Pilot is configured at runtime through the platform (Settings → AI Analysis):
provider, model and LLM API key are stored as a JSON blob in Redis (the
`LLM_CONFIG` key from `redis_keys`) and read back by `pilot/service.py` on each
call. The API key is entered by the user in the UI, never taken from the
environment.

## Run / health

```bash
pilot --version            # health check (from brick.yaml)
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

## Part of the Citadel suite
Pilot sits near the end of the pipeline, reasoning over normalized/detected data.
Upstream/runtime dependencies (per `brick.yaml`): Elasticsearch,
[Sluice](https://github.com/sltcnb/sluice), [Sigil](https://github.com/sltcnb/sigil),
[Anvil](https://github.com/sltcnb/anvil), [Augur](https://github.com/sltcnb/augur).
Downstream: [Scribe](https://github.com/sltcnb/citadel-report) renders its investigation
report. Platform: [citadel](https://github.com/sltcnb/citadel) · Contracts:
[citadel-contracts](https://github.com/sltcnb/citadel-contracts).
