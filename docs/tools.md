# Tool Suite

The Citadel suite is 10 standalone tools. Each has its own directory under `tools/`, CLI, and `brick.yaml`; Citadel composes them over the shared [contracts](contracts.md).

| Tool | Role | Standalone CLI example |
|------|------|------------------------|
| **Talon** | Acquisition agent | `talon collect --host workstation01 --out bundle/` |
| **Sluice** | Intake & routing | `sluice ingest bundle/ --route` |
| **Babel** | Parser library (43 parsers) | `babel parse evtx Security.evtx > events.jsonl` |
| **Rosetta** | Canonicalizer (ECS v8 + OSSEM, GeoIP/ASN/rDNS) | `rosetta normalize events.jsonl > ecs.jsonl` |
| **Sigil** | Detection engine (Sigma + YARA) | `sigil match --rules sigma/ ecs.jsonl` |
| **Anvil** | Analysis runner (12+ analyzers) | `anvil run volatility --image mem.raw` |
| **Augur** | Intel enrichment | `augur enrich --ioc 1.2.3.4 --out stix.json` |
| **Pilot** | Investigation agent (LLM) | `pilot investigate --case CASE-001` |
| **Scribe** | Report engine | `scribe render --case CASE-001 --format pdf` |
| **Citadel** | Platform / integrator | `citadel up --profile full` |

## Notes per tool

- **Talon** — collects host/disk artifacts into an artifact bundle. Lives in `tools/talon/`.
- **Sluice** — detects, dedups, routes, and parses anything; emits to the bus. `tools/sluice/` + `tools/sluice-worker/`.
- **Babel** — parses any artifact into a normalized `ForensicEvent` stream (43 parsers). `tools/babel/`.
- **Rosetta** — normalizes any event stream to ECS v8 + OSSEM and enriches IPs (GeoIP/ASN/rDNS). `tools/rosetta/`.
- **Sigil** — matches Sigma + YARA against an event stream. `tools/sigil/`.
- **Anvil** — runs sandboxed deep analyzers (Volatility/Hayabusa/…). `tools/anvil/`.
- **Augur** — enriches IOCs (MISP/VT/OTX/…) into STIX. `tools/augur/`; the platform's live intel runs in `api/routers/cti.py`.
- **Pilot** — an LLM agent that investigates a case/index. `tools/pilot/`; logic in the `api` LLM layer.
- **Scribe** — renders a case to HTML/PDF/STIX/MISP. `tools/scribe/`; logic in `api/routers/reports.py` + `export.py`.
- **Citadel** — provides cases, timeline, search, multi-tenancy, and the console; composes the suite. `api/` + `frontend/`.
