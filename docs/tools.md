# Tool Suite

The Citadel suite is 14 standalone tools. Each has its own repository, CLI, and `brick.yaml`; Citadel pins each at a tested version and composes them over the shared [contracts](contracts.md).

**Status legend** — built · partial · planned (from `tools/SUITE.yaml`).

| Tool | Role | Standalone CLI example | Status |
|------|------|------------------------|--------|
| **Talon** | Acquisition agent | `talon collect --host workstation01 --out bundle/` | built |
| **Sluice** | Intake & routing | `sluice ingest bundle/ --route` | built |
| **Babel** | Parser library (43 parsers) | `babel parse evtx Security.evtx > events.jsonl` | built |
| **Rosetta** | Canonicalizer (ECS v8 + OSSEM) | `rosetta normalize events.jsonl > ecs.jsonl` | planned |
| **Sigil** | Detection engine (Sigma + YARA) | `sigil match --rules sigma/ ecs.jsonl` | partial |
| **Anvil** | Analysis runner (12+ analyzers) | `anvil run volatility --image mem.raw` | built |
| **Augur** | Intel enrichment | `augur enrich --ioc 1.2.3.4 --out stix.json` | partial |
| **Pilot** | Investigation agent (LLM) | `pilot investigate --case CASE-001` | built |
| **Scribe** | Report engine | `scribe render --case CASE-001 --format pdf` | partial |
| **Wraith** | Memory forensics | `wraith analyze mem.raw` | planned |
| **Wiretap** | Network threat detection | `wiretap hunt capture.pcap` | planned |
| **Nimbus** | Cloud forensics | `nimbus collect aws --read-only --out bundle/` | planned |
| **Warden** | Identity & attack-path audit | `warden audit okta --graph paths.json` | planned |
| **Citadel** | Platform / integrator | `citadel up --profile full` | built |

## Notes per tool

- **Talon** — collects host/disk/cloud artifacts into an artifact bundle. Maps to the current `collector/` directory.
- **Sluice** — detects, dedups, routes, and parses anything; emits to the bus. Maps to `ingester/` + `processor/`.
- **Babel** — parses any artifact into a normalized `ForensicEvent` stream (43 parsers today). Maps to `plugins/`.
- **Rosetta** — normalizes any event stream to ECS v8 + OSSEM. *New tool*; the mapping lives in parsers/processor today.
- **Sigil** — matches Sigma + YARA against an event stream. Maps to `tools/sigil/`.
- **Anvil** — runs sandboxed deep analyzers (Volatility/Hayabusa/…). Maps to `modules/`.
- **Augur** — enriches IOCs (MISP/VT/OTX/…) into STIX. *New tool*; intel bits live in `api/routers/` today.
- **Pilot** — an LLM agent that investigates a case/index. Maps to the `api` LLM layer.
- **Scribe** — renders a case to HTML/PDF/STIX/MISP. Maps to `api/routers/reports.py` + `export.py`.
- **Wraith** — push-button memory-image analysis. *New tool* (Volatility runs via Anvil today).
- **Wiretap** — hunts C2/beacon/DNS-tunnel/lateral movement in PCAP. *New tool* (pcap/zeek via Babel today).
- **Nimbus** — read-only AWS/Azure/GCP collection + posture detections. *New tool*.
- **Warden** — audits 7 IdPs and builds a cross-provider attack-path graph. *New tool*.
- **Citadel** — provides cases, timeline, search, multi-tenancy, and the console; composes the suite. Maps to `api/` + `frontend/`.
