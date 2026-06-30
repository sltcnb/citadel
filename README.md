<div align="center">

<img src="frontend/public/logo.svg" alt="Citadel" height="64">

# Citadel

**A DFIR platform built from independent, standalone tools — each useful on its own, all composed by Citadel.**

[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-orange.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![React 18](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![Elasticsearch 8](https://img.shields.io/badge/Elasticsearch-8-005571.svg)](https://www.elastic.co/)
[![Helm](https://img.shields.io/badge/Helm-chart-0F1689.svg)](charts/citadel)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)

</div>

Citadel takes a forensic artifact from acquisition to a finished, searchable, detection-rich case — acquire → ingest → parse → normalize → detect → analyze → enrich → investigate → report. Every stage is a **standalone tool** with its own CLI; the platform wires them together over **shared contracts**.

```
Talon ─▶ Sluice ─▶ Babel ─▶ Rosetta ─▶ ┬─▶ store (timeline · search)
 acquire   route    parse    →ECS       ├─▶ Sigil   (detections)
                                        ├─▶ Anvil   (analyzers)
                                        └─▶ Augur   (intel)
                          Pilot drives the tools · Scribe writes the report
```

---

## Install

```bash
git clone https://github.com/sltcnb/citadel.git && cd citadel
./foctl deploy docker     # single host · or: deploy helm · deploy k8s
```
Open **http://localhost** — default login `admin` / `CitadelAdmin1!` (change immediately).

**Full guide → [docs/installation.md](docs/installation.md)** (Docker Compose · Helm/bring-your-own-substrate · Kubernetes · ingress for Traefik/Tailscale · resource sizing).

---

## The tool suite

Each tool is its own repo (`tools/<name>`), its own CLI, its own `brick.yaml`. Run one alone, or adopt the platform. Full index: [`tools/README.md`](tools/README.md) · [`tools/SUITE.yaml`](tools/SUITE.yaml).

| Tool | Role | Input → Output | Standalone CLI |
|------|------|----------------|----------------|
| **Talon** | Acquisition agent | host/disk/cloud → artifact bundle | `talon collect --out case.bundle` |
| **Sluice** | Intake & routing | bundle/file/dir → routed events (+ bus) | `sluice ingest case.bundle` |
| **Babel** | Parser library (44) | artifact → `ForensicEvent` | `babel parse Security.evtx` |
| **Rosetta** | Canonicalizer | `ForensicEvent` → ECS v8 + OSSEM (+ GeoIP/ASN/rDNS) | `rosetta normalize ev.jsonl` |
| **Sigil** | Detection engine | ECS + rules → detections | `sigil validate ./rules/` |
| **Anvil** | Analysis runner | artifact + module → findings | `anvil run volatility3 -a mem.raw` |
| **Augur** | Intel enrichment | IOCs → scored STIX / MISP | `augur enrich iocs.json` |
| **Pilot** | Investigation agent | case → autonomous report (LLM) | `pilot investigate --case ID` |
| **Scribe** | Report engine | case → HTML/PDF/STIX/MISP | `scribe report --case ID -f pdf` |
| **Citadel** | Platform / integrator | cases · timeline · search · console | `docker compose --profile full up` |

### Self-describing tools

Each tool ships a `capabilities.yaml` declaring, per platform, what it can do and the inputs each operation needs. Citadel **renders the UI from that declaration** — forms, options, validation — then routes the user's input to the tool and the tool's output back. Edit a tool's `capabilities.yaml` (e.g. add a Talon collection feature) and the Citadel UI changes with **no orchestrator code change**; `foctl deploy` self-registers the manifest into Redis (`fo:capabilities:<tool>`), so a tool-only change needs **no API rebuild**. Custom parsers (Studio) and custom modules (Anvil registry) are folded in **live** — they appear without editing any manifest. See [docs/contracts.md → Capability advertisement](docs/contracts.md#capability-advertisement).

---

## Features

| Area | What |
|------|------|
| **Acquisition** | Talon live + dead-box collection (Windows/Linux/macOS/server); in-app **Harvest** (server-side Talon collection from a mounted disk image / path); resumable encrypted upload; gRPC remote agent (mTLS) |
| **Ingestion** | 44 parsers, 80+ forensic formats auto-detected (EVTX, MFT, Registry, Prefetch, LNK, PCAP, Plaso, syslog, Zeek, Suricata, browsers, Android/iOS, disk images) |
| **Detection** | 1 666 built-in rules (1 487 Sigma across 13 ATT&CK tactics + 179 native ES queries); Sigma→ES conversion; ATT&CK coverage matrix; SigmaHQ import; runtime Sigma opt-out (global + per-case) |
| **Analysis** | Hayabusa, RegRipper, YARA, Volatility3, capa/FLOSS, oletools, PE/strings, CTI IOC matching — typed `BaseModule` + DAG pipelines |
| **Search** | Elasticsearch full-text + facets, saved queries, timeline, CSV export, cross-case search |
| **Normalize** | `ForensicEvent → ECS v8` + OSSEM ATT&CK; GeoIP / ASN / reverse-DNS enrichment of IP fields |
| **Investigate** | Alert-triggered auto-investigation · entity graph (host↔user↔IP lateral movement) · baseline / rare-artifact stacking · reverse kill-chain assembly · cross-case Pilot memory · continuous co-pilot watch · editable investigation templates |
| **AI assist** | LLM providers (Anthropic, OpenAI, Ollama, OpenRouter) for the Pilot agent — which can drive entity-graph / rare-artifact stacking / cross-case-memory tools mid-investigation — rule generation, summaries; cost tracking; **prompt-injection guardrails** (untrusted evidence sanitized + fenced as data) and **confidence-calibrated verdicts** |
| **Threat intel** | STIX/TAXII, MISP, YETI, OTX/URLhaus/AbuseIPDB/Shodan/GreyNoise enrichment; SSRF-guarded feed fetches (per-feed TLS-verify opt-out for internal/self-signed servers) |
| **Authentication** | JWT (short-lived SSE stream tokens) · MFA/TOTP · **SSO via Google & Microsoft OIDC** (auto-provisioning, domain allowlist) · forced password rotation off defaults · login rate-limiting |
| **Authorization (RBAC)** | Granular permissions + role presets (admin/analyst/developer/guest) · **groups** (roles + permissions + company scope + members) · per-user direct permissions · per-company multi-tenant isolation (IDOR-guarded) · tiered licensing |
| **Evidence integrity** | Tamper-evident, hash-chained **audit log** + signed **chain-of-custody** manifests (court-ready, HMAC-signable); BitLocker keys redacted from API |
| **Observability** | structured JSON logs, Prometheus `/metrics`, `/healthz`/`/readyz`, admin log viewer, persistent audit trail |

---


## Architecture

- **Standalone-first / contract-first** — tools never import each other; they exchange `ForensicEvent → ECS`, artifact bundles, and `brick.yaml` manifests. Contracts live in [`contracts/`](contracts/) + the pip-installable [`citadel_contracts`](tools/citadel_contracts) package.
- **Transport per edge**: Redis Streams for the pipeline data-plane · gRPC + S3/MinIO for the Talon remote agent (mTLS) · in-process via `citadel_contracts` for the hot Sluice→Babel path.
- **Stateless compute, stateful substrate** — state lives in Elasticsearch, MinIO, Redis; workers scale on queue depth.

| Component | Tech |
|-----------|------|
| Frontend | React 18 + Vite + Tailwind (nginx) |
| API | FastAPI / Python 3.11 (Uvicorn) |
| Workers | Celery (ingest + modules queues) |
| Search | Elasticsearch 8 |
| Broker/state | Redis 7 |
| Artifacts | MinIO (S3) |
| Ingress | Traefik (TLS, host routing) |

---

## Develop & test

```bash
./scripts/run_tests.sh         # 16 suites + Babel→Rosetta→Sigil integration (stdlib-only gate)
```
Add a parser or a tool: [docs → Contributing](docs/contributing.md). CI (`.github/workflows/`) runs lint, the test gate, multi-arch image builds + Trivy/SBOM, and `mkdocs build --strict`.

Full documentation site (`mkdocs serve`): [`docs/`](docs/) — Installation · Getting Started · Architecture · Operations · Testing · Contributing.

---

## Licensing

**Source-available, noncommercial.** Source is licensed under the **PolyForm Noncommercial License 1.0.0** ([`LICENSE`](LICENSE)) — run, modify, and self-host for any **noncommercial** purpose (personal, research, education, nonprofits, government). **Any commercial use requires prior written authorization signed by the copyright holder** (any signed written grant — letter or agreement — suffices) — no commercial use is permitted without it. This applies to the whole repo, including the standalone tools under `tools/` and the shared `contracts/`. On top of the license, premium runtime tiers (pro / enterprise / mssp) are unlocked by a license key; no key → Community tier. Detail: [`LICENSING.md`](LICENSING.md).
