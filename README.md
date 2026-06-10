<div align="center">

<img src="frontend/public/logo.svg" alt="Citadel" height="64">

# Citadel

**A DFIR platform built from independent, standalone tools — each useful on its own, all composed by Citadel.**

[![License: MIT](https://img.shields.io/badge/source-MIT-yellow.svg)](LICENSE)
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

**Full guide → [INSTALLATION.md](INSTALLATION.md)** (Docker Compose · Helm/bring-your-own-substrate · Kubernetes · ingress for Traefik/Tailscale · resource sizing).

---

## The tool suite

Each tool is its own repo (`tools/<name>`), its own CLI, its own `brick.yaml`. Run one alone, or adopt the platform. Full index: [`tools/README.md`](tools/README.md) · [`tools/SUITE.yaml`](tools/SUITE.yaml).

| Tool | Role | Input → Output | Standalone CLI |
|------|------|----------------|----------------|
| **Talon** | Acquisition agent | host/disk/cloud → artifact bundle | `talon collect --out case.bundle` |
| **Sluice** | Intake & routing | bundle/file/dir → routed events (+ bus) | `sluice ingest case.bundle` |
| **Babel** | Parser library (43+) | artifact → `ForensicEvent` | `babel parse Security.evtx` |
| **Rosetta** | Canonicalizer | `ForensicEvent` → ECS v8 + OSSEM | `rosetta normalize ev.jsonl` |
| **Sigil** | Detection engine | ECS + rules → detections | `sigil validate ./rules/` |
| **Anvil** | Analysis runner | artifact + module → findings | `anvil run volatility3 -a mem.raw` |
| **Augur** | Intel enrichment | IOCs → scored STIX / MISP | `augur enrich iocs.json` |
| **Pilot** | Investigation agent | case → autonomous report (LLM) | `pilot investigate --case ID` |
| **Scribe** | Report engine | case → HTML/PDF/STIX/MISP | `scribe report --case ID -f pdf` |
| **Citadel** | Platform / integrator | cases · timeline · search · console | `docker compose --profile full up` |

Domain analyzers — **Wraith** (memory), **Wiretap** (network), **Nimbus** (cloud), **Warden** (identity) — live in the sibling [`../domain-tools/`](../domain-tools) repos and feed Citadel over the same contracts.

---

## Features

| Area | What |
|------|------|
| **Ingestion** | 40+ forensic formats auto-detected (EVTX, MFT, Registry, Prefetch, LNK, PCAP, Plaso, syslog, Zeek, Suricata, browsers, Android/iOS, disk images) |
| **Detection** | 1 628 built-in rules (1 487 Sigma across 13 ATT&CK tactics + 141 ES queries); Sigma→ES conversion; ATT&CK coverage matrix; SigmaHQ import |
| **Analysis** | Hayabusa, RegRipper, YARA, Volatility3, capa/FLOSS, oletools, PE/strings, CTI IOC matching — typed `BaseModule` + DAG pipelines |
| **Search** | Elasticsearch full-text + facets, saved queries, timeline, CSV export |
| **AI assist** | LLM providers (Anthropic, OpenAI, Ollama, OpenRouter) for the Pilot agent, rule generation, summaries; cost tracking |
| **Threat intel** | STIX/TAXII, MISP, OTX/URLhaus/AbuseIPDB/Shodan/GreyNoise enrichment |
| **Access** | JWT auth; roles admin/analyst/developer/guest; per-company isolation; tiered licensing |
| **Observability** | structured JSON logs, Prometheus `/metrics`, `/healthz`/`/readyz`, admin log viewer |

---


## Architecture

- **Standalone-first / contract-first** — tools never import each other; they exchange `ForensicEvent → ECS`, artifact bundles, and `brick.yaml` manifests. Contracts live in [`contracts/`](contracts/) + the pip-installable [`citadel_contracts`](tools/citadel_contracts) package.
- **Transport per edge** ([ADR-0004](docs/adr/0004-transport-per-edge.md)): Redis Streams for the pipeline data-plane · gRPC + S3/MinIO for the Talon remote agent (mTLS) · in-process via `citadel_contracts` for the hot Sluice→Babel path.
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

Full documentation site (`mkdocs serve`): [`docs/`](docs/) — Getting Started · Architecture · Operations · Testing · Contributing · ADRs.

---

## Licensing

**Open-core.** Source is **MIT** ([`LICENSE`](LICENSE)) — run, modify, self-host all of it. Premium runtime tiers (pro / enterprise / mssp) are unlocked by a commercial license key; no key → Community tier. The standalone tools + contracts are MIT with no gating. Detail: [`LICENSING.md`](LICENSING.md).
