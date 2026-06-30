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

**Open-core / source-available.** The whole repo is source-available under the PolyForm Noncommercial License — run, modify, and self-host it for any noncommercial purpose. Premium *runtime* tiers are unlocked by a license key; no key → Community tier. See [Licensing](#licensing).

---

## Quickstart

`./foctl` drives every deployment — it generates secrets, creates `.env`, builds images, and sizes resources, so a first install is one command.

```bash
git clone https://github.com/sltcnb/citadel.git && cd citadel
./foctl deploy docker     # single host · or: ./foctl  (interactive menu)
```

Open **http://localhost** — default login `admin` / `CitadelAdmin1!` (you are forced to set a new password on first sign-in).

| Mode | Command | Best for |
|------|---------|----------|
| **Docker Compose** | `./foctl deploy docker` | laptop, single server, evaluation, air-gapped |
| **Kubernetes** (raw manifests) | `./foctl deploy k8s` | a cluster where Citadel also provisions ES/Redis/MinIO |
| **Kubernetes** (new local k3d) | `./foctl deploy k8s-new` | development, CI, offline labs |
| **Helm** (app-only) | `./foctl deploy helm` | a cluster already running ES/Redis/MinIO + an ingress |

**Operations** — `./foctl status` · `./foctl logs api` · `./foctl update` (rebuild + redeploy) · `./foctl destroy` · `./foctl config`. `foctl` auto-detects the mode if you omit it.

**Run a single tool standalone** (no platform required):

```bash
babel parse Security.evtx -o events.jsonl                 # parse one artifact
rosetta normalize events.jsonl --ecs 8.11 -o ecs.jsonl    # → ECS v8 + OSSEM
augur enrich iocs.json -o enriched.stix.json              # enrich IOCs
python tools/sigil/sigil_validate.py                      # validate detection rules
```

**Compose profiles** (manual Docker): `edge` (Talon) · `pipeline` (Sluice+Babel+Rosetta+store) · `full` (everything).

<details>
<summary><b>Helm / Kubernetes by hand, ingress, and SSO</b></summary>

The umbrella chart `charts/citadel` deploys the **app only** (api + processor + frontend); point it at existing Elasticsearch / Redis / MinIO, or set `--set elasticsearch.enabled=true` (etc.) to let Helm run them.

```bash
# build (native arch) + make images visible to the cluster
docker build -t citadel-api:1.0.0       -f api/Dockerfile .
docker build -t citadel-processor:1.0.0 -f tools/sluice-worker/Dockerfile .
docker build -t citadel-frontend:1.0.0  -f frontend/Dockerfile frontend

# size requests/limits from the real host (optional)
python3 scripts/allocate_resources.py        # → charts/citadel/values-resources.generated.yaml

# install against existing substrate
helm upgrade --install citadel charts/citadel -n citadel --create-namespace \
  -f charts/citadel/values-resources.generated.yaml \
  --set-string config.elasticsearchUrl=http://elasticsearch.<ns>:9200 \
  --set-string config.redisUrl=redis://redis-service.<ns>:6379/0 \
  --set-string config.minioEndpoint=minio-service.<ns>:9000 \
  --set ingress.enabled=true --set-string ingress.fqdn=citadel.example.com \
  --set-string ingress.className=traefik
```

> Build the host's **native** arch only — emulated cross-arch builds are 10–50× slower.

**Ingress** — `ingress.className`: `traefik` (default; TLS + http→https redirect) · `tailscale` (`--set ingress.tls.enabled=false`) · `nginx`/other (Traefik-only bits skipped) · or `--set ingress.enabled=false` and route your own Ingress to `citadel-frontend:80` (`/`) and `citadel-api:8000` (`/api`).

**SSO (Google / Microsoft)** — off until configured. Set provider client id/secret plus `SSO_REDIRECT_BASE`, optional `SSO_ALLOWED_DOMAINS`, `SSO_DEFAULT_ROLE`, `SSO_AUTO_PROVISION`, and redeploy. Register the redirect URI `{SSO_REDIRECT_BASE}/api/v1/auth/sso/{google|microsoft}/callback`. The platform verifies the provider's `id_token` against its JWKS before issuing a session.

**Prerequisites** — Docker (Compose v2); kubectl + a cluster and Helm 3 for k8s/Helm modes; Python 3 for `foctl`.

**Troubleshooting** — Elasticsearch takes ~1–2 min to go healthy on first start; pods pending/crashlooping → `kubectl -n <ns> describe pod <p>`; service logs via `./foctl logs api` or `GET /api/v1/admin/logs/{service}`.
</details>

---

## The tool suite

Each tool is its own product (`tools/<name>`), with its own CLI and `brick.yaml`. Run one alone, or adopt the platform. Full index: [`tools/README.md`](tools/README.md) · [`tools/SUITE.yaml`](tools/SUITE.yaml).

| Tool | Role | Standalone CLI | Docs |
|------|------|----------------|------|
| **Talon** | Acquisition agent — host/disk/mount → artifact bundle | `talon collect --out case.bundle` | [README](tools/talon/README.md) |
| **Sluice** | Intake & routing — bundle/file/dir → routed events | `sluice ingest case.bundle` | [README](tools/sluice/README.md) |
| **Babel** | Parser library — artifact → `ForensicEvent` (40+ packs) | `babel parse Security.evtx` | [README](tools/babel/README.md) |
| **Rosetta** | Canonicalizer — `ForensicEvent` → ECS v8 + OSSEM | `rosetta normalize ev.jsonl` | [README](tools/rosetta/README.md) |
| **Sigil** | Detection engine — ECS + rules → detections | `sigil validate ./rules/` | [README](tools/sigil/README.md) |
| **Anvil** | Analysis runner — artifact + module → findings | `anvil run volatility3 -a mem.raw` | [README](tools/anvil/README.md) |
| **Augur** | Intel enrichment — IOCs → scored STIX / MISP | `augur enrich iocs.json` | [README](tools/augur/README.md) |
| **Pilot** | Investigation agent — case → autonomous report (LLM) | `pilot investigate --case ID` | [README](tools/pilot/README.md) |
| **Scribe** | Report engine — case → HTML/PDF/Markdown/DOCX | `scribe report --case ID -f pdf` | [README](tools/scribe/README.md) |
| **citadel_contracts** | Shared contract package every tool imports | — | [README](tools/citadel_contracts/README.md) |
| **Citadel** | Platform / integrator — cases · timeline · search · console | `docker compose --profile full up` | this README |

### Self-describing tools

Each tool ships a `capabilities.yaml` declaring, per platform, what it can do and the inputs each operation needs. Citadel **renders the UI from that declaration** — forms, options, validation — then routes the user's input to the tool and the tool's output back. Edit a tool's `capabilities.yaml` (e.g. add a Talon collection feature) and the Citadel UI changes with **no orchestrator code change**; `foctl deploy` self-registers the manifest into Redis (`fo:capabilities:<tool>`), so a tool-only change needs **no API rebuild**. Custom parsers (Studio) and custom modules (Anvil registry) are folded in **live** — they appear without editing any manifest.

---

## Features

| Area | What |
|------|------|
| **Acquisition** | Talon live + dead-box collection (Windows/Linux/macOS/server); in-app **Harvest** (server-side Talon collection from a mounted disk image / path); resumable encrypted upload; gRPC remote agent (mTLS) |
| **Ingestion** | 40+ parsers, 80+ forensic formats auto-detected (EVTX, MFT, Registry, Prefetch, LNK, PCAP, Plaso, syslog, Zeek, Suricata, browsers, Android/iOS, disk images) |
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

## Using the case console

Inside a case, the top toolbar is the command surface and everything you produce
flows to **one** place — **Findings**. Each control, left to right:

| Control | What it does |
|---------|--------------|
| **Ingest** | Upload artifacts (files, bundles, disk images) or pull from S3. Opens the ingest panel with live per-job progress. |
| **AI** | Open Pilot — the autonomous AI investigator. It reads the case (events, detections, **and the Findings store**), runs tool-calls, and writes a report. |
| **⚡ Auto-AI: ON/OFF** | Toggle. When **ON**, the AI investigation launches **automatically** the moment ingest finishes — no click needed. When **OFF**, you launch it by hand with the **AI** button. |
| **Findings** | The single output store. Everything the case produces lands here (see below). Filter by kind/severity, export CSV, re-ingest a selection, delete, pivot to source events. |
| **Detect ▾** | Menu: **Detection Rules** (Sigma/EQL library), **Anomalies** (z-score spike scan), **Baseline / rare artifacts**, **MITRE coverage**. |
| **Investigate ▾** | Menu: **IOCs** (observed indicators + threat-intel match), **Process Tree**, **Entity graph** (host↔user↔IP), **Kill chain**, **Co-Pilot** (what's new + cross-case memory). |
| **Case ▾** | Menu: **Notes**, **Templates**, **Report** (export MD/HTML/PDF/DOCX), **Evidence chain** (signed chain-of-custody). |
| **Modules** | Launch analysis modules (Hayabusa, YARA, CAPA, Volatility…). Pick a module → pick files → launch. A **Run status** link shows progress/failures/retry; **results land in Findings**. |
| **🗑 Delete** | Delete the case (two-click confirm). |

### Findings — the one output

Every analysis surface writes here, automatically, in one shape — so you query,
export, report, and re-ingest them all the same way:

- **Modules** write their detections as findings on completion.
- **IOC threat-match**, **anomaly scan**, **MITRE coverage** auto-save to Findings (no "save" button — the panels are live explorers; Findings is the durable record).
- **Pilot (AI)** can read the store and save findings it establishes.

From the Findings panel you can:

- **Filter** by *kind* (ioc / anomaly / mitre / module / killchain / …) and *severity*.
- **Export CSV** of the current view.
- **Re-ingest selection** — push a subset (or a whole kind) back into the case as a fresh ingest job ("part or total").
- **Delete**, or **pivot** to the raw source events a finding was derived from.

Findings are ordinary timeline events (`artifact_type:finding`), so they are also
searchable in the timeline, included in the **Report**, and carried in the
`.citadel` archive export — no separate path.

### Run status vs. output

Launching a module opens **Module run status** (progress / failure / retry / logs)
— that is *status*, not output. The moment a run finds something, those results
are findings. Status answers "is it running / did it fail"; **Findings** answers
"what did we find". They are deliberately separate.

---

## Architecture

Citadel is an end-to-end DFIR pipeline assembled from standalone tools. Tools stay independent because they speak only **contracts** — never each other's internals.

```
Talon → Sluice → Babel → Rosetta → {store, Sigil, Anvil, Augur} → timeline → Pilot → Scribe → console
```

- **Standalone-first / contract-first** — tools never import each other; they exchange `ForensicEvent → ECS`, artifact bundles, and `brick.yaml` manifests. Contracts live in [`contracts/`](contracts/) + the pip-installable [`citadel_contracts`](tools/citadel_contracts) package.
- **Single responsibility** — one tool, one job; swap a rule pack, parser, or index without touching neighbours.
- **Stateless compute, stateful substrate** — state lives in Elasticsearch, MinIO, Redis; workers scale on queue depth.

### The three shared layers

1. **`ForensicEvent`** — what a Babel parser yields: required `timestamp` (ISO-8601 **Z**) + `message`; `artifact_type` (the ~90-entry taxonomy routing key); structured types carry their `raw` record. Rosetta maps it to **ECS v8 + OSSEM** — the schema the timeline, search, Sigil, and Scribe all read.
2. **Artifact bundle** — the portable unit Talon hands to Sluice: `bundle/ manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256`.
3. **`brick.yaml`** — every tool's manifest (`name`, `kind`, `version`, `consumes`, `produces`, `dependencies`, `health`, `status`). Standalone use never requires it.

### Bus topics

The async pipeline runs over a message bus (**Redis Streams** default; NATS/Kafka pluggable). Each stage is a consumer group; delivery is **at-least-once**, so consumers dedup by event sha256 / doc id.

```
artifacts.received → events.parsed → events.normalized → {events.indexed, detections.matched, modules.completed, intel.enriched}
```

| Topic | Producer | Consumers |
|-------|----------|-----------|
| `artifacts.received` | Talon / upload API | Sluice |
| `events.parsed` | Babel (via Sluice) | Rosetta |
| `events.normalized` | Rosetta | store, Sigil, Anvil, Augur |
| `events.indexed` | store | timeline |
| `detections.matched` | Sigil | Citadel, webhooks |
| `modules.completed` | Anvil | Citadel |
| `intel.enriched` | Augur | Citadel |

Full contract: [`contracts/bus_topics.md`](contracts/bus_topics.md) · schemas: [`contracts/`](contracts/).

### Transport (per edge)

Redis Streams for the pipeline data-plane · gRPC + S3/MinIO for the Talon remote agent (mTLS) · in-process via `citadel_contracts` for the hot Sluice→Babel path.

| Component | Tech |
|-----------|------|
| Frontend | React 18 + Vite + Tailwind (nginx) |
| API | FastAPI / Python 3.11 (Uvicorn) |
| Workers | Celery (ingest + modules queues) |
| Search | Elasticsearch 8 |
| Broker/state | Redis 7 |
| Artifacts | MinIO (S3) |
| Ingress | Traefik (TLS, host routing) |

### Repository layout

- `api/` + `frontend/` — the Citadel platform (integrator).
- `tools/` — the standalone suite tools + `citadel_contracts` (shared contract).
- `contracts/` — the schemas every tool speaks.
- `charts/citadel/` — Helm · `config/` — runtime config · `k8s/` — raw manifests.

---

## Operations

- **Resource sizing** — `scripts/allocate_resources.py` detects the **real** host RAM/CPU, applies the policy in `config/resources.yaml` (`max_pct_of_host` admin cap, `headroom_pct`, per-service `weights`/`storage_weights`), and writes a Helm values overlay. Never over-commits — a config claiming more than the host is capped with a warning. `scripts/allocate_resources.py --print` shows the plan.
- **Observability** — every worker exposes structured JSON logs, a Prometheus `/metrics` endpoint, and `/healthz` + `/readyz`.
- **Admin log viewer** — tools ship capped per-service JSON log streams to Redis (`citadel:logs:<service>`); read via `GET /api/v1/admin/logs/services` and `GET /api/v1/admin/logs/<service>?limit=&level=`. Anvil per-run logs are at `fo:module_log:<run_id>`.
- **Pinned tools** — `tools/versions.yaml` pins each tool to a ref; `scripts/fetch_tools.sh` clones/checks them out at deploy time (skips vendored + unreachable cleanly).

---

## Develop, test & contribute

```bash
./scripts/run_tests.sh         # 16 suites + Babel→Rosetta→Sigil integration (stdlib-only gate)
```

The gate uses only the standard library (no pytest/ES/Redis needed) and runs enforced in CI on Python 3.11 and 3.12; a richer optional `pytest` job runs on top when its deps are present. `tests/integration/test_pipeline_e2e.py` drives a real artifact across three tool boundaries (`access.log → Babel → Rosetta → Sigil → detection`) offline. Babel parsers have golden-file tests (`tools/babel/tests/golden/`; regenerate with `BABEL_REGEN_GOLDEN=1`). `citadel_contracts.validate_forensic_event` enforces the ForensicEvent contract at runtime.

**Add a parser** (the common case) — scaffold from the cookiecutter, implement `parse()`, drop the package under `tools/babel/`; the loader discovers it, no registration:

```bash
cookiecutter tools/babel/template     # → manifest.yaml + <name>_plugin.py + test
```

**Add a whole tool** — new `tools/<name>/`, depending only on `citadel_contracts` + the schemas in `contracts/`; ship a `brick.yaml`; emit `ForensicEvent`; register it in `tools/versions.yaml` + `tools/SUITE.yaml`. **Rule:** never `import` another tool's internals — cross only via contracts. Timestamps are ISO-8601 **Z**; structured artifact types must carry `raw`; add a test and keep `scripts/run_tests.sh` green. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

CI (`.github/workflows/`) runs lint, the test gate, multi-arch image builds + Trivy/SBOM.

---

## Licensing

**Source-available, noncommercial.** Source is licensed under the **PolyForm Noncommercial License 1.0.0** ([`LICENSE`](LICENSE)) — run, modify, and self-host for any **noncommercial** purpose (personal, research, education, nonprofits, government). **Any commercial use requires prior written authorization signed by the copyright holder** (any signed written grant — letter or agreement — suffices) — no commercial use is permitted without it. This applies to the whole repo, including the standalone tools under `tools/` and the shared `contracts/`. On top of the license, premium runtime tiers (pro / enterprise / mssp) are unlocked by a license key; no key → Community tier. Detail: [`LICENSING.md`](LICENSING.md).
