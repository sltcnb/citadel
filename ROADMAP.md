# Citadel — Platform & Standalone Tool Suite

> A DFIR platform built from independent, standalone tools — each useful on its own, all composed by **Citadel**.
>
> *(Renamed from traceX. This is the refreshed suite plan; the prior codebase-improvement roadmap is preserved in `ROADMAP.legacy.md`.)*

**Legend** — ● built · ◐ partial · ○ planned

---

## 1. Executive Summary

Citadel is a digital-forensics and incident-response (DFIR) platform built as a suite of standalone tools. Each tool has its own name, repository, CLI, and reason to exist — an analyst can pick up any one of them alone, with no platform required. Citadel is the integrator: it wires the tools together over shared contracts into an end-to-end pipeline, from acquisition to a finished report.

Lifecycle coverage:

- **Acquire** — Talon collects artifacts from hosts, disks, and cloud.
- **Ingest & parse** — Sluice routes every artifact to Babel (multi-format parser library); Rosetta canonicalizes to ECS v8 + OSSEM.
- **Detect & analyze** — Sigil matches Sigma/YARA; Anvil runs heavy analyzers in a sandbox; Augur enriches indicators; Pilot reasons over a case autonomously.
- **Specialize** — Wraith (memory), Wiretap (network), Nimbus (cloud), Warden (identity).
- **Report** — Scribe renders HTML/PDF/STIX/MISP.
- **Integrate** — Citadel provides cases, timeline, search, multi-tenancy, and the console.

---

## 2. The Tool Suite

| Tool | Role | Standalone use | Maps to (current dir) |
|------|------|----------------|-----------------------|
| **Talon** | Acquisition agent | Collect host/disk/cloud artifacts into a bundle | `collector/` |
| **Sluice** | Intake & routing | Detect, dedup, route, parse anything | `ingester/` + `processor/` |
| **Babel** | Parser library | Parse any artifact → normalized event stream (43 parsers) | `plugins/` |
| **Rosetta** | Canonicalizer | Normalize any event stream → ECS v8 + OSSEM | *new* (mapping today in parsers/processor) |
| **Sigil** | Detection engine | Match Sigma + YARA against an event stream | `tools/sigil/` |
| **Anvil** | Analysis runner | Run sandboxed deep analyzers (Volatility/Hayabusa/…) | `modules/` |
| **Augur** | Intel enrichment | Enrich IOCs (MISP/VT/OTX/…) → STIX | *new* (intel bits in `api/routers/`) |
| **Pilot** | Investigation agent | LLM agent investigates a case/index | `api` LLM layer (`llm_config.py`, agent) |
| **Scribe** | Report engine | Render a case → HTML/PDF/STIX/MISP | `api/routers/reports.py`, `export.py` |
| **Wraith** | Memory forensics | Push-button memory-image analysis | *new* (Volatility via Anvil today) |
| **Wiretap** | Network detection | Hunt C2/beacon/DNS-tunnel/lateral in PCAP | *new* (pcap/zeek via Babel today) |
| **Nimbus** | Cloud forensics | Read-only AWS/Azure/GCP collection | *new* |
| **Warden** | Identity audit | Audit 7 IdPs + cross-provider attack-path graph | *new* |
| **Citadel** | Platform / integrator | Cases, timeline, search, console; composes the suite | `api/` + `frontend/` |

---

## 3. How Citadel Composes the Tools

Tools stay independent because they speak only **contracts** — never each other's internals.

### 3.1 Principles
- **Standalone-first** — every tool runs as a CLI without the platform.
- **Contract-first** — every tool ships a `brick.yaml` manifest declaring inputs, outputs, schema versions.
- **Single responsibility** — one tool, one job.
- **Schema is the lingua franca** — `ForensicEvent → ECS v8 + OSSEM`, plus artifact bundles. Never bespoke formats.
- **Stateless compute, stateful substrate** — state lives in Elasticsearch, MinIO, Redis.
- **Replaceable** — swap a rule pack, parser, or index without touching neighbours.
- **Content vs. code** — Sigil rule packs and Babel parser packs are versioned content, distinct from engine code.

### 3.2 The canonical event
Babel parsers yield a `ForensicEvent` (required `timestamp` + `message`; recommended `artifact_type` + raw record). Rosetta maps it to ECS v8 + OSSEM. A ~90-entry artifact-type taxonomy is the routing key; structured types carry their raw record.

### 3.3 The artifact bundle
```
bundle/  manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256
```

### 3.4 The wiring: bus + gRPC
- Synchronous request/response over **gRPC** (Talon ↔ Sluice, Pilot ↔ tools).
- Asynchronous pipeline over a **message bus** — Redis Streams default, NATS/Kafka pluggable.
- Topics: `artifacts.received → events.parsed → events.normalized → {events.indexed, detections.matched, modules.completed, intel.enriched}`

### 3.5 The tool manifest (`brick.yaml`)
`name, kind, version, consumes{content_types,filenames}, produces{schema,artifact_types}, dependencies, health`

### 3.6 Pipeline & deployment
```
Talon → Sluice → Babel → Rosetta → {store, Sigil, Anvil, Augur} → Citadel timeline → Pilot → Scribe → console
```
- Monorepo-of-submodules: Citadel pins each tool at a tested version.
- Helm umbrella chart `charts/citadel` + per-tool subcharts; autoscale hot workers (Babel/Anvil).
- Compose profiles: `--profile edge` (Talon) | `pipeline` (Sluice+Babel+Rosetta+store) | `full` (everything).

---

## 4. Cross-Cutting Concerns
- **Security** — JWT authn + RBAC; secrets in Vault/sealed-secrets; mTLS between tools + agent; parser sandbox + fuzz (atheris/schemathesis); SBOM + trivy + signed images (cosign); tamper-evident bundles + immutable audit log; Pilot prompt-injection guardrails.
- **Multi-tenancy** — company isolation at index/object-store/search; per-tenant ES ILM retention; PII redaction; legal hold.
- **Observability** — Prometheus metrics, OTel traces, structured logs, health endpoint per tool; load tests + published throughput.
- **Reliability** — idempotent ingest + at-least-once bus; autoscale Babel/Anvil on queue depth; disk-backed buffer on index outage; ES/MinIO backup + DR drill.
- **Quality** — CI + tests per tool; semver + CHANGELOG + Conventional Commits; `brick.yaml` + dep graph; MkDocs + ADRs + per-tool README; i18n/a11y console.

---

## 5. Delivery Plan

### Phase 1 — Hardening (Weeks 1-3)
CI (ruff/mypy/eslint/hadolint/yamllint; pytest+cov, testcontainers, mock LLMs; buildx multi-arch, trivy/pip-audit/npm-audit, syft SBOM, kubeconform). Tests (hot-path unit, Babel golden-files, one integration pipeline, one Playwright path; fail-on-decrease). Packaging (pyproject + MIT LICENSE + topics per tool; `charts/citadel` Helm; MkDocs + ADRs + per-tool README + `brick.yaml`).

### Phase 2 — Pipeline & detection tools (Weeks 4-6)
Talon: ArtifactCollector interface + gRPC remote agent (chunked/resumable/encrypted). Sluice: route every Section-6 built row + bus emit + idempotent re-ingest. Babel+Rosetta: MIME decls + golden tests; consolidate ECS/OSSEM mapping into Rosetta; standalone CLI + daemon. Anvil: typed analyzer interface + result schema + 12 retrofits. Sigil: CI + sample corpus + grow rules. Augur: 5+ sources + confidence scoring + STIX export + cache.

### Phase 3 — Domain tools (Weeks 7-9) — *built outside this repo*
Nimbus (new): AWS/Azure/GCP read-only collection + posture detections. Warden (new): 7-IdP audit + cross-provider attack-path graph. Promote one of Wraith/Wiretap/Scribe to a polished standalone repo.

> The domain tools (Wraith, Wiretap, Nimbus, Warden) live **outside Citadel** in the sibling `../domain-tools/` folder — each its own standalone repo. Citadel consumes their output via the shared contracts; their scaffolds are no longer under `tools/`.

### Phase 4 — Profile & visibility (Weeks 1-10)
Profile README, tool-suite table, blog series, distribution (LinkedIn, r/netsec, r/DFIR, Awesome-DFIR, meetup talk). English only; commit regularly.

---

## 6. Timeline & Milestones

| Week | Focus | Deliverable / validation |
|------|-------|--------------------------|
| 1 | Hardening + Profile | CI green, pyproject + MIT LICENSE, profile README, topics, brick.yaml template |
| 2 | Tests | pytest on hot paths + Babel golden-files; `test.yml` green; codecov |
| 3 | Helm + Docs | `charts/citadel` lint+template; MkDocs (pipeline diagram); ADRs; health endpoints |
| 4 | Talon + Sluice | Collector plugin extraction + gRPC agent PoC; Sluice routes every built input |
| 5 | Rosetta + Anvil + Sigil | Standalone Rosetta (EVTX+syslog→ECS); typed Anvil interface + 12 retrofits; Sigil CI green |
| 6 | Integration + Augur | End-to-end over the bus; Augur 5-source + STIX; one Playwright path |
| 7 | Nimbus | CloudTrail+Activity+Audit across AWS/Azure/GCP; repo live |
| 8 | Warden | AD+Okta+Workspace collected; cross-provider path query returns a path |
| 9 | Promote Wraith/Wiretap/Scribe | One domain tool polished standalone (in `../domain-tools/`); start high-value planned parsers |
| 10 | Visibility | Profile README + tool-suite table; 2 blog posts; LinkedIn campaign |

---

## Appendix A — Shared Contracts

**A.1 ForensicEvent → ECS**
```
{ timestamp(req,ISO8601Z), message(req), artifact_type, timestamp_desc, raw(req for structured),
  +Rosetta: event.category/type, host.*, user.*, process.*, source/destination.*, ecs.version }
```

**A.2 Artifact bundle manifest**
```
{ session_id, hostname, os, started_at, finished_at,
  artifacts:[{name, sha256, size, category}], artifact_count, total_bytes, errors:[] }
```

**A.3 Talon agent (collector.proto, sketch)**
```
service Collector { Register(AgentHello)->TaskList; Heartbeat(stream)->stream Task;
  UploadChunk(stream Chunk)->UploadAck /* 8MB, sha256/chunk, resumable */ }
```

**A.4 brick.yaml (per tool)**
```
name, kind, version, consumes{content_types,filenames}, produces{schema,artifact_types}, dependencies, health
```

## Appendix B — Warden Per-Provider Detail
One collector per IdP → a common graph (Identity/Group/Resource/Session; MEMBER_OF/HAS_ROLE/CAN_IMPERSONATE/TRUSTS).
Providers: Active Directory (LDAP), Okta (REST), Google Workspace (Admin SDK), FreeIPA/RH IDM, Azure AD/Entra (Graph), Keycloak (Admin REST), JumpCloud (REST v2).
Cross-provider: link by UPN/email (`SAML_IDENTITY`); `shortestPath` untrusted→privileged; alert on new path.
```
MATCH p=shortestPath((n:Identity{risk:'high'})-[*..15]->(m:Identity{privileged:true})) RETURN p,length(p)
```
