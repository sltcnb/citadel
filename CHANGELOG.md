# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Analyst investigation suite + security/UX hardening (2026-06)

- **Alert-triggered auto-investigation** — fired detection rules spawn scoped Pilot investigations (severity×count ranked); analysts open pre-triaged alerts with verdicts instead of raw rows. `POST /cases/{id}/alert-rules/triage`.
- **Entity graph** — host↔user↔IP relationship view for lateral-movement at a glance. `GET /cases/{id}/graph`.
- **Baseline / rare-artifact stacking** — least-frequency-of-occurrence: values rare across the case but present on a target host. `GET /cases/{id}/baseline/stack`.
- **Reverse kill-chain assembly** — from an anchor event, walk back to first access / forward to impact, ATT&CK-tagged. `GET /cases/{id}/killchain`.
- **Cross-case Pilot memory** — IOCs/TTPs/verdicts persist across cases ("this IOC burned us before"); auto-persisted on Pilot conclude. **Continuous co-pilot** watch surfaces un-triaged new activity. `/pilot/memory`, `/cases/{id}/pilot/watch`.
- **Confidence calibration** — Pilot verdicts annotated with evidence-weighted confidence bands; low-confidence verdicts flagged "needs more data".
- **Signed evidence chain-of-custody** — per-case hash-chained artifact seals + court-ready, HMAC-signable manifest with verification. `/cases/{id}/evidence/*`.
- **Tamper-evident audit log** — persistent, hash-chained record of all mutating requests; `GET /audit/log` + `/audit/verify` (admin).
- **Rosetta enrichment** — GeoIP / ASN / reverse-DNS for public IP fields (ECS `*.geo`, `*.as`); graceful no-op without MaxMind DBs.
- **Sigma opt-out** — runtime global toggle (admin, Settings) + per-case override; replaces the restart-only env flag.
- **Frontend** — case toolbar consolidated from 15 buttons into grouped **Detect / Investigate / Case** menus; every case panel gained an inline "How to use" help block (what it does · when to use · data it needs) and a responsive full-width-on-mobile drawer; route-level code-splitting (main bundle 816 kB → 64 kB); shared `useAsyncConfig`/`Badge`/format utilities; vitest test runner bootstrapped.

### Security

- **IDOR closed** across ~25 case-scoped endpoints (`require_case_access` company-filter enforcement).
- **Analyst→RCE** via plugin upload gated to admin.
- **Prompt-injection guardrails** on the Pilot agent — untrusted forensic evidence sanitized + fenced as data, system prompt instructs the model evidence is never instructions.
- **Auth** — `AUTH_ENABLED=false` fails closed without explicit `CITADEL_ALLOW_NO_AUTH`; forced password rotation off the default bootstrap password; login rate-limiting; short-lived SSE stream tokens (no full JWT in query strings); CTI feed fetches re-validate redirects (SSRF).
- **Secrets** — CTI feed `api_key` and case BitLocker recovery keys redacted from API responses.

### Fixed

- Detection thresholds miscounted above 10 k (`track_total_hits`); silent rule-failure swallowing; empty MITRE report section (wrong field names); non-atomic archive restore; Redis read-modify-write races on rule/feed/config blobs (optimistic WATCH/MULTI); job pagination over unordered sets; anomaly baseline window included future days.
- Event-loop blocking offloaded to executors (CTI scheduler, malware upload + bounded streaming, SSE log polling, chunked ingest).
- Backend test suite grown from 1 → 148 passing (auth/ACL/sigma-converter/triage/baseline/graph/killchain/pilot-memory/evidence-seal/audit).

### Changed — directories match tool names

- **Tool dirs renamed to their tool names**: `collector`→`talon`, `plugins`→`babel`, `modules`→`anvil`, `ingester`→`sluice`, `processor`→`sluice-worker` (`rosetta`/`augur`/`sigil` already matched). The `plugins` Python package was renamed to `babel` across all imports; container/k8s `/app/plugins`→`/app/babel`, `/app/modules`→`/app/anvil`, `/app/ingester`→`/app/sluice`. Submodule/manifest/brick/pyproject names, Dockerfiles, compose, CI, and docs all updated. 16/16 suites green. (Container/k8s deploy paths updated mechanically — need a build to confirm.)
- **Sigil rules are their own submodule** at `tools/sigil` (moved out of `api/`); the API loads them from an env-configurable `CITADEL_RULES_DIR` (`/app/sigil` in the image).
- **`citadel-contracts` is its own repo** — registered in `.gitmodules` + `versions.yaml`, made pip-installable (`pip install ./tools/citadel_contracts`), and installed in the api + sluice-worker images (no more runtime `sys.path` reliance).

### Added

- **Phase 1 (Hardening):** MIT LICENSE; root + per-tool `pyproject.toml`; CI (`ci.yml`/`build.yml`/`codeql.yml`); `.pre-commit-config`; MkDocs site + 3 ADRs; `charts/citadel` Helm umbrella chart.
- **Phase 2 (Pipeline & detection):**
  - **Talon** — pluggable `ArtifactCollector` ABC + gRPC agent client skeleton (`collector.proto`); resumable sha256 chunked upload (8/8 tests pass).
  - **Sluice** — bus emit to `events.parsed` + idempotent re-ingest (sha256 dedup), behind a feature flag.
  - **Babel** — MIME-type declarations across all 40 parsers; golden-file test harness validating events against the ForensicEvent contract.
  - **Rosetta** — new standalone canonicalizer CLI: ForensicEvent JSONL → ECS v8 JSONL, config-driven field maps.
  - **Anvil** — typed `BaseModule` interface + structured `Result` schema; 3 analyzers retrofitted.
  - **Sigil** — runnable rule-CI validator (YAML + UUID-uniqueness + lint) + offline Lucene matcher + sample_events corpus.
  - **Augur** — new standalone intel CLI: pluggable sources (URLhaus/AbuseIPDB/OTX), cross-source confidence scoring, STIX 2.1 export, TTL cache (offline-tested).

### Added — Phase 2 gap-closure to docx done-when

- **Talon** — X25519 + AES-256-GCM payload encryption (`crypto.py`); in-process Collector servicer + resilient resumable **encrypted** upload end-to-end, with tamper detection (`secure_upload.py`, 5/5 tests). _Done-when met._
- **Sluice** — routing-coverage checker proving every built parser has a handler + routes (286/286 signals, 0 gaps; `routing_coverage.py`). _Done-when met._
- **Babel** — all manifests normalized to semver; Parser SDK guide + cookiecutter template that scaffolds a loadable parser (`sdk/`, `template/`, 2/2 tests). _Done-when met._
- **Rosetta** — `daemon` mode: watch dir → normalize → ES/file sink with disk-backed backpressure (EVTX+syslog→ECS, 3/3 tests). _Done-when met._
- **Anvil** — all **12** analyzers on the typed `BaseModule` interface; DAG pipeline runner with dependency ordering + data passing (3/3 tests). _Done-when met._
- **Sigil** — Sigma→ES `convert` (1628 rules, 0 failures) + published ATT&CK `coverage_matrix.md` (13/14 tactics); 1628 rules (6/6 tests). _Done-when met._
- **Augur** — 5 sources (URLhaus/AbuseIPDB/OTX/Shodan/GreyNoise); MISP event export with round-trip preserving indicators + severity (5/5 tests). _Done-when met._

### Added — depth/quality hardening

- **Project-wide timestamp normalization** to ISO-8601 `Z`: canonicalized in Rosetta (`to_iso_z`), Babel (`iso_z` in `make_event` + suricata/zeek fixes), Sluice bus_emit; **enforced** in the golden harness (regex always + jsonschema `FormatChecker` when present). Caught + fixed 2 real inconsistencies (zeek, suricata).
- **Rosetta** — fieldmap expanded to 41 artifact types; OSSEM/ATT&CK enrichment (`threat.technique.id`/`tactic.name`) from explicit event tags or an artifact-type map.
- **Anvil** — discovery switched from fragile regex source-scrape to **AST** static extraction (handles any string formatting, import-free); `Result.artifacts[]` + metrics now flow through the sandbox envelope and are persisted to the module run record.
- **Observability** — stdlib-only `observability.py` for the worker: structured JSON logs, Prometheus-text metrics registry, `/healthz` + `/readyz` + `/metrics` HTTP server.
- **Sigil** — convert now prefers real **pysigma** + Lucene backend when installed, falling back to the documented subset converter.
- **Talon** — real gRPC server module (`collector_server.py`) with **mTLS** (`require_client_auth`) + `generate_stubs.sh`; shares the offline-tested upload core.
- **Babel** — skip-aware **binary golden** harness (EVTX/LNK/Prefetch/Registry/MFT): cases registered, run when a real fixture + runtime lib are present, otherwise skip with a reason.

### Added — decoupling, transport, bug fixes

- **`citadel_contracts` package** — extracted the parser contract (`BasePlugin` + `ForensicEvent` helpers + `iso_z`/`classify_os`/`STRUCTURED_ARTIFACTS`) into a standalone, dependency-free package. `plugins/base_plugin.py` is now a backward-compatible re-export shim; the **processor (Sluice) imports the contract, not Babel internals**. Parser packs are now drop-in interchangeable (subclass the contract, point the loader at the dir). Verified: 39 parsers load, 286/286 signals route, class identity holds.
- **Transport per edge** (ADR-0004): Redis Streams = default data-plane; Talon stays gRPC + S3/MinIO; Sluice→Babel stays in-process via `citadel_contracts` (fastest), gRPC-ready later.
- **Dockerfiles** (api, processor) copy `citadel_contracts` to `/app/citadel_contracts`.

### Added — symmetry, TS contracts, hygiene

- **TypeScript contract codegen** — `scripts/contracts_codegen.py` generates `frontend/src/contracts/*.ts` from `contracts/*.schema.json` (single source; CI `--check` fails on drift).
- **Module contract in `citadel_contracts`** — `citadel_contracts.module` (`BaseModule`/`Result`/`RunContext`/…) is now the canonical Anvil module contract; `tools/anvil/base.py` is a re-export shim. Anvil modules are swappable like Babel parsers; 12/12 verified, class identity holds.
- **Clean container imports** — `PYTHONPATH=/app` in the api + processor images so `citadel_contracts` resolves without runtime `sys.path` insertion (the dev bootstrap remains a fallback).
- **Tool repos renamed to real names** — submodules/manifest/brick/pyproject now use `talon`/`sluice`/`babel`/`rosetta`/`anvil`/`augur`/`sigil` (+ domain `wraith`/`wiretap`/`nimbus`/`warden`), not `citadel-*`. Talon CLI help shows `talon`, not `citadel-collector`.
- **Removed AI-tooling fingerprint** — deleted `.claude/` and git-ignored it (+ `.cursor/`, `.aider*`).

### Added — contract enforcement, docs platform

- **Runtime contract validator** — `citadel_contracts.validate_forensic_event` (dependency-free core rules + optional jsonschema). Sluice's bus emit delegates to it (single source; adds ISO-8601 Z + raw-for-structured enforcement). 4/4 tests.
- **api/plugin_loader** repointed to `citadel_contracts` (closed a second contract-boundary leak — there were two loaders).
- **Docs platform** — MkDocs site made publishable: Getting Started, Operations, Testing, Contributing, Licensing pages + ADR-0004 in nav; `docs/requirements.txt`; a `mkdocs build --strict` CI job. All nav targets verified to resolve.

### Added — deploy, ops, integration

- **End-to-end integration test** (`tests/integration/`) — Babel→Rosetta→Sigil over the contracts, offline; caught + fixed a Rosetta gap (it now passes through standard ECS sub-objects `host/user/network/http/…` instead of dropping them).
- **Real CI test gate** — `scripts/run_tests.sh` runs all 15 suites; `ci.yml` runs it enforced (no soft-fail) on py 3.11/3.12.
- **Resource allocator** (`scripts/allocate_resources.py` + `config/resources.yaml`) — detects real host RAM/CPU, respects an **admin cap** (`max_pct_of_host`) + headroom + per-service weights, emits a Helm values overlay. Storage split across stateful services.
- **Helm ingress** — single-FQDN ingress (frontend `/` + API `/api`) with traefik websecure + TLS + http→https redirect, mirroring the original config (`ingress.*` values).
- **Admin log viewer** — `observability.RedisLogHandler` ships capped per-service JSON log streams; admin-only `GET /api/v1/admin/logs/{service}` tails them.
- **Tools-as-repos** — `tools/versions.yaml` (pinned per-tool refs) + `scripts/fetch_tools.sh` (clone/checkout at deploy) + corrected `.gitmodules`.
- **`tools/README.md`** — human-readable index of every tool (role, dir, in→out, CLI, status, contracts).
- **Licensing clarified** — open-core: MIT source + commercial license-key feature tiers (documented in `LICENSING.md` + README); no conflict.

### Fixed — inherited bugs

- **Aggregation `'__missing__' is not an IP string literal`** — new pure `api/agg_rules.py`: the string `missing` bucket is attached only for text/keyword fields (never ip/numeric/date), and numeric/date aggs are validated against field type → clean 400 instead of a cryptic ES mapper error.
- **`apport.log` mislabelled `binary_files`** — `strings_fallback` now classifies text vs binary (UTF-8/printable ratio) and emits `generic_text` for logs.
- **`wtmp`/`btmp` routing** — confirmed `UtmpPlugin` claims them (+ rotations) at priority 110 over the strings catch-all; regression-locked (the old-project symptom does not reproduce in Citadel).

- **Sluice** — `process_artifact` `UnboundLocalError` masking the real error on MinIO download-failure path (init `claimed_sha256`/`artifact_sha256` before `try`).
- **Anvil** — capa/floss `MODULE_DESCRIPTION` reverted to single-line so the API description scraper resolves them; `result.schema.json` `$id` no longer overclaims the `/contracts/` namespace.
- **Talon** — `--bundle-manifest` now honors a user-supplied filename instead of always writing `manifest.json`.

### Changed

- Renamed traceX → Citadel; added tool-suite scaffolding (contracts/, tools/, brick.yaml manifests).
- Restructured: standalone tools under `tools/`; platform stays at root; Phase-3 domain tools (Wraith/Wiretap/Nimbus/Warden) moved to sibling `../domain-tools/`.
- ROADMAP: removed old Phase 4 (OSS contributions); renumbered Phase 5 → Phase 4 (Visibility).
