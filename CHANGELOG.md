# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Analyst investigation suite

- **Alert-triggered auto-investigation** — fired detection rules spawn scoped Pilot investigations (ranked by severity × match count); analysts open pre-triaged alerts with a verdict instead of raw rows.
- **Entity graph** — host ↔ user ↔ IP relationship view for spotting lateral movement at a glance.
- **Baseline / rare-artifact stacking** — least-frequency-of-occurrence: surface values rare across the case but present on a target host.
- **Reverse kill-chain assembly** — from an anchor event, walk back to first access and forward to impact, tagged with ATT&CK.
- **Cross-case Pilot memory** — IOCs, TTPs, and verdicts persist across cases ("this IOC appeared in a prior case"); a continuous co-pilot surfaces un-triaged new activity.
- **Confidence-calibrated verdicts** — Pilot conclusions carry evidence-weighted confidence bands; low-confidence verdicts are flagged "needs more data".
- **Signed evidence chain-of-custody** — per-case, hash-chained artifact seals plus a court-ready, HMAC-signable custody manifest.
- **Tamper-evident audit log** — persistent, hash-chained record of every mutating request, with on-demand verification.
- **IP enrichment** — GeoIP, ASN, and reverse-DNS on public IP fields during normalization.
- **Sigma opt-out** — runtime global toggle plus per-case override (replaces the restart-only environment flag).

### Added

- **Delete module run results** — a module run can be removed from the case (or the standalone malware view) along with everything it produced: its indexed detections and findings, its results file and artifacts in object storage, and its Redis record. A one-click "Delete N failed" clears out every failed run at once; runs still pending or running are refused until cancelled.

### Changed

- Case toolbar consolidated into grouped **AI / Detect / Investigate / Case** menus; every case panel has an inline "How to use" help block and a responsive, full-width-on-mobile layout.
- Faster first load — route-level code-splitting cuts the main bundle from ~816 kB to ~64 kB.

### Security

- Multi-tenant access control enforced on all case-scoped endpoints (company isolation).
- Prompt-injection guardrails on the Pilot agent — evidence is treated as untrusted data, never instructions.
- Authentication fails closed when disabled without an explicit opt-in; forced password rotation off the default; login rate-limiting; short-lived tokens for streaming.
- Secrets (CTI API keys, BitLocker recovery keys) redacted from API responses; SSRF-guarded threat-intel fetches.

### Fixed

- **Threat intel no longer matches your own estate** — `cti_match` derives internal/non-routable status from the indicator value (RFC1918, loopback, link-local, CGNAT, multicast, reserved, `.local`/`.corp`/… hostnames) instead of trusting the flag written at feed-ingest time, and suppresses internal, own-network and allowlisted indicators from the timeline by default (`include_internal=true` keeps them). Private IPs are no longer reported as HIGH threat-intel detections.
- **Reports show the AI work that was actually done** — the exported report used to read `case:{id}:ai:report` alone, so a case with a risk assessment, autopilot runs or investigation sessions still printed "No AI narrative". It now falls back to an assessment assembled from those artifacts, labelled as derived rather than as a written report.
- **AI report evidence accuracy** — the ingested-files provenance section matched a job status the pipeline never writes (always "None."), module detections reached the model unnamed (`rule_title` was never read), and runs that failed were omitted entirely, letting "nothing found" read as "nothing there". Failed/incomplete runs are now listed explicitly as having produced no coverage.
- **Cuckoo runs no longer succeed falsely** — submission errors and analysis timeouts were emitted as low-severity "detections" on a COMPLETED run, so failures flowed into reports as sandbox evidence. Errors go to stderr, a run where nothing was analysed fails, and a task that never reaches `reported` no longer has its empty report scored as clean.
- Module runs record a `created_at`, so a run that failed at dispatch still shows a timestamp and the list keeps launch order instead of falling back to the random run id; run times display seconds so a batch launched together is distinguishable.
- Correct detection counts above 10 000; surfaced previously-silent rule failures; fixed an empty MITRE report section; atomic archive restore; resolved concurrent-edit races on rule/feed/config storage.
- Heavy work (intel polling, malware upload, log streaming, chunked ingest) moved off the request path for a more responsive API.
- **Talon collector reliability** — the harvester now tees a full execution log to `<output>.collector.log` from the first line and uploads it to S3 alongside the archive (second presigned URL), so a crash, an OOM/IO kill, or a `SIGTERM` still leaves a post-mortem. Signal handlers and a wrapping `try/finally` guarantee the log ships on any exit. The collector refuses to upload an empty (~22-byte stub) archive — it ships the log instead and exits non-zero. Free space on the output and staging volumes is logged up front (a full disk is the usual cause of truncated archives and mid-run kills), packaging detects `ENOSPC` and stops with a clear "DISK FULL" message instead of a silently truncated ZIP, and a dead-box `cryptsetup --version` probe can no longer hang the unlock.

## [1.0.0] — Initial release

End-to-end DFIR platform: **acquire → ingest → parse → normalize → detect → analyze → enrich → investigate → report**, built as a suite of standalone tools (Talon, Sluice, Babel, Rosetta, Sigil, Anvil, Augur, Pilot, Scribe) composed by Citadel over shared contracts.

- **Acquisition** — Talon live + dead-box collection (Windows/Linux/macOS), BitLocker decryption, resumable encrypted uploads, gRPC remote agent (mTLS).
- **Ingestion & parsing** — 40+ forensic formats auto-detected (EVTX, MFT, Registry, Prefetch, PCAP, cloud audit logs, mobile, browsers, AV/EDR); recursive archive + disk-image extraction; custom-parser SDK.
- **Normalization** — `ForensicEvent → ECS v8` + OSSEM/ATT&CK enrichment.
- **Detection** — 1 600+ built-in rules (Sigma + ES queries), Sigma→ES conversion, ATT&CK coverage matrix.
- **Analysis** — Hayabusa, YARA, Volatility3, capa/FLOSS, oletools, RegRipper, CTI matching, in sandboxed DAG pipelines.
- **Threat intel** — STIX/TAXII, MISP, OTX/URLhaus/AbuseIPDB/Shodan/GreyNoise enrichment with confidence scoring.
- **Investigation & reporting** — autonomous LLM Pilot agent; HTML/PDF/STIX/MISP reports.
- **Platform** — cases, timeline, full-text + faceted search, multi-tenancy, RBAC, JWT auth, tiered licensing.
- **Deploy** — Docker Compose, Helm chart, and Kubernetes manifests; Prometheus metrics, health probes, structured logs.
