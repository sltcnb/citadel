# Roadmap

This page summarizes the delivery plan. The authoritative source is the root [`ROADMAP.md`](https://github.com/sltcnb/citadel/blob/main/ROADMAP.md) (the prior codebase-improvement roadmap is preserved in `ROADMAP.legacy.md`).

## The five phases

### Phase 1 — Hardening (Weeks 1-3)
CI (ruff/mypy/eslint/hadolint/yamllint; pytest+cov, testcontainers, mock LLMs; buildx multi-arch, trivy/pip-audit/npm-audit, syft SBOM, kubeconform). Tests (hot-path unit, Babel golden-files, one integration pipeline, one Playwright path; fail-on-decrease). Packaging (pyproject + MIT LICENSE + topics per tool; `charts/citadel` Helm; MkDocs + ADRs + per-tool README + `brick.yaml`).

### Phase 2 — Pipeline & detection tools (Weeks 4-6)
Talon: ArtifactCollector interface + gRPC remote agent (chunked/resumable/encrypted). Sluice: route every built input row + bus emit + idempotent re-ingest. Babel + Rosetta: MIME decls + golden tests; consolidate ECS/OSSEM mapping into Rosetta; standalone CLI + daemon. Anvil: typed analyzer interface + result schema + 12 retrofits. Sigil: CI + sample corpus + grow rules. Augur: 5+ sources + confidence scoring + STIX export + cache.

### Phase 3 — Domain tools (Weeks 7-9) — *built outside this repo*
Nimbus (new): AWS/Azure/GCP read-only collection + posture detections. Warden (new): 7-IdP audit + cross-provider attack-path graph. Promote one of Wraith/Wiretap/Scribe to a polished standalone repo. These domain tools live in the sibling `../domain-tools/` folder, each its own repo; Citadel consumes their output over the shared contracts.

### Phase 4 — Profile & visibility (Weeks 1-10)
Profile README, tool-suite table, blog series, distribution (LinkedIn, r/netsec, r/DFIR, Awesome-DFIR, meetup talk). English only; commit regularly.

## 10-week timeline

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
