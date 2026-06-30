# Sigil — Detection Engine

> Mark the malicious: match Sigma + native rules and YARA against the normalized timeline.

**Status: partial** (rule corpus + validate/convert/coverage tooling built; full match daemon pending).

Sigil is the detection layer. It evaluates Citadel-native Lucene-style rules and SigmaHQ rules (converted to Elasticsearch queries) against ECS-shaped events, plus YARA signatures against case files. It ships a built-in rule library organised by ATT&CK tactic, a Sigma→ES converter, and an ATT&CK coverage matrix.

## Pipeline position

```
Rosetta ──ECS events──▶ Sigil ──detections──▶ timeline / alert-rules / webhooks
```

Detect stage: consumes the normalized event stream, produces detections.

## Inputs → Outputs

- **Inputs** — ECS event stream (NDJSON, `contracts/forensic_event/v1.json`) + rule packs.
- **Outputs** — detections (emitted as forensic events) + `coverage_matrix.{json,md}` (ATT&CK tactic/technique breakdown).
- **Dependencies** — Elasticsearch (query backend for Sigma→ES evaluation).

## Rule library

- **27 native packs** by ATT&CK tactic — `01_anti_forensics.yaml` … `27_cloud_saas.yaml` (anti-forensics, authentication, privilege escalation, persistence, execution, lateral movement, defense evasion, credential access, discovery, C2, exfiltration, initial access, impact, plus Sysmon/browser/registry/prefetch/MFT/LNK/Zeek/PowerShell/container/cloud-specific packs).
- **SigmaHQ imports** under `sigma_hq/` (execution, persistence, discovery, collection, exfiltration, impact, other).
- `coverage_matrix.json` / `.md` — generated ATT&CK coverage.

## Run standalone

The tools are plain Python scripts (run directly; the `sigil` health command wraps `sigil_validate.py`):

```bash
python sigil_validate.py            # validate every rule: schema, required fields, unique UUIDs, query/condition lint
python sigil_validate.py --quiet    # summary only
python sigil_validate.py rule.yaml  # validate specific file(s)
python sigil_convert.py             # convert the corpus to ES queries; report native/sigma/failure tallies
python sigil_coverage.py            # regenerate coverage_matrix.{json,md}
```

`sigil_match.py` is the offline Lucene-subset matcher used by the rule tests against the `sample_events/` corpus.

## In Citadel

The platform converts Sigma to ES queries, runs the rule library against a case timeline, and surfaces matches as detections (with runtime per-case opt-out and an ATT&CK coverage view). Native and imported rules are managed under the Detection Rules and YARA Rules surfaces.

See `../../contracts/forensic_event.schema.json`.
