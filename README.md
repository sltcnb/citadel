# Citadel

A DFIR platform that composes standalone forensic tools into one case workflow: acquire, ingest, parse, normalize, detect, analyze, enrich and report.

Each stage is its own repository with its own CLI and its own tests. Citadel pins a tested set of them and wires them together over shared contracts. You can run the whole platform, or take one tool and ignore the rest.

## The pipeline

```
Talon ──▶ Sluice ──▶ Babel ──▶ Rosetta ──▶ Elasticsearch
                                              │
                        ┌─────────────────────┼─────────────────────┐
                        ▼                     ▼                     ▼
                      Sigil                 Anvil                 Augur
                    (detect)             (analyze)              (enrich)
                        └─────────────────────┼─────────────────────┘
                                              ▼
                                      Pilot ──▶ Scribe
                                  (investigate)  (report)
```

| Stage | Tool | Does |
|---|---|---|
| Acquire | [talon](https://github.com/sltcnb/talon) | Live or dead-box collection on Windows, Linux and macOS into a hash-verified ZIP. gRPC remote agent over mTLS. |
| Intake | [sluice](https://github.com/sltcnb/sluice) | Identifies and deduplicates each artifact, routes it to a parser. |
| Parse | [babel](https://github.com/sltcnb/babel) | 51 parser packs: EVTX, MFT, Registry, plist, PCAP, browsers, macOS triage, cloud audit. |
| Normalize | [rosetta](https://github.com/sltcnb/rosetta) | Maps everything to ECS v8 and OSSEM through config-driven field maps. |
| Detect | [sigil](https://github.com/sltcnb/sigil) | 231 native rules plus Sigma and YARA over the timeline. |
| Analyze | [anvil](https://github.com/sltcnb/anvil) | Sandboxed runner for capa, FLOSS, oletools, PE triage, chained in a DAG. |
| Enrich | [augur](https://github.com/sltcnb/augur) | IOCs to scored, sourced STIX 2.1 via OTX, AbuseIPDB, GreyNoise, Shodan, URLhaus, MISP. |
| Investigate | [pilot](https://github.com/sltcnb/pilot) | LLM agent that forms hypotheses, pivots, and cites its evidence. |
| Report | [scribe](https://github.com/sltcnb/scribe) | Case data to Markdown, HTML or DOCX. |
| Contracts | [citadel-contracts](https://github.com/sltcnb/citadel-contracts) | The schemas and plugin contracts all of the above share. |

## Running it

```bash
make dev
```

That generates a `.env` with fresh secrets on first run and brings the stack up with Docker Compose: Elasticsearch, Kibana, Redis, MinIO, the FastAPI backend, ingest and module workers, and the React frontend.

```bash
make dev-down          # stop
make logs-api          # follow a service
make shell-api         # shell into the API container
make reload-plugins    # pick up parser changes without a rebuild
```

## Deploying

```bash
make deploy            # ./foctl deploy k8s
make status
make destroy
```

Kubernetes manifests are in [`k8s/`](k8s/), Helm charts in [`charts/`](charts/), and there is a Traefik compose file for a reverse-proxied deployment. `foctl` is the operations CLI.

## Stack

FastAPI and Celery on the backend, React 19 with Vite and Tailwind on the frontend, Elasticsearch for the timeline, Redis for the bus and queues, MinIO for evidence blobs.

## How the tools are wired

[`tools/SUITE.yaml`](tools/SUITE.yaml) indexes every tool, its role and its status. [`tools/versions.yaml`](tools/versions.yaml) pins each one at a tested ref, and `scripts/fetch_tools.sh` clones or checks out that ref.

All ten tools are currently `vendored: true`, meaning they live in-tree here and `fetch_tools.sh` skips them. Externalising one with `--force` needs its pinned ref to exist as a tag in its own repo, which is not yet the case.

Every tool declares its surface in a `brick.yaml`: what it consumes, what it produces, what it depends on, and how to health-check it. Nothing talks to anything except through the schemas in [`contracts/`](contracts/).

## Development

```bash
pytest -q                       # backend
cd frontend && npm test         # frontend
```

CI runs lint (Python, frontend, Dockerfiles, YAML), tests on 3.11 and 3.12, a CVE scan, and CodeQL.

## License

[PolyForm Noncommercial 1.0.0](LICENSE). Run, modify and self-host it for any noncommercial purpose. Commercial use needs written authorization from the copyright holder; see [LICENSING.md](LICENSING.md).

This is a source-available license, not an OSI-approved open source license.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).
