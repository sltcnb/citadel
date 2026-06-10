# Getting Started

Citadel runs three ways: a single tool from its CLI, the pipeline, or the full
platform.

## Run a single tool (standalone)

Every tool is usable on its own — no platform required:

```bash
babel parse Security.evtx -o events.jsonl          # parse one artifact
rosetta normalize events.jsonl --ecs 8.11 -o ecs.jsonl   # → ECS
augur enrich iocs.json -o enriched.stix.json       # enrich IOCs
sigil validate tools/sigil/                    # validate detection rules
```

## Run the platform (Docker Compose)

```bash
cp .env.example .env            # set JWT_SECRET etc.
docker compose --profile full up
# API   → http://localhost:8000/api/v1/health
# Console → http://localhost:8000
```

Profiles: `edge` (Talon only) · `pipeline` (Sluice+Babel+Rosetta+store) · `full` (everything).

## Deploy to Kubernetes (Helm)

```bash
# 1. (optional) pull pinned tool versions
scripts/fetch_tools.sh

# 2. compute resource requests/limits from your host + policy
scripts/allocate_resources.py --print

# 3. install
helm install citadel charts/citadel \
  -f charts/citadel/values-resources.generated.yaml \
  --set ingress.enabled=true --set ingress.fqdn=citadel.example.com
```

See [Operations](operations.md) for resource allocation, ingress/FQDN, and the
admin log viewer; [Testing](testing.md) for the test gate.

## Repository layout

- `api/` + `frontend/` — the Citadel platform (integrator).
- `tools/` — the standalone suite tools + `citadel_contracts` (shared contract).
- `contracts/` — the schemas every tool speaks.
- `charts/citadel/` — Helm · `docs/` — this site · `config/` — runtime config.
