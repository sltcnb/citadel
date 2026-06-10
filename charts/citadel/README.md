# charts/citadel — Citadel umbrella chart

Helm chart for the Citadel DFIR platform: API, processor, and frontend, with optional in-cluster substrate (Elasticsearch, Redis, MinIO).

## Install

```bash
# Lint and render
helm lint charts/citadel
helm template citadel charts/citadel

# Install with external substrate (default — substrate disabled)
helm install citadel charts/citadel \
  --set api.image.tag=1.0.0 \
  --set config.elasticsearchUrl=http://es:9200 \
  --set config.redisUrl=redis://redis:6379/0

# Install with in-cluster substrate (requires the bitnami repo + `helm dependency build`)
helm install citadel charts/citadel \
  --set elasticsearch.enabled=true \
  --set redis.enabled=true \
  --set minio.enabled=true
```

## Values

| Key | Default | Purpose |
|-----|---------|---------|
| `api.image.repository` / `.tag` | `citadel-api` / appVersion | API image |
| `api.ingress.enabled` | `false` | Expose API/console via Ingress |
| `api.livenessProbe` / `.readinessProbe` | `/api/v1/health`, `/api/v1/health/ready` | Health checks |
| `processor.replicaCount` | `1` | Async workers (ingest/modules) |
| `frontend.image.repository` / `.tag` | `citadel-frontend` / appVersion | Console image |
| `elasticsearch.enabled` / `redis.enabled` / `minio.enabled` | `false` | Deploy substrate in-cluster |
| `config.elasticsearchUrl` / `.redisUrl` / `.minioEndpoint` | external | Substrate endpoints when disabled |

Substrate dependencies are conditioned (`*.enabled`) so `helm template` works without pulling them.
