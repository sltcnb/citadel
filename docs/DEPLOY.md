# Deploying Citadel by hand

`./foctl deploy {docker|k8s|k8s-new|helm}` covers the common paths (see the README Quickstart). This page documents Helm-by-hand, ingress options, and SSO.

## Helm / Kubernetes by hand

The umbrella chart `charts/citadel` deploys the **app only** (api + processor + frontend); point it at existing Elasticsearch / Redis / MinIO, or set `--set elasticsearch.enabled=true` (etc.) to let Helm run them.

```bash
# build (native arch) + make images visible to the cluster
docker build -t citadel-api:1.0.0       -f api/Dockerfile .
docker build -t citadel-processor:1.0.0 -f tools/sluice/worker/Dockerfile .
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

## Ingress

`ingress.className`: `traefik` (default; TLS + http→https redirect) · `tailscale` (`--set ingress.tls.enabled=false`) · `nginx`/other (Traefik-only bits skipped) · or `--set ingress.enabled=false` and route your own Ingress to `citadel-frontend:80` (`/`) and `citadel-api:8000` (`/api`).

## SSO (Google / Microsoft)

Off until configured. Set provider client id/secret plus `SSO_REDIRECT_BASE`, optional `SSO_ALLOWED_DOMAINS`, `SSO_DEFAULT_ROLE`, `SSO_AUTO_PROVISION`, and redeploy. Register the redirect URI `{SSO_REDIRECT_BASE}/api/v1/auth/sso/{google|microsoft}/callback`. The platform verifies the provider's `id_token` against its JWKS before issuing a session.

## Troubleshooting

Elasticsearch takes ~1–2 min to go healthy on first start; pods pending/crashlooping → `kubectl -n <ns> describe pod <p>`; service logs via `./foctl logs api` or `GET /api/v1/admin/logs/{service}`.
