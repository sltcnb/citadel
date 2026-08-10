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

## Elasticsearch / Kibana passwords

On a first deploy foctl generates `es_password` (the built-in `elastic`
superuser) and `kibana_password` (the built-in `kibana_system` user) into
`config.json`'s `secrets` block — stable across redeploys — and substitutes them
into `elasticsearch-secret`. After ES first reports ready, foctl also sets the
`kibana_system` password inside ES via the `_security` API, which is what lets
the Kibana pod connect (nothing else ever sets that password).

## Kibana dashboards

`k8s/kibana/citadel-dashboards.ndjson` ships two data views (`fo-case-*`, plus
a detections/findings view) and a starter dashboard (events over time,
detections by level, top artifact types). Import after deploy:

```sh
PW=$(kubectl -n citadel get secret elasticsearch-secret -o jsonpath='{.data.elastic_password}' | base64 -d)
kubectl -n citadel port-forward svc/kibana-service 5601:5601 &
curl -u "elastic:$PW" -X POST "http://localhost:5601/kibana/api/saved_objects/_import?overwrite=true" \
     -H "kbn-xsrf: true" -F file=@k8s/kibana/citadel-dashboards.ndjson
```

(Regenerate with `python3 scripts/build_kibana_assets.py` if you edit it.)

Docker mode gets the same treatment via `.env`: `ELASTIC_PASSWORD` /
`KIBANA_PASSWORD` are generated on first `./foctl deploy docker` (or
`./foctl ensure-env`), and foctl sets the `kibana_system` password once the
stack is up.

**Rotating (k8s):** note that `ELASTIC_PASSWORD` is only a *bootstrap* value —
changing `es_password` in `config.json` does not change the password inside an
existing ES data volume. To rotate:

```bash
# 1. set the new password inside ES
kubectl exec -n <ns> elasticsearch-0 -- sh -c \
  'curl -sf -u "elastic:$ELASTIC_PASSWORD" -X POST \
   http://localhost:9200/_security/user/elastic/_password \
   -H "Content-Type: application/json" -d "{\"password\": \"NEW_VALUE\"}"'
# 2. put NEW_VALUE in config.json secrets.es_password and redeploy
./foctl deploy k8s --no-build
```

Rotate `kibana_password` the same way against
`_security/user/kibana_system/_password`, then redeploy (foctl re-sets it on
every deploy, so a redeploy alone heals drift).

## SSO (Google / Microsoft)

Off until configured. Set provider client id/secret plus `SSO_REDIRECT_BASE`, optional `SSO_ALLOWED_DOMAINS`, `SSO_DEFAULT_ROLE`, `SSO_AUTO_PROVISION`, and redeploy. Register the redirect URI `{SSO_REDIRECT_BASE}/api/v1/auth/sso/{google|microsoft}/callback`. The platform verifies the provider's `id_token` against its JWKS before issuing a session.

## Troubleshooting

Elasticsearch takes ~1–2 min to go healthy on first start; pods pending/crashlooping → `kubectl -n <ns> describe pod <p>`; service logs via `./foctl logs api` or `GET /api/v1/admin/logs/{service}`.
