# Installation

`./foctl` drives every deployment. Run it with no arguments for an interactive
menu, or pass a command directly. It handles the fiddly parts for you —
**generating secrets, creating `.env`, building images, and sizing resources** —
so a first install is one command.

```bash
git clone https://github.com/sltcnb/citadel.git && cd citadel
./foctl                       # interactive: pick Docker / Kubernetes
# or go straight to a mode:
./foctl deploy docker
```

Default login after any install: **`admin` / `CitadelAdmin1!`** — you're forced
to set a new password on first sign-in.

| Mode | Command | Best for |
|------|---------|----------|
| **Docker Compose** | `./foctl deploy docker` | laptop, single server, evaluation, air-gapped |
| **Kubernetes** (raw manifests) | `./foctl deploy k8s` | a cluster where Citadel also provisions ES/Redis/MinIO |
| **Kubernetes** (new local k3d) | `./foctl deploy k8s-new` | development, CI, offline labs |
| **Helm** (app-only) | `./foctl deploy helm` | a cluster already running ES/Redis/MinIO + an ingress |

## What foctl automates

- **Secrets** — generates `jwt_secret`, `minio_access_key`, and the internal
  service token into `config.json`, kept **stable across redeploys** (a
  regenerated JWT secret would log everyone out). The one-time admin password is
  surfaced on first deploy.
- **`.env`** — created from `.env.example` on first Docker run.
- **Resource sizing** — `scripts/allocate_resources.py` runs automatically for
  Helm/k8s, detecting real host RAM/CPU and splitting an allocatable pool across
  services per `config/resources.yaml` (respects an admin cap `max_pct_of_host`).
- **Images** — builds for the host's native arch and loads them into the cluster.

You rarely need the manual steps below — they're documented as a fallback.

## Prerequisites

- **Docker** (Compose v2) — Docker mode and image builds.
- **kubectl** + a reachable cluster — Kubernetes / Helm modes.
- **Helm 3** — Helm mode.
- **Python 3** — `foctl` itself.

## Operations

`foctl` auto-detects the mode if you omit it.

```bash
./foctl status                 # service / pod health
./foctl logs api               # stream logs: api | processor | frontend | all
./foctl update                 # rebuild images + redeploy
./foctl destroy                # remove services + data (confirms first)
./foctl config                 # show parsed config.json + redacted .env
```

Kubernetes deploy flags: `--no-build` (re-apply manifests only), `--no-cache`
(force full rebuild), `--restart` (re-apply + restart pods), `--setup-traefik`
(apply kube-system Traefik config — first deploy only).

---

## Manual equivalents (fallback)

### Docker Compose by hand
```bash
cp -n .env.example .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(python3 -c 'import secrets;print(secrets.token_hex(32))')/" .env
docker compose --profile full up -d --build
```
Access `http://localhost` (or the host's LAN/Tailscale name); API docs at
`/api/v1/docs`. Stop with `docker compose down` (`-v` wipes data). Profiles:
`edge` · `pipeline` · `full`.

> Build the host's **native** arch only — emulated cross-arch builds are 10–50× slower.

### Helm by hand
The umbrella chart `charts/citadel` deploys the **app only** (api + processor +
frontend); point it at existing Elasticsearch / Redis / MinIO.

```bash
# 1. build (native) + make images visible to the cluster
docker build -t citadel-api:1.0.0       -f api/Dockerfile .
docker build -t citadel-processor:1.0.0 -f tools/sluice-worker/Dockerfile .
docker build -t citadel-frontend:1.0.0  -f frontend/Dockerfile frontend
#    k3s:  for i in api processor frontend; do docker save citadel-$i:1.0.0 | sudo k3s ctr images import -; done
#    k3d:  k3d image import citadel-{api,processor,frontend}:1.0.0

# 2. (optional) size requests/limits from the real host
python3 scripts/allocate_resources.py        # → charts/citadel/values-resources.generated.yaml

# 3. install against existing substrate
helm upgrade --install citadel charts/citadel -n citadel --create-namespace \
  -f charts/citadel/values-resources.generated.yaml \
  --set-string config.elasticsearchUrl=http://elasticsearch.<ns>:9200 \
  --set-string config.redisUrl=redis://redis-service.<ns>:6379/0 \
  --set-string config.minioEndpoint=minio-service.<ns>:9000 \
  --set-string secret.jwtSecret=$(python3 -c 'import secrets;print(secrets.token_hex(32))') \
  --set-string secret.minioAccessKey=<key> --set-string secret.minioSecretKey=<secret> \
  --set ingress.enabled=true --set-string ingress.fqdn=citadel.example.com \
  --set-string ingress.className=traefik
```

**Ingress** — `ingress.className`: `traefik` (default; TLS + http→https redirect
emitted) · `tailscale` (`--set ingress.tls.enabled=false`, Tailscale terminates
TLS) · `nginx`/other (Traefik-only bits skipped) · or `--set ingress.enabled=false`
and route your own Ingress to `citadel-frontend:80` (`/`) and `citadel-api:8000` (`/api`).

**In-cluster substrate** (heavy — needs RAM) — let Helm run ES/Redis/MinIO:
```bash
helm repo add bitnami https://charts.bitnami.com/bitnami && helm dependency build charts/citadel
helm upgrade --install citadel charts/citadel -n citadel --create-namespace \
  --set elasticsearch.enabled=true --set redis.enabled=true --set minio.enabled=true \
  --set redis.auth.enabled=false --set elasticsearch.security.enabled=false \
  --set-string config.elasticsearchUrl=http://citadel-elasticsearch:9200 \
  --set-string config.redisUrl=redis://citadel-redis-master:6379/0 \
  --set-string config.minioEndpoint=citadel-minio:9000
```

### Tools from per-tool repos (optional)
All tools are vendored in-tree, so a normal install needs nothing extra. To
assemble from per-tool repos instead: `scripts/fetch_tools.sh` (reads
`tools/versions.yaml`, pins each at a ref; skips vendored tools, never blocks on auth).

---

## Post-install

- Set the new admin password at first sign-in (enforced).
- For premium tiers, add a license key (see [Licensing](licensing.md)); no key → Community.

## Troubleshooting

- Pods pending / crashlooping: `kubectl -n <ns> describe pod <p>` + `kubectl -n <ns> logs <p>`.
- API not ready: Elasticsearch takes ~1–2 min to go healthy on first start.
- Helm app can't reach substrate: confirm the `config.*Url` hosts resolve from the
  namespace (cross-namespace = `svc.<ns>.svc.cluster.local`).
- Service logs: `./foctl logs api` or admin-only `GET /api/v1/admin/logs/{service}`.
- Resource sizing details: see [Operations](operations.md).
