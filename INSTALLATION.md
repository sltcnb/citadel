# Installing & Deploying Citadel

Three ways to run Citadel, all driven by `./foctl` (or do it by hand). Pick one:

| Mode | Command | Best for |
|------|---------|----------|
| **Docker Compose** | `./foctl deploy docker` | laptop, single server, evaluation, air-gapped |
| **Helm** (app-only) | `./foctl deploy helm` | a cluster that already runs ES/Redis/MinIO + an ingress |
| **Kubernetes** (raw manifests) | `./foctl deploy k8s` | a cluster where Citadel should also provision its substrate |

Default login after any install: **`admin` / `CitadelAdmin1!`** — change it immediately (Settings → Users).

---

## Prerequisites

- **Docker** (Compose v2) — for `docker` mode and for building images.
- **kubectl** + a reachable cluster — for `helm` / `k8s` modes.
- **Helm 3** — for `helm` mode.
- Python 3 — `foctl` itself.

---

## Option A — Docker Compose (single host)

```bash
cd citadel
./foctl deploy docker            # creates .env from .env.example, builds, starts
```
Manual equivalent:
```bash
cp -n .env.example .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(python3 -c 'import secrets;print(secrets.token_hex(32))')/" .env
docker compose --profile full up -d --build
```
Access: `http://localhost` (or the host's Tailscale/LAN name). API docs `/api/v1/docs`.
Stop: `docker compose down` (add `-v` to wipe data). Profiles: `edge` | `pipeline` | `full`.

> Build the host's **native** arch only. Don't `docker buildx --platform linux/amd64,linux/arm64` locally — emulated arch is 10-50× slower.

---

## Option B — Helm (bring-your-own substrate)

The umbrella chart `charts/citadel` deploys the **app only** (api + processor + frontend). Point it at existing **Elasticsearch / Redis / MinIO**.

### With foctl (recommended)
Edit `config.json` (from `config.json.example`) — set `release`, `access.hostname`, `access.ingress_class`, the `substrate.*` URLs, and `secrets.*`:
```bash
./foctl deploy helm              # builds images, imports to cluster, helm upgrade --install
./foctl status helm
./foctl destroy helm
```

### By hand
```bash
# 1. build (native) + make images visible to the cluster
docker build -t citadel-api:1.0.0       -f api/Dockerfile .
docker build -t citadel-processor:1.0.0 -f tools/sluice-worker/Dockerfile .
docker build -t citadel-frontend:1.0.0  -f frontend/Dockerfile frontend
#    k3s:  for i in api processor frontend; do docker save citadel-$i:1.0.0 | sudo k3s ctr images import -; done
#    k3d:  k3d image import citadel-{api,processor,frontend}:1.0.0
#    registry: push, and pass --set global.image.registry=<registry>/

# 2. (optional) size requests/limits from the real host + your policy
python3 scripts/allocate_resources.py        # → charts/citadel/values-resources.generated.yaml

# 3. install (reuse existing substrate; example points at another namespace)
helm upgrade --install citadel charts/citadel -n citadel --create-namespace \
  -f charts/citadel/values-resources.generated.yaml \
  --set-string api.image.repository=citadel-api \
  --set-string processor.image.repository=citadel-processor \
  --set-string frontend.image.repository=citadel-frontend \
  --set-string config.elasticsearchUrl=http://elasticsearch.<ns>:9200 \
  --set-string config.redisUrl=redis://redis-service.<ns>:6379/0 \
  --set-string config.minioEndpoint=minio-service.<ns>:9000 \
  --set-string secret.jwtSecret=$(python3 -c 'import secrets;print(secrets.token_hex(32))') \
  --set-string secret.minioAccessKey=<key> --set-string secret.minioSecretKey=<secret> \
  --set ingress.enabled=true --set-string ingress.fqdn=citadel.example.com \
  --set-string ingress.className=traefik
```

### Ingress (Traefik / Tailscale / nginx)
- **Traefik** (default): `--set-string ingress.className=traefik` — TLS entrypoint + http→https redirect middleware are emitted.
- **Tailscale operator**: `--set-string ingress.className=tailscale --set ingress.tls.enabled=false` (Tailscale terminates TLS; the Traefik middleware is skipped).
- **nginx / other**: set `ingress.className` accordingly; Traefik-only bits are skipped.
- **Bring your own**: `--set ingress.enabled=false` and route your own Ingress to `citadel-frontend:80` (`/`) and `citadel-api:8000` (`/api`).

### In-cluster substrate (optional)
To let Helm run ES/Redis/MinIO instead of reusing existing ones (heavy — needs RAM):
```bash
helm repo add bitnami https://charts.bitnami.com/bitnami && helm dependency build charts/citadel
helm upgrade --install citadel charts/citadel -n citadel --create-namespace \
  --set elasticsearch.enabled=true --set redis.enabled=true --set minio.enabled=true \
  --set redis.auth.enabled=false --set elasticsearch.security.enabled=false \
  --set-string config.elasticsearchUrl=http://citadel-elasticsearch:9200 \
  --set-string config.redisUrl=redis://citadel-redis-master:6379/0 \
  --set-string config.minioEndpoint=citadel-minio:9000
```

---

## Option C — Kubernetes (raw manifests, provisions substrate)

```bash
./foctl deploy k8s               # edit config.json first (hostname, namespace, secrets)
./foctl deploy k8s-new           # create a local k3d cluster, then deploy
./foctl deploy k8s --no-build    # skip image build
./foctl status k8s   /   ./foctl logs api k8s   /   ./foctl destroy k8s
```
This path applies `k8s/` (namespace, storage, redis, minio, elasticsearch, kibana, api, processor, frontend, ingress) — it brings its own ES/Redis/MinIO.

---

## Resource allocation

`scripts/allocate_resources.py` detects the **real** host RAM/CPU and splits an allocatable pool across services per `config/resources.yaml` (incl. an admin cap `max_pct_of_host`), emitting a Helm values overlay. See [docs/operations.md](docs/operations.md).

## Tools pulled on deploy (optional)

All tools are vendored in-tree, so you don't need this for a normal install. To assemble from per-tool repos instead: `scripts/fetch_tools.sh` (reads `tools/versions.yaml`, pins each tool at a ref). Skips vendored tools and never blocks on auth.

---

## Post-install

- Change the admin password.
- Set a strong `JWT_SECRET` (compose `.env`) / `secret.jwtSecret` (helm) — otherwise sessions reset on restart/upgrade.
- For premium tiers, add a license key (see [LICENSING.md](LICENSING.md)); no key → Community.

## Troubleshooting

- Pods pending/crashlooping: `kubectl -n <ns> describe pod <p>` + `kubectl -n <ns> logs <p>`.
- API not ready: Elasticsearch takes ~1-2 min to go healthy first.
- Helm app can't reach substrate: verify the `config.*Url` hosts resolve from the namespace (cross-namespace = `svc.<ns>.svc.cluster.local`).
- Worker/tool logs for an admin: `GET /api/v1/admin/logs/{service}` or `./foctl logs api`.
