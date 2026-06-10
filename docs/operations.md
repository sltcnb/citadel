# Operations

## Resource allocation (auto, from a global config)

`scripts/allocate_resources.py` detects the **real** host RAM/CPU, applies the
policy in `config/resources.yaml`, and writes a Helm values overlay
(`charts/citadel/values-resources.generated.yaml`).

Policy knobs (`config/resources.yaml`):

| Key | Meaning |
|-----|---------|
| `total.memory` / `.cpu` | hard ceiling, or `auto` to use the host |
| `total.storage` | total persistent storage to divide among stateful services |
| `max_pct_of_host` | **admin cap** — the most of the host Citadel may use (the box may run other workloads) |
| `headroom_pct` | fraction of the admitted budget reserved for OS/kube |
| `weights` | relative compute share per service (hot workers get more) |
| `storage_weights` | per-service share of `total.storage` |

```bash
scripts/allocate_resources.py --print
# Host: 36.0Gi RAM, 12 CPU → allocatable 28.8Gi / 9.6 CPU
# (set max_pct_of_host: 50 to box Citadel into half the host)
```

The allocator never over-commits: a config that *claims* more than the host has
is capped to the host, with a warning.

## Ingress / FQDN

Single FQDN, frontend at `/` and API at `/api`, traefik websecure + TLS + an
http→https redirect (mirrors the original layout). Configure under `ingress.*`:

```yaml
ingress:
  enabled: true
  className: traefik
  fqdn: citadel.example.com
  entrypoint: websecure
  redirectHttp: true
  tls: { enabled: true, secretName: citadel-tls }
```

## Observability

Every worker exposes (via `observability.py`): structured **JSON logs**, a
**Prometheus** `/metrics` endpoint, and `/healthz` + `/readyz`.

## Admin log viewer

Tools ship capped per-service JSON log streams to Redis
(`citadel:logs:<service>`). Admins read them via the API:

```
GET /api/v1/admin/logs/services          # which tools have logs
GET /api/v1/admin/logs/processor?limit=200&level=ERROR
```

Anvil per-run analyzer logs remain at `fo:module_log:<run_id>` (modules API).

## Tools pulled on deploy

`tools/versions.yaml` pins each tool to a ref; `scripts/fetch_tools.sh` clones/
checks them out at deploy time (skips vendored + unreachable cleanly).
