# Transport security

This page covers where Citadel encrypts traffic, where it does not, and how to
close the remaining gaps. It exists because "the datastores are only reachable
inside the cluster" is a network-topology argument, not an encryption one — a
single compromised pod on the same network reads plaintext east-west traffic,
credentials included.

## What is encrypted by default

| Hop | Default | Notes |
| --- | --- | --- |
| Browser → ingress (k8s) | **TLS** | Traefik terminates; `:80` redirects and carries HSTS. `TLSOption citadel-tls` pins TLS 1.2 minimum with AEAD ciphers. |
| Browser → proxy (docker compose) | **TLS** | `nginx/nginx.prod.conf` always serves `:443`. `nginx/tls-bootstrap.sh` generates a self-signed certificate if none is mounted, so HTTPS is never off — see [Certificates](#certificates). |
| Ingress → api / frontend pods | plaintext | Inside the pod network. |
| api / processor → Elasticsearch | plaintext | Basic-auth credentials cross in the clear. |
| api / processor → MinIO | plaintext | S3 signature + evidence bytes cross in the clear. |
| api / processor → Redis | plaintext | `AUTH` password crosses in the clear. |
| Kibana → Elasticsearch | plaintext | `kibana_system` password crosses in the clear. |
| processor → api (finalize chain) | plaintext | `INTERNAL_SERVICE_TOKEN` crosses in the clear. |
| Collector (Talon) → S3 | **TLS, verified** | A certificate that fails to verify aborts the upload unless `--insecure-tls` is passed. |
| API → Kubernetes API | **TLS, verified** | Fails closed if the cluster CA bundle is absent. |

The plaintext rows are the shipped default because the bundled Elasticsearch,
Redis and MinIO manifests serve plaintext, and turning the clients to TLS
without certificates on those services would just break the deployment. None
of it is hardcoded, though — every hop above reads its scheme from
configuration, so a cluster with certificates flips over without code changes.

## Enabling TLS for the datastores

Add a `transport` block to `config.json`:

```json
{
  "transport": {
    "elasticsearch_tls": true,
    "redis_tls": true,
    "minio_tls": true,
    "api_tls": false
  }
}
```

`./foctl deploy` then renders `https://` / `rediss://` and `MINIO_SECURE=true`
into the ConfigMap and the processor Deployment. Each flag is independent, so
you can migrate one datastore at a time.

Setting a flag is the *client* half. Each service also needs a server
certificate, and the clients need to trust its issuer:

- **Elasticsearch** — set `xpack.security.http.ssl.enabled=true` with a
  keystore in `k8s/elasticsearch/statefulset.yaml`, then mount the issuing CA
  into the api, processor and Kibana pods. Kibana additionally needs
  `ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES` and
  `ELASTICSEARCH_SSL_VERIFICATIONMODE=full`.
- **MinIO** — place `public.crt` / `private.key` under `/root/.minio/certs`
  in the MinIO pod. With `minio_tls: true` the clients use HTTPS; a private CA
  must be in the pods' trust store, because the client verifies.
- **Redis** — Redis needs `tls-port` plus cert/key/CA, and `rediss://` on the
  client side.

The practical way to run all of this is cert-manager with a private issuer:
one `Certificate` per service, mounted as a Secret, with the CA added to each
client pod's trust bundle. That is deployment-specific enough that Citadel
does not ship it.

For deployments where per-service certificates are not workable, a service
mesh (Istio, Linkerd) gives the same property with mTLS at the sidecar and
leaves these flags at their defaults.

### Verifying

```sh
# Should refuse a plaintext request once ES serves TLS
kubectl -n <ns> exec deploy/api -- curl -sS http://elasticsearch-service:9200

# Confirm the rendered config
kubectl -n <ns> get configmap api-config -o yaml | grep -E 'ELASTICSEARCH_URL|MINIO_SECURE'
```

`./foctl deploy` prints a warning on every deploy while any datastore hop is
still plaintext, so this never silently becomes the permanent state.

## Certificates

### Docker compose

The proxy serves `:443` unconditionally. On first boot,
`nginx/tls-bootstrap.sh` looks for `nginx/certs/fullchain.pem` +
`nginx/certs/privkey.pem`:

- **Present** — used as-is.
- **Absent** — a self-signed certificate is generated. Browsers warn, and the
  certificate does not authenticate the server, but traffic is still encrypted
  against a passive observer. Replace it before going live.

`nginx/certs/` is gitignored — never commit certificates or keys.

If TLS is terminated by a proxy you already run in front of the stack, mount
`nginx/nginx.behind-proxy.conf` instead of `nginx.prod.conf` and bind
`PROXY_PORT` to loopback so the plaintext listener is not publicly reachable.

### Kubernetes

The ingress expects a `forensics-tls` Secret in the release namespace. Use
cert-manager, or create it directly:

```sh
kubectl -n <ns> create secret tls forensics-tls \
  --cert=fullchain.pem --key=privkey.pem
```

## Evidence at rest

Encryption at rest is a property of the StorageClass, not of the PVC. The
evidence claim therefore names its class explicitly rather than inheriting
whatever the cluster marks as default (often unencrypted `local-path`):

```json
{ "storage": { "uploads_storage_class": "encrypted-ssd" } }
```

Leaving it unset keeps the cluster default and makes `./foctl deploy` warn.

## Evidence integrity

Two behaviours worth knowing about, because both trade a visible failure for a
silent one:

- **Rejected documents fail the ingest job.** Elasticsearch answers `_bulk`
  with HTTP 200 even when individual documents are rejected (mapping conflict,
  field type mismatch). Those rejections raise `ESBulkPartialFailure`, naming
  each dropped document, rather than being logged and swallowed. A job that
  used to "succeed" with missing events now fails — the events were missing
  either way; the difference is whether anyone is told.
- **A timed-out search reports UNKNOWN, not zero.** Anvil's grep module has a
  15-second per-file budget; a pattern that exceeds it records a finding saying
  the result is unknown instead of reporting no matches.

## Collector uploads

`talon`'s presigned upload verifies the endpoint certificate. If verification
fails the upload is **aborted** — it is not retried unverified, because an
attacker who can intercept the connection could otherwise force that downgrade
just by presenting a bad certificate.

For a deliberate upload to an internal S3/MinIO with a self-signed
certificate, pass `--insecure-tls` (or set `FO_INSECURE_TLS=1`). That accepts
an unauthenticated connection for that run and says so on stderr.
