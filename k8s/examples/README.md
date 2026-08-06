# k8s/examples — site-specific reference manifests (NOT applied by foctl)

These files are leftovers from a specific installation. They are **not** part of
`foctl`'s APPLY_ORDER and are never applied automatically — namespaces and
settings inside them (e.g. `citadel-dev`, `traefik-system`, the Tailscale
`csirt-gateway` LoadBalancer) are site-specific examples only.

- `middleware-no-buffering.yaml` — Traefik Middleware that disables request
  buffering for large uploads. Adapt the namespace and reference it from an
  Ingress annotation if you need it.
- `traefik-timeouts.yaml` — notes/sketch for raising Traefik entrypoint
  timeouts for large uploads (the ConfigMap is inert; see the comments inside).
- `traefik-config-updated.yaml` — k3s `HelmChartConfig` for Traefik with long
  timeouts and a Tailscale LoadBalancer. Apply only with
  `./foctl deploy k8s --setup-traefik`-style manual review; it restarts Traefik.
