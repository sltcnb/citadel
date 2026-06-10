# Citadel licensing

> **Open-core.** The Citadel **source code is MIT-licensed** (see [`LICENSE`](LICENSE)) —
> run, modify, and self-host all of it. This document describes a **separate
> layer**: a commercial **license-key** system that unlocks premium *runtime
> feature tiers* (pro / enterprise / mssp). It is **not** a source-code license
> and does not restrict the MIT grant. No key → Community tier, fully functional
> within its limits. The standalone tools under `tools/` and the shared
> `contracts/` + `citadel_contracts` are MIT with no key gating.

Citadel gates premium features behind a signed JWT license key.

**No key → Community plan automatically.** One binary, the runtime tier is
whatever the key says. No build-time switch, no compile flag.

## Plans

| Plan        | Cases | Users | Companies | Export | AI assist | S3 archive | Multi-tenant | MSSP UI |
|-------------|-------|-------|-----------|--------|-----------|------------|--------------|---------|
| community   | 3     | 2     | 1         | ✗      | ✗         | ✗          | ✗            | ✗       |
| pro         | ∞     | ∞     | 1         | ✓      | ✗         | ✓          | ✗            | ✗       |
| enterprise  | ∞     | ∞     | 1         | ✓      | ✓         | ✓          | ✓            | ✗       |
| mssp        | ∞     | ∞     | ∞         | ✓      | ✓         | ✓          | ✓            | ✓       |

Custom plug-ins + alert rules are on every plan. Source of truth:
`api/license/models.py` → `PLAN_FEATURES`.

## Env vars (API pod)

| Var | Required | Meaning |
|-----|----------|---------|
| `CITADEL_LICENSE_KEY` | no | Signed JWT (the key). Absent → Community. |
| `CITADEL_LICENSE_SIGNING_KEY` | no | HS256 secret used to verify the JWT. Must match what minted the key. Absent → built-in default (safe only for Community). |

If the JWT signature mismatch, expired, or malformed → silent fallback to
Community + `/api/v1/license/info` reports the rejection reason for the UI.

## Mint a key (operator side)

The generator script lives **outside this repo** so the signing-secret
workflow + minted JWTs never end up in source. Operator keep it private.

```bash
pip install pyjwt

# Perpetual enterprise key
python /path/to/generate_license.py \
    --plan enterprise --org "Acme Corp" --seats 25 \
    --signing-key "$CITADEL_LICENSE_SIGNING_KEY"

# 14-day trial
python /path/to/generate_license.py \
    --plan enterprise --org "Acme" --seats 5 --days 14 \
    --signing-key "$CITADEL_LICENSE_SIGNING_KEY"
```

`--days N` sets the JWT `exp` claim. The API verifies expiry; expired keys
silently downgrade to Community — no operator action needed.

`--features '{"max_companies": 500}'` overrides plan defaults for one-off
contracts. Use sparingly.

## Runtime resolution flow

1. API boot → `api/license/client.py` reads both env vars.
2. JWT decode HS256. Failure (missing, bad sig, expired) → Community + a `message` explaining why.
3. Result cached 10 min so expiry detected promptly.
4. `GET /api/v1/license/info` returns the resolved license.
5. Frontend `LicenseProvider` + `useFeature(name)` gate UI.
6. Backend `require_feature("ai_assist")` FastAPI dependency gates endpoints.
7. `check_case_limit / check_user_limit / check_company_limit` enforce caps.

## Rotate the signing secret

If `CITADEL_LICENSE_SIGNING_KEY` change, **every** previously issued key stop
verifying — all customers silently downgrade to Community. Mint replacements
with the new secret first.

## K8s deployment

Both env vars wired via `api-auth-secret`:
- `k8s/configmaps/api-config.yaml` — Secret stringData fields.
- `k8s/api/deployment.yaml` — `optional: true` so absence ≠ crashloop.

Substituted via `foctl deploy k8s` placeholders `__FO_LICENSE_KEY__` /
`__FO_LICENSE_SIGNING_KEY__`.
