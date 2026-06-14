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

## To get a key, contact me, I might get you a free one
