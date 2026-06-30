# Citadel licensing

> **Source-available, noncommercial.** The Citadel **source code is licensed
> under the PolyForm Noncommercial License 1.0.0** (see [`LICENSE`](LICENSE)) —
> run, modify, and self-host it for any **noncommercial** purpose. **Commercial
> use requires prior written authorization signed by the copyright holder (any
> signed written grant — letter or agreement — suffices); no commercial use is
> permitted without it.**
> This covers the whole repo, including the standalone tools under `tools/` and
> the shared `contracts/` + `citadel_contracts`.
>
> Separately, a commercial **license-key** system unlocks premium *runtime
> feature tiers* (pro / enterprise / mssp) at runtime. No key → Community tier,
> fully functional within its limits. The license key is a runtime feature gate;
> it is **not** a substitute for the signed commercial license required for any
> commercial use under the terms above.

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

## Commercial use & keys

Commercial use needs prior written authorization signed by me (see
[`LICENSE`](LICENSE)) — any signed written grant suffices, it need not be a
formal commercial-license contract. To request authorization or a runtime key,
contact me — I might get you a free key for noncommercial use.
