# Licensing

Citadel is **open-core**.

- **Source code: MIT** ([`LICENSE`](https://github.com/sltcnb/citadel/blob/main/LICENSE)).
  Run, modify, and self-host all of it. The standalone tools under `tools/` and
  the shared `contracts/` + `citadel_contracts` are MIT with no gating.
- **Commercial license key** (a separate layer) unlocks premium *runtime feature
  tiers* — it is **not** a source-code license and does not restrict the MIT
  grant. No key → Community tier, fully functional within its limits.

| Plan | Cases | Users | Companies | Export | AI assist | S3 archive | Multi-tenant | MSSP UI |
|------|-------|-------|-----------|--------|-----------|------------|--------------|---------|
| community | 3 | 2 | 1 | ✗ | ✗ | ✗ | ✗ | ✗ |
| pro | ∞ | ∞ | 1 | ✓ | ✗ | ✓ | ✗ | ✗ |
| enterprise | ∞ | ∞ | 1 | ✓ | ✓ | ✓ | ✓ | ✗ |
| mssp | ∞ | ∞ | ∞ | ✓ | ✓ | ✓ | ✓ | ✓ |

Source of truth for features: `api/license/models.py` → `PLAN_FEATURES`.
Full detail: [`LICENSING.md`](https://github.com/sltcnb/citadel/blob/main/LICENSING.md).
