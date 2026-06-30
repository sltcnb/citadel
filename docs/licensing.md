# Licensing

Citadel is **source-available and noncommercial**.

- **Source code: PolyForm Noncommercial License 1.0.0**
  ([`LICENSE`](https://github.com/sltcnb/citadel/blob/main/LICENSE)).
  Run, modify, and self-host it for any **noncommercial** purpose (personal,
  research, education, nonprofits, government). This covers the whole repo,
  including the standalone tools under `tools/` and the shared `contracts/` +
  `citadel_contracts`.
- **Commercial use requires prior written authorization signed by the copyright
  holder.** Any signed written grant (letter or agreement) suffices — it need
  not be a formal commercial-license contract. No commercial use is permitted
  without it — contact the copyright holder to request authorization.
- **Commercial license key** (a separate runtime layer) unlocks premium
  *runtime feature tiers*. No key → Community tier, fully functional within its
  limits. The key is a runtime feature gate, not a substitute for the signed
  commercial license above.

| Plan | Cases | Users | Companies | Export | AI assist | S3 archive | Multi-tenant | MSSP UI |
|------|-------|-------|-----------|--------|-----------|------------|--------------|---------|
| community | 3 | 2 | 1 | ✗ | ✗ | ✗ | ✗ | ✗ |
| pro | ∞ | ∞ | 1 | ✓ | ✗ | ✓ | ✗ | ✗ |
| enterprise | ∞ | ∞ | 1 | ✓ | ✓ | ✓ | ✓ | ✗ |
| mssp | ∞ | ∞ | ∞ | ✓ | ✓ | ✓ | ✓ | ✓ |

Source of truth for features: `api/license/models.py` → `PLAN_FEATURES`.
Full detail: [`LICENSING.md`](https://github.com/sltcnb/citadel/blob/main/LICENSING.md).
