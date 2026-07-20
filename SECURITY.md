# Security Policy

Citadel is a DFIR platform that handles sensitive forensic evidence, credentials,
and threat intelligence. We take the security of the platform and its users
seriously.

## Supported versions

Security fixes are provided for the latest released `1.x` line and the `main`
branch. Older tags may not receive backports.

| Version | Supported |
|---------|-----------|
| `1.x`   | ✅        |
| `< 1.0` | ❌        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, use one of the following private channels:

- Open a [GitHub Security Advisory](https://github.com/sltcnb/citadel/security/advisories/new)
  (preferred — keeps the report private and lets us collaborate on a fix).
- If you cannot use advisories, contact the maintainers privately through the
  repository owner's profile.

Please include, where possible:

- The affected component (API, worker, a specific tool under `tools/`, frontend,
  or deployment tooling such as `foctl`).
- A description of the issue and its impact (e.g. auth bypass, SSRF, RCE, secret
  disclosure, path traversal, injection).
- Steps to reproduce or a proof of concept.
- The version, commit, or deployment mode (`docker`, `k8s`, `helm`) affected.

## Response process

- We aim to acknowledge new reports within **3 business days**.
- We will provide an initial assessment and a remediation plan once the issue is
  confirmed.
- We will coordinate a disclosure timeline with you and credit you in the
  advisory unless you prefer to remain anonymous.

## Scope and hardening notes

Deployments should follow the hardening guidance in
[`docs/DEPLOY.md`](docs/DEPLOY.md) and [`.env.example`](.env.example). In
particular:

- **Change the default `admin` credentials** immediately; the first sign-in
  forces a password change.
- **Set strong `JWT_SECRET` and `MINIO_SECRET_KEY`** values — never reuse the
  examples.
- **Do not disable authentication** (`AUTH_ENABLED=false`) outside an isolated,
  trusted lab; it grants unrestricted admin to every request.
- Keep container images up to date; CI runs Trivy and `pip-audit` scans and CVE
  gating on release tags.

## Security tooling in CI

The project runs the following automated checks (see `.github/workflows/`):

- **CodeQL** static analysis (Python + JavaScript), including a weekly schedule.
- **Trivy** filesystem and image scanning (HIGH/CRITICAL), with a release gate
  that blocks fixable critical CVEs on tagged releases.
- **pip-audit** against `api/requirements.txt`.
- **SBOM** generation for built images.

### CVE triage process

The `cve-scan` job in `.github/workflows/ci.yml` runs Trivy against the
repository filesystem and **fails the build** on any new HIGH/CRITICAL,
fixable CVE. Existing CVEs that have been reviewed and accepted (e.g. the
vulnerable code path isn't reachable, or a fix is scheduled but blocked on
something else) are allowlisted in [`.trivyignore`](.trivyignore) at the repo
root — that file is the source of truth for what's currently accepted and why.

LOW/MEDIUM severity findings and `pip-audit` stay informational
(`continue-on-error`) — they're surfaced in the job log but never block a PR.

**When the blocking Trivy step fails on a PR:**

1. Confirm the finding is real (not a scanner false-positive) and check
   whether a fixed version is available (`ignore-unfixed: true` already drops
   no-fix-available CVEs from the gate).
2. If it's fixable in the same PR (a routine dependency bump), fix it — that's
   almost always preferred over allowlisting.
3. If it can't be fixed immediately, add an entry to `.trivyignore` with:
   - The **CVE ID**.
   - A one-line **justification**: why it's accepted now (e.g. the vulnerable
     code path is unreachable in Citadel's usage, the component isn't exposed
     to untrusted input, or the fix is tracked but blocked on a compatibility
     constraint).
   - A **review-by date** using the `exp:YYYY-MM-DD` suffix, no more than 90
     days out. Trivy stops honoring the ignore once that date passes, so the
     job goes red again until someone re-triages it (either the fix has
     landed by then, or the entry needs a fresh justification and a new date).
   - A link to a tracking issue if the fix needs code changes beyond a version
     bump.
4. Never widen the allowlist by raising the `severity` threshold in the
   workflow or re-adding `continue-on-error` to the blocking step — the
   allowlist file is the only sanctioned way to unblock a known, accepted CVE.

See `.trivyignore` for the current allowlist and the expected entry format.
