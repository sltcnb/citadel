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
