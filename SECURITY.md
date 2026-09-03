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
  examples. The API refuses to start when the MinIO credentials are unset or
  left at the well-known `minioadmin` default; `./foctl deploy` generates
  strong ones. `CITADEL_ALLOW_DEFAULT_MINIO_CREDS=true` overrides that check
  and should never be set outside a throwaway environment.
- **Do not disable authentication** (`AUTH_ENABLED=false`) outside an isolated,
  trusted lab; it grants unrestricted admin to every request.
- **Review transport encryption.** Browser-facing traffic is TLS by default,
  but traffic to the bundled Elasticsearch, Redis and MinIO is plaintext until
  those services carry certificates — service credentials and evidence bytes
  cross the pod network in the clear. See
  [`docs/security-transport.md`](docs/security-transport.md) for what is
  encrypted, and for the `transport.*` switches that flip each hop to TLS.
- **Encrypt evidence at rest** by naming an encrypting StorageClass in
  `storage.uploads_storage_class`; the default cluster class often does not.
- **Sandbox the processor.** It executes third-party analysis modules, so
  install a sandbox runtime (gVisor / Kata) and name its RuntimeClass
  (`resources.processor_runtime_class`, or `processor.runtimeClassName` in the
  Helm chart). Without one, a malicious module only has to break standard
  container isolation to reach the node.
- **Consider a plugin trust manifest.** Loading a plugin executes it, and the
  loaders pick candidates by filename glob off a shared writable volume.
  Group/world-writable plugin files are always refused; setting
  `PLUGIN_TRUST_MANIFEST` to a JSON allowlist of `path → sha256` (stored
  *outside* the plugins volume) additionally restricts execution to approved,
  unmodified files. See `tools/citadel_contracts/plugin_trust.py`.
- **Leave the image pruner off.** `maintenance.image_pruner` deploys a
  privileged CronJob with a hostPath mount of `/`, which is a container-escape
  primitive. Prefer kubelet image garbage collection
  (`--image-gc-high-threshold` / `--image-gc-low-threshold`).
- Keep container images up to date; CI runs Trivy and `pip-audit` scans and CVE
  gating on release tags.
- Pin third-party GitHub Actions to a full commit SHA, not a tag or branch.
- **Confine harvest paths.** `HARVEST_MOUNT_ROOTS` (default `/mnt,/data`)
  bounds which worker-side directories a harvest may read. Widen it only to
  directories that genuinely hold evidence.
- **Do not disable TLS verification for collector uploads.** `talon`
  aborts an upload whose certificate does not verify; `--insecure-tls` /
  `FO_INSECURE_TLS=1` overrides that for a known self-signed internal
  endpoint and says so on stderr. It is not a general-purpose flag.
- **CTI feeds always verify TLS** — there is no per-feed opt-out. For an
  internal MISP/TAXII with a private certificate, add its CA to the container
  trust store.

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

### Frontend npm advisories (`npm audit`)

Trivy's lockfile scan suppresses `devDependencies`, so the blocking gate says
nothing about the frontend build toolchain. `npm audit` in `frontend/` is the
tool that sees those, and it is not wired into CI — run it by hand when
touching frontend deps.

Anything that ships to a browser is treated like a runtime CVE: fix it, and
check what the fix actually changes. Note that `@monaco-editor/react` fetches
the editor from a CDN at runtime, so a lockfile bump alone does not change what
users execute — see the version pin in `frontend/src/lib/monacoLoader.js`.

**Currently accepted (dev-only, reviewed 2026-07-27):** a cluster of HIGH
advisories against the eslint toolchain — `eslint`, `@eslint/config-array`,
`@eslint/eslintrc`, `eslint-plugin-react`, `minimatch` — all of which trace to
one root cause, `brace-expansion <= 5.0.7` reached through eslint's transitive
`minimatch@3`. Accepted because:

- It is a linter-only dependency. It never ships, and exploiting it requires
  control over the glob patterns in our own eslint config.
- The forward fix is blocked upstream. It needs eslint 10, and
  `eslint-plugin-react` (7.37.5, the latest release) declares
  `peer eslint@"^3 || … || ^9.7"` — so `npm ci` hard-fails with `ERESOLVE` on
  eslint 10. This is why the Dependabot eslint-10 PRs cannot merge.
- Overriding `brace-expansion` to a patched `^5.0.8` clears `npm audit` to zero
  but **breaks linting** (`TypeError: expand is not a function`) — v5 is
  ESM-only, so `minimatch@3`'s `require()` gets a namespace object instead of a
  function. Do not "fix" it that way; it buys a green scanner and a dead linter.

Re-check when `eslint-plugin-react` ships eslint 10 support, which resolves the
whole cluster in one bump.
