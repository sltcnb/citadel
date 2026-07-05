# Talon — Acquisition Agent

> Acquire a host's forensic story — live or dead-box — into one signed, hash-verified bundle.

**Status: built** — live and dead-box collection across Windows, Linux, and macOS; gRPC remote agent (mTLS) and S3/MinIO upload paths.

Talon is the first stage of the pipeline: it walks a host (or a mounted image / raw device) and gathers forensic artifacts into a portable **artifact bundle**. It owns the per-OS artifact catalog — 56 Windows categories, 21 Linux, 12 macOS — and is the *source of truth* for what is collectable; Citadel renders its collection UI straight from Talon's `capabilities.yaml` and holds no artifact knowledge of its own.

## Pipeline position

```
Talon ──bundle──▶ Sluice ──▶ Babel ──▶ Rosetta ──▶ …
```

First node. Runs on the endpoint (live) or against a mount/device (dead-box), and hands a bundle to **Sluice**.

## Inputs → Outputs

- **Inputs** — a live host filesystem, a mounted volume (dead-box), or a raw block device (optionally with a BitLocker recovery key); plus the artifact categories to gather. No bus/stdin input.
- **Output** — an **artifact bundle** conforming to `contracts/bundle_manifest/v1.json`:
  ```
  bundle/  manifest.json | events.jsonl | blobs/<sha256> | bundle.sha256
  ```
  `manifest.json` carries `session_id`, `hostname`, `os`, timestamps, and an `artifacts[]` list with per-file `sha256` / `size` / `category`.

## Contracts

Sourced from `brick.yaml`; all contracts are versioned in the [citadel-contracts](https://github.com/sltcnb/citadel-contracts) repo (`pip install git+https://github.com/sltcnb/citadel-contracts`).

- **Consumes** — nothing from the bus (`content_types: []`); Talon reads live hosts, mounts, and raw devices.
- **Produces** — `contracts/bundle_manifest/v1.json` (the artifact bundle manifest), any artifact type (~80 categories).
- **Speaks** — `contracts/collector.proto` (`citadel.collector.v1.Collector` gRPC service) for the remote agent path.

## Install

```bash
git clone https://github.com/sltcnb/talon && cd talon
pip install -e .            # provides the `talon` console script (collect:main); Python >= 3.11
```

Runtime is stdlib-only (`dependencies = []` in `pyproject.toml`); `requirements-build.txt` only carries PyInstaller for the `build.sh` / `build.bat` single-binary builds. boto3 is optional for the credentialed S3 path in `fo_uploader.py`.

## Configuration

No operator environment variables — Talon is configured via CLI flags, optionally merged over a `config.json` shipped next to the script (embedded-config mode for packaged agents; CLI always wins). The Windows OS variables it reads (`SystemDrive`, `SystemRoot`, `ProgramData`) only locate artifacts on the target host.

## Run standalone

```bash
talon                                              # all OS defaults, live host
talon --collect evtx,registry,prefetch             # selective live collection
talon --path /mnt/windows --collect registry,evtx  # dead-box: mounted volume
talon --disk /dev/sdb1 --bitlocker-key 123456-...  # dead-box: raw device + BitLocker
talon --output /tmp/evidence.zip                   # write a local ZIP
talon --api-url http://citadel/api/v1 --case-id IR-001 --api-token <tok>   # upload to a case
talon --fetch "mimikatz*" --fetch "re:\.(ps1|hta)$" --fetch-root C:\Users  # IOC file sweep
talon --dry-run --verbose                          # preview, collect nothing
```

Key flags: `--collect` (comma-separated categories), `--path` / `--disk` / `--bitlocker-key` (dead-box), `--output`/`-o`, `--api-url` / `--case-id` / `--api-token` (Citadel upload), `--fetch` / `--fetch-root` / `--fetch-max-files` / `--fetch-max-mb` (filename or `re:` regex search), `--bundle-manifest`, `--skip-problematic`, `--dry-run`, `--verbose`/`-v`.

When `--collect` is omitted the OS default set is used (e.g. Windows: evtx, registry, prefetch, lnk, browser, tasks, mft, triage, sysmon, antivirus).

Health check (declared in `brick.yaml`): `talon --version`.

## Tests

```bash
pytest tests/                       # test_chunker, test_secure_upload, test_stability
python3 tests/test_chunker.py       # each file also runs standalone
```

## Remote agent (gRPC / mTLS)

For fleet collection, Talon speaks the `citadel.collector.v1.Collector` gRPC service (`contracts/collector.proto`):

- **Register / Heartbeat** — the agent enrolls and the server pushes collection tasks.
- **UploadChunk** — resumable 8 MiB chunked upload with per-chunk SHA-256, optional AES-256-GCM sealing (X25519 ECDH → HKDF-SHA256, chunk offset as AAD). On reconnect the client resumes from `bytes_received`.

Bundles can also land in **S3/MinIO** via presigned URLs (stdlib-only) or credentialed boto3 (`fo_uploader.py`).

## In Citadel

Talon's bundle is the unit Sluice consumes. In-app **Harvest** runs Talon server-side against a mounted image/path; the standalone agent uploads to a case over the API or gRPC. Editing `capabilities.yaml` (e.g. adding a collection category) changes the Citadel collector UI with no orchestrator code change.

## Part of the Citadel suite

Talon is the acquisition stage — the first node — of [Citadel](https://github.com/sltcnb/citadel). Upstream: none. Downstream (`brick.yaml` dependency): [Sluice](https://github.com/sltcnb/sluice), which receives bundles via gRPC or upload token. Contracts (`bundle_manifest`, `collector.proto`): [citadel-contracts](https://github.com/sltcnb/citadel-contracts).
