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

## Run standalone

`pip install -e .` provides the `talon` console script (`collect:main`).

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

Key flags: `--collect` (comma-separated categories), `--path` / `--disk` / `--bitlocker-key` (dead-box), `--output`/`-o`, `--api-url` / `--case-id` / `--api-token` (Citadel upload), `--fetch` / `--fetch-root` (filename or `re:` regex search), `--bundle-manifest`, `--dry-run`, `--verbose`/`-v`, `--version`.

When `--collect` is omitted the OS default set is used (e.g. Windows: evtx, registry, prefetch, lnk, browser, tasks, mft, triage, sysmon, antivirus).

## Remote agent (gRPC / mTLS)

For fleet collection, Talon speaks the `citadel.collector.v1.Collector` gRPC service (`contracts/collector.proto`):

- **Register / Heartbeat** — the agent enrolls and the server pushes collection tasks.
- **UploadChunk** — resumable 8 MiB chunked upload with per-chunk SHA-256, optional AES-256-GCM sealing (X25519 ECDH → HKDF-SHA256, chunk offset as AAD). On reconnect the client resumes from `bytes_received`.

Bundles can also land in **S3/MinIO** via presigned URLs (stdlib-only) or credentialed boto3 (`fo_uploader.py`).

## In Citadel

Talon's bundle is the unit Sluice consumes. In-app **Harvest** runs Talon server-side against a mounted image/path; the standalone agent uploads to a case over the API or gRPC. Editing `capabilities.yaml` (e.g. adding a collection category) changes the Citadel collector UI with no orchestrator code change.

See `../../contracts/bundle_manifest.schema.json` and `../../contracts/collector.proto`.
