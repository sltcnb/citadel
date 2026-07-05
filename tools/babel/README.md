# Babel — Parser Library

> Many tongues, one event: turn any forensic artifact into a normalized `ForensicEvent`.

**Status: built** — 40+ parser packs across Windows, Linux, macOS, mobile, network, cloud, container, and generic formats.

Babel is a pure parser library. Each parser is a `BasePlugin` subclass that reads a raw artifact and yields `ForensicEvent` dicts (required `timestamp` + `message`; structured types carry their `raw` record). It has no dependencies on the rest of the suite — it runs standalone or inside Sluice.

## Pipeline position

```
Sluice ──routes a file──▶ Babel ──ForensicEvent──▶ Rosetta ──ECS──▶ store / detect / analyze
```

## Inputs → Outputs

- **Inputs** — any raw artifact (`.evtx`, registry hives, `.lnk`, `.pf`, `.plist`, `.pcap`/Zeek/Suricata, browser profiles, syslog, auditd, container/k8s logs, cloud audit, Android/iOS, disk images, …). Parser selection is content-sniffed.
- **Outputs** — a `ForensicEvent` JSONL stream (`contracts/forensic_event/v1.json`), one event per line, tagged with an `artifact_type` from the ~90-entry taxonomy.

## Parser discovery & routing

No registry. The loader scans the built-in packs plus any custom-ingester directory for `BasePlugin` subclasses. Each parser declares `PLUGIN_PRIORITY` (≈100 for a dedicated handler, ≈10 for a generic fallback); the highest-priority parser that matches the content wins. Custom ingesters authored in **Studio** drop in as Python modules and are picked up on the next scan — no edit to any manifest.

Parser packs include: `access_log`, `android`, `antivirus`, `apt_history`, `archive`, `auditd`, `browser`, `cloud_audit` (AWS/Azure/GCP), `crictl`, `dd_image`, `diskimage`, `docker`, `evtx`, `hayabusa`, `ios`, `iptables`, `json_file`, `jumplist`, `k3s`, `k8s_resources`, `lastlog`, `linux_config`, `linux_triage`, `lnk`, `log2timeline`, `macos_uls`, `markofweb`, `mft`, `ndjson`, `netstat`, `notifications`, `pcap`, `plaso`, `plist`, `prefetch`, `recyclebin`, `registry`, `scheduled_task`, `shell_history`, `strings_fallback`, `suricata`, `syslog`, `timestamped_log`, `trend_telemetry`, `utmp`, `wer`, `win_timeline`, `windows_triage`, `wlan_profile`, `zeek`.

## Contracts

From `brick.yaml` (v1.0.0, status **built**):

- **Consumes** — any content type / filename; each parser declares its own `SUPPORTED_MIME_TYPES` and handled filenames.
- **Produces** — schema `https://citadel.dfir/contracts/forensic_event/v1.json` (ForensicEvent v1); artifact types span the ~90-entry taxonomy.
- **Dependencies** — none: pure library, runs standalone or inside Sluice.

The `forensic_event.schema.json` schema and the `BasePlugin` contract are versioned in the `citadel_contracts` package ([github.com/sltcnb/citadel-contracts](https://github.com/sltcnb/citadel-contracts)).

## Install

```bash
pip install git+https://github.com/sltcnb/citadel-contracts   # BasePlugin / ForensicEvent contract
pip install -e .
```

In the monorepo, `base_plugin.py` resolves a sibling `citadel_contracts` checkout automatically; in a standalone clone install it from the repo above.

## Configuration

Only the `dd_image` parser reads the environment (see `dd_image/dd_image_plugin.py`) — every other parser is configured purely by its input and plugin constants:

| Variable | Default | Purpose |
|---|---|---|
| `MINIO_BUCKET` | `forensics-cases` | bucket for extracted-file upload |
| `DD_MAX_EXTRACT_MB` | `500` | per-file extraction cap |
| `MINIO_ENDPOINT` | `minio:9000` | object-store endpoint |
| `MINIO_ACCESS_KEY` | *(empty)* | object-store credentials |
| `MINIO_SECRET_KEY` | *(empty)* | object-store credentials |
| `MINIO_SECURE` | `false` | TLS toggle |
| `REDIS_URL` | `redis://redis:6379/0` | progress/limits state |

## Run standalone

```bash
babel parse Security.evtx -o events.jsonl   # parse one artifact to ForensicEvent JSONL
babel list-parsers                          # list the discovered parser set (also the brick health check)
```

## Add a parser

Scaffold from the cookiecutter template, implement `parse()`, drop the package into the Babel root:

```bash
cookiecutter template/    # from the Babel root → manifest.yaml + <name>_plugin.py + test
```

Declare `SUPPORTED_EXTENSIONS` / `SUPPORTED_MIME_TYPES` and `PLUGIN_PRIORITY`; yield dicts with the required `timestamp` (ISO-8601 **Z**) + `message`. The loader discovers it — no registration. See [`sdk/README.md`](sdk/README.md).

## Tests

```bash
pytest tests/                                       # from the Babel root; includes golden tests
BABEL_REGEN_GOLDEN=1 pytest tests/test_golden.py    # regenerate golden fixtures after a parser change
```

## In Citadel

Sluice calls Babel for every routed artifact; events are validated, indexed into Elasticsearch, and normalized by Rosetta. The live parser set is advertised to the UI (`GET /plugins`), and Studio-authored parsers appear without a manifest edit.

See `forensic_event.schema.json` and the `BasePlugin` contract in [github.com/sltcnb/citadel-contracts](https://github.com/sltcnb/citadel-contracts).

## Part of the Citadel suite

Babel is the parsing stage of [Citadel](https://github.com/sltcnb/citadel). **Upstream:** [sluice](https://github.com/sltcnb/sluice) routes each intake artifact to a parser. **Downstream:** the ForensicEvent stream is canonicalized to ECS by [rosetta](https://github.com/sltcnb/rosetta) before storage, detection ([sigil](https://github.com/sltcnb/sigil)) and analysis ([anvil](https://github.com/sltcnb/anvil)). Babel itself has no suite dependencies (`dependencies: []` in `brick.yaml`).
