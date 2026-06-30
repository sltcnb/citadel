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

Parser packs include: `access_log`, `android`, `antivirus`, `apt_history`, `archive`, `auditd`, `browser`, `cloud_audit` (AWS/Azure/GCP), `crictl`, `dd_image`, `diskimage`, `docker`, `evtx`, `hayabusa`, `ios`, `iptables`, `json_file`, `k3s`, `k8s_resources`, `lastlog`, `linux_config`, `linux_triage`, `lnk`, `log2timeline`, `macos_uls`, `mft`, `ndjson`, `netstat`, `pcap`, `plaso`, `plist`, `prefetch`, `registry`, `scheduled_task`, `shell_history`, `strings_fallback`, `suricata`, `syslog`, `timestamped_log`, `utmp`, `wer`, `windows_triage`, `wlan_profile`, `zeek`.

## Run standalone

```bash
babel parse Security.evtx -o events.jsonl   # parse one artifact to ForensicEvent JSONL
babel list-parsers                          # list the discovered parser set (also the health check)
```

## Add a parser

Scaffold from the cookiecutter template, implement `parse()`, drop the package under `tools/babel/`:

```bash
cookiecutter tools/babel/template    # → manifest.yaml + <name>_plugin.py + test
```

Declare `SUPPORTED_EXTENSIONS` / `SUPPORTED_MIME_TYPES` and `PLUGIN_PRIORITY`; yield dicts with the required `timestamp` (ISO-8601 **Z**) + `message`. The loader discovers it — no registration. See `tools/babel/sdk/README.md`.

## In Citadel

Sluice calls Babel for every routed artifact; events are validated, indexed into Elasticsearch, and normalized by Rosetta. The live parser set is advertised to the UI (`GET /plugins`), and Studio-authored parsers appear without a manifest edit.

See `../../contracts/forensic_event.schema.json` and the `BasePlugin` contract in [`../citadel_contracts`](../citadel_contracts).
