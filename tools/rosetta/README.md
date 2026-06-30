# Rosetta — Canonicalizer

> One schema to rule them all: any event stream → ECS v8 + OSSEM.

**Status: partial** (standalone CLI works; daemon + OSSEM/ATT&CK enrichment pending).

## Pipeline position

```
Babel ──ForensicEvent──▶ Rosetta ──ECS v8 + OSSEM──▶ store / Sigil / Anvil / Augur / timeline
```

Sits between parse and index so the timeline, search, Sigil, and Scribe all read **one** schema.

- **Inputs** — a `ForensicEvent` JSONL stream (`contracts/forensic_event/v1.json`).
- **Outputs** — ECS v8 documents + OSSEM/ATT&CK fields (`contracts/ecs_extension.md`), optionally GeoIP/ASN/rDNS-enriched.

## Install
```
pip install -e .            # provides the `rosetta` console script
```

## Standalone
```
rosetta normalize events.jsonl --ecs 8.11 -o ecs.jsonl
rosetta normalize - --ecs 8.11 < events.jsonl > ecs.jsonl   # stdin/stdout
rosetta normalize events.jsonl --map mymaps.yaml -o ecs.jsonl
rosetta daemon --watch /var/log --es http://es:9200          # planned
```

Try it on the bundled sample:
```
rosetta normalize examples/sample.jsonl --ecs 8.11 -o ecs.jsonl
```

## Field map
The `artifact_type` → ECS `event.category`/`event.type` mapping and the
per-type `raw` field copies are config-driven in `rosetta/fieldmaps/default.yaml`.
Covers `windows_event` (EVTX), `process` (Sysmon), `syslog`, and `prefetch`.
Point `--map` at your own yaml to extend coverage without code changes.

## Capabilities
- [●] ECS-shaped events (`@timestamp`, `ecs.version`, `event.*`, host/user/process, `citadel.raw`)
- [●] Standalone CLI: ForensicEvent JSONL → ECS v8 JSONL
- [●] Config-driven field maps (ECS categorization + raw field copies)
- [●] ECS version pinning (`--ecs`)
- [◐] Shared canonicalizer (consolidate mapping out of parsers)
- [ ] OSSEM relationships + Sigma-tag→ATT&CK technique enrichment
- [ ] Daemon: watch + ES out + disk-backed backpressure
- [●] Enrichment hooks: GeoIP / ASN / reverse-DNS on public IP fields (`enrich.py`)

## Enrichment (GeoIP / ASN / rDNS)
Public IPs on ECS fields (`source.ip`, `destination.ip`, `client.ip`, `server.ip`)
are annotated with `*.geo.{country_iso_code,country_name,city_name,location}` and
`*.as.{number,organization_name}`; reverse-DNS (`*.domain`) is opt-in.

```
pip install -e '.[enrich]'                 # adds geoip2
export GEOIP_CITY_DB=/usr/share/GeoIP/GeoLite2-City.mmdb
export GEOIP_ASN_DB=/usr/share/GeoIP/GeoLite2-ASN.mmdb
export ROSETTA_ENABLE_RDNS=true            # optional, slow — off by default
```
Graceful no-op when `geoip2` or the `.mmdb` files are absent — normalization never
fails on missing enrichment. Private/loopback/reserved IPs are skipped.

## Tests
```
pytest tests/
```

## In Citadel
Runs between parse and index so the timeline and search see one schema.

**Done when:** single canonicalizer; CLI + daemon parse EVTX + syslog → ECS.

See `../../contracts/ecs_extension.md`.
