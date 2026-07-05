# Augur — Intel Enrichment

> Turn raw indicators into scored, sourced, shareable intelligence.

**Status: partial** (STIX/TAXII/MISP/VT bits live in `api/routers/` today; this tool extracts and grows them).

## Pipeline position

```
Rosetta / case IOCs ──▶ Augur ──scored STIX / MISP──▶ entities / timeline
```

- **Inputs** — IOCs (file or case-extracted indicators).
- **Outputs** — scored, sourced `EnrichedIOC`s exported as a STIX 2.1 bundle.

## Contracts

From `brick.yaml` (v0.5.0, status **partial**):

- **Consumes** — `application/json` IOC lists; case indicators arrive as ForensicEvent v1 (`https://citadel.dfir/contracts/forensic_event/v1.json`).
- **Produces** — enriched IOCs / STIX as ForensicEvent v1 (same schema), artifact type `intel_indicator`.

Contract schemas are versioned in the `citadel_contracts` package ([github.com/sltcnb/citadel-contracts](https://github.com/sltcnb/citadel-contracts)).

## Install

```bash
pip install -e .        # only runtime dep: requests; installs the `augur` CLI
```

## Standalone
```
augur enrich iocs.json -o enriched.stix.json   # offline by default; add --online for live calls
augur sources                                  # list sources; `augur --version` is the brick health check
```

## Configuration

API keys are read from the environment (only used with `--online`; all default to empty — keyless sources like URLhaus still work):

| Variable | Source |
|---|---|
| `AUGUR_URLHAUS_API_KEY` | URLhaus (abuse.ch) |
| `AUGUR_ABUSEIPDB_API_KEY` | AbuseIPDB |
| `AUGUR_OTX_API_KEY` | AlienVault OTX |
| `AUGUR_SHODAN_API_KEY` | Shodan |
| `AUGUR_GREYNOISE_API_KEY` | GreyNoise |

Everything else (source selection `-s`, cache TTL `--cache-ttl`, output path) is CLI flags.

## Capabilities
- [●] Pluggable `Source` interface (`augur/sources/base.py`)
- [●] Sources (5): URLhaus (abuse.ch), AbuseIPDB, OTX, Shodan, GreyNoise — real API shapes, network-guarded
- [●] Cross-source confidence scoring (weighted + agreement bonus)
- [●] STIX 2.1 bundle export (indicators + producer identity)
- [●] Enrichment cache (in-memory TTL; Redis-swappable)
- [●] `augur enrich` / `augur sources` CLI (offline by default, `--online` for live calls)
- [ ] Additional sources: VirusTotal, …
- [ ] STIX / TAXII feed subscriptions + MISP sync
- [ ] Per-source rate limit + scheduled re-enrich of stale IOCs

## Architecture
```
iocs.json --> io.load_iocs --> Enricher(sources, TTLCache)
                                   |  per source: cache.get -> Source.enrich -> cache.set
                                   v
                              scoring.fuse  --> EnrichedIOC(score, severity, labels)
                                   v
                              stix.build_bundle --> STIX 2.1 bundle
```
Sources never reach the network on their own: HTTP goes through an injected
`session`. Tests inject a `MockSession`, so the whole suite runs offline.

## Tests
```
pip install -e .[test] && pytest        # runs tests/ — fully offline (MockSession, no network)
```
Patterns emitted by `stix.ioc_to_pattern` are checked against the same regex
grammar the Citadel CTI router uses (`api/routers/cti.py` in
[github.com/sltcnb/citadel](https://github.com/sltcnb/citadel)), so exports
round-trip back into the platform.

## In Citadel
Case IOCs go to Augur; enrichments attach to entities and the timeline.

**Done when:** 5+ sources with scoring + cache; STIX export round-trips with MISP.

## Part of the Citadel suite

Augur is the intel-enrichment stage of [Citadel](https://github.com/sltcnb/citadel). **Upstream:** case IOCs extracted from events canonicalized by [rosetta](https://github.com/sltcnb/rosetta). **Downstream:** scored intel attaches to case entities and the timeline, feeding [pilot](https://github.com/sltcnb/citadel-pilot) and [scribe](https://github.com/sltcnb/citadel-report). Platform service dependency (from `brick.yaml`): **Redis** — enrichment cache TTL + rate limiting (standalone runs use the in-memory cache).
