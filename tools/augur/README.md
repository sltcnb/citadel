# Augur — Intel Enrichment

> Turn raw indicators into scored, sourced, shareable intelligence.

**Status: partial** (STIX/TAXII/MISP/VT bits live in `api/routers/` today; this tool extracts and grows them).

## Standalone
```
augur enrich iocs.json -o enriched.stix.json
```

## Capabilities
- [●] Pluggable `Source` interface (`augur/sources/base.py`)
- [●] Sources: URLhaus (abuse.ch), AbuseIPDB, OTX — real API shapes, network-guarded
- [●] Cross-source confidence scoring (weighted + agreement bonus)
- [●] STIX 2.1 bundle export (indicators + producer identity)
- [●] Enrichment cache (in-memory TTL; Redis-swappable)
- [●] `augur enrich` / `augur sources` CLI (offline by default, `--online` for live calls)
- [ ] Additional sources: Shodan, GreyNoise, VirusTotal (reach 5+)
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

## Test
```
pip install -e .[test] && pytest        # 23 tests, no network
```
Patterns emitted by `stix.ioc_to_pattern` are checked against the same regex
grammar the Citadel CTI router uses (`api/routers/cti.py`), so exports
round-trip back into the platform.

## In Citadel
Case IOCs go to Augur; enrichments attach to entities and the timeline.

**Done when:** 5+ sources with scoring + cache; STIX export round-trips with MISP.
