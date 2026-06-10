# Testing

## The gate

`scripts/run_tests.sh` runs every tool's suite plus the cross-tool integration
test, using only the standard library (no pytest/ES/Redis needed) — so it's a
fast, dependency-light CI gate:

```bash
./scripts/run_tests.sh
# 16 suites: agg-rules, sigil, babel routing/SDK/golden, anvil DAG/artifacts,
# rosetta daemon, augur, talon e2e/chunker, sluice routing, observability,
# contract validator, and the Babel→Rosetta→Sigil integration.
```

CI runs it enforced (no soft-fail) on Python 3.11 and 3.12; a richer optional
`pytest` job runs on top when its deps are present.

## Integration test

`tests/integration/test_pipeline_e2e.py` drives a real artifact across three
tool boundaries over the contracts — `access.log → Babel → Rosetta → Sigil →
detection` — offline. It is the guard against field-shape drift between tools
(it caught, and the fix added, Rosetta's ECS sub-object passthrough).

## Contract enforcement

`citadel_contracts.validate_forensic_event` enforces the ForensicEvent contract
at runtime (required fields, ISO-8601 **Z** timestamp, `raw` for structured
types). Sluice validates every event here before emitting to the bus.

## Golden files

Babel parsers have golden-file tests (`tools/babel/tests/golden/`): parse a
committed fixture, compare byte-for-byte to the expected normalized events, and
validate each against the ForensicEvent schema. Regenerate after an intentional
change with `BABEL_REGEN_GOLDEN=1`. Binary-format goldens (EVTX/LNK/…) activate
when a real fixture + parser lib are present, else skip with a reason.
