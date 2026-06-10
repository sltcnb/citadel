# sample_events corpus

A tiny corpus of ECS-shaped `ForensicEvent` documents used to exercise the
Sigil rule packs offline (no Elasticsearch required). Each `*.jsonl` file is a
JSON-Lines stream of events that conform to
`../../../contracts/forensic_event.schema.json` (required `timestamp` +
`message`, plus structured fields like `evtx.event_id`, `host.*`).

| File | Intent |
|------|--------|
| `positive.jsonl` | Events that SHOULD trigger specific native rules. |
| `negative.jsonl` | Benign events that should NOT trigger those rules. |

`test_rule_match.py` loads a few rules from the native packs, runs them against
this corpus via `sigil_match.query_matches`, and asserts the expected
fire/no-fire outcome. Add an event here whenever you add or tighten a rule.
