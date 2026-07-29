# Autopilot evaluation harness

Scores a Pilot autopilot run against a scenario rubric, so a change to the agent
can be measured instead of argued about.

## Why

`_AGENT_PROMPT` is 344 lines / ~5,300 tokens, and much of it is a patch log of
past failures written as instructions:

> "Queries are LUCENE/KQL, NOT Splunk SPL. NO pipes…"
> "Forward slashes are handled for you — do NOT try to escape them…"
> "If a field:value query returns 0 twice, the FIELD is probably wrong…"
> "DON'T LOOP: if you've already found relevant evidence… STOP re-wording the same search"

Each line encodes a real failure. But none of them can be evaluated, so none can
safely be **removed** — the prompt only grows, and a change that makes the agent
worse is invisible. This harness is the missing feedback loop.

## Layout

| path | what it is |
|---|---|
| `scoring.py` | pure scorer — stdlib only, no LLM, no ES. Consumes the agent run doc the service already persists |
| `scenarios/*.yaml` | seed documents + the analyst's question + a rubric |
| `pilot_eval.py` | CLI: validate, seed, drive the live agent, score, save/replay |
| `../tests/test_pilot_eval.py` | 22 tests for the scorer |

## Metrics

Each fails for exactly one reason, so a failure says *what* broke:

- **evidence_recall** — did it surface the fo_ids the scenario planted as the answer? *(primary)*
- **citation_grounding** — do the fo_ids it CITES actually exist? Catches a verdict built on invented evidence
- **verdict** — does `incident_confirmed` match? Scored separately from evidence, because finding events and drawing the right conclusion are different skills
- **technique_recall** — ATT&CK coverage; a sub-technique satisfies its parent
- **termination** — concluded, or ran out of budget? `max_steps_reached` is a partial failure even when correct: the analyst waited for a commitment that never came
- **efficiency** — steps against budget. Reported, but **never gates**: a correct slow answer beats a fast wrong one
- **waste** — steps that returned nothing *and* repeated an earlier signature (the behaviour "DON'T LOOP" asks for, now counted)

Deliberate design choice: *"the agent looked at a lot of things"* must never score
well. `test_volume_is_not_quality` pins that.

## Usage

```bash
# validate the scenarios (runs in CI — no services needed)
python3 tools/pilot/eval/pilot_eval.py --check
python3 tools/pilot/eval/pilot_eval.py --list

# drive the live agent, then save the runs for later re-scoring
python3 tools/pilot/eval/pilot_eval.py \
    --api http://localhost:8000/api/v1 --token "$TOKEN" \
    --es http://localhost:9200 --save runs/baseline.json

# re-score saved runs offline — no LLM, no cost, deterministic
python3 tools/pilot/eval/pilot_eval.py --replay runs/baseline.json
```

Exit code is non-zero when any scenario fails its gates.

**Seeding is destructive** — it deletes and rewrites `fo-case-<case-id>-<scenario>-*`
indices. Use a throwaway case id (default `pilot-eval`), never a real one.

## Why live runs are not in CI

Driving the agent needs an LLM: it costs money, it is nondeterministic, and CI has
no credentials. So the two questions are split:

- *"Is the agent good?"* — needs the LLM. Run it deliberately, save the result.
- *"Did I break the scorer or a scenario?"* — needs neither. **This is what CI checks**
  (`--check` plus the scorer's unit tests, both in `scripts/run_tests.sh`).

Saving runs also gives you a baseline to diff against: score the same saved run
before and after a prompt change and the scorer's own behaviour is held constant.

## Adding a scenario

1. Copy an existing YAML. Give every seed doc an explicit `fo_id` — the rubric
   references them, and `--check` fails if a doc lacks one.
2. Mark the planted answer with `key: true`. `--check` fails when
   `rubric.key_evidence` and the `key: true` docs disagree, which is the drift that
   otherwise makes a scenario silently unscoreable.
3. Shape the docs **exactly** as the parser emits them, so the scenario measures
   the agent and not a parser. Check `tools/sigil/field_inventory.json` for the
   real field names — note its `dynamic_namespaces`, where absence proves nothing.
4. Include noise. A scenario with one document does not test discrimination.
