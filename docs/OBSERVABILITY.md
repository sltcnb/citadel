# Observability

Citadel emits three different things, and they are not interchangeable. Reaching
for the wrong one is why a question that should take a minute takes an afternoon.

| | Where | Lives for | Answers |
|---|---|---|---|
| **Logs** | Redis streams `citadel:logs:<service>` | ~2 000 lines, gone on restart | "What is this service doing *right now*?" |
| **Metrics** | Prometheus text at the worker's `:9100/metrics` | Process lifetime | "How much, how fast, how many in flight?" |
| **Telemetry** | Elasticsearch `citadel-telemetry-*` | 30 days, survives restarts | "What should we fix next?" |

Logs and metrics already existed. Telemetry is the one you read when the goal is
to *improve* the platform rather than to watch it.

---

## Telemetry

### Everything is advertised

**No part of Citadel knows what a "parse outcome" or a "token count" is.** Event
kinds, indexed fields and rendered panels all come from a `telemetry:` block in
each component's own `capabilities.yaml` — the same contract that already builds
the tool input forms. Remove a tool and its panels leave with it; plug one in
and its panels appear, with no orchestrator change.

Platform services advertise through exactly the same path: `tools/citadel/`
declares the API's `request`/`error`/`ui` telemetry, `tools/sluice/` the
worker's `task` telemetry, `tools/pilot/` the `llm` telemetry. There is no
privileged built-in.

What ships today, and who declares it:

| `kind` | Advertised by | One document per |
|---|---|---|
| `error` | `citadel` | unexpected exception, with the full traceback |
| `request` | `citadel` | HTTP request (sampled — see below) |
| `ui` | `citadel` | browser crash, unhandled rejection, or 5xx the user hit |
| `task` | `sluice` | task run and parse attempt |
| `llm` | `pilot` | call to a language-model backend |

`anvil` declares no kind of its own — it adds one field (`task.module`) and one
panel to Sluice's `task` events. That cross-tool extension is deliberate and
supported.

`GET /api/v1/admin/telemetry/contract` shows the merged result: every kind,
field and panel the platform currently sees, plus any warnings. **It is the
first place to look when a panel is missing or a field will not group** — if it
is not there, no manifest declared it.

Field groups: `error.*` (`type`, `message`, `signature`, `stack`), `http.*`
(`method`, `route`, `path`, `status_code`), `task.*` (`name`, `id`, `queue`,
`artifact_type`, `plugin`, `module`, `events`, `retries`), `llm.*` (`provider`,
`base_url`, `model`, `purpose`, token counts, `cost_usd`, `tokens_per_second`),
`ui.*` (`route`, `component`, `source`, `user_agent`, `app_version`), plus
`user.name`, `user.role`, `case_id`, `correlation_id` and a free-form `labels`
object.

**`case_id` is ambient.** The API middleware binds the case a request is about
into a `ContextVar` for the life of that request, and any event raised
underneath it — an LLM call deep inside Pilot, an unhandled exception —
inherits it. That is what makes "which investigation cost the most tokens" a
query rather than a guess. An explicitly passed `case_id` always wins.

**`llm.cost_usd` is not always billed.** Providers that return a cost are
recorded as-is (`labels.cost_source = "actual"`); for self-hosted and most
OpenAI-compatible endpoints the platform's own price table is used instead
(`"estimated"`). Never assume a cost figure is an invoice.

Two fields do most of the work:

- **`error.signature`** — the error message with ids, numbers, hex addresses and
  quoted values replaced by placeholders, so 400 occurrences of one bug are one
  bucket. `ValueError: case 8f3a not found` and `ValueError: case 91bd not
  found` share a signature; a different exception type does not.
- **`http.route`** — the *templated* path (`/api/v1/cases/{case_id}`). Aggregate
  on this; `http.path` holds the concrete URL for reading a single event.

### What is *not* recorded

Prompt and response bodies are not stored — only their token counts, latency,
cost and purpose. Request and response payloads are not stored. Telemetry is
about shapes and rates, and case data is evidence: it belongs in the case index
under its own access controls, not in an operational index.

### Sampling

Recording every request would make telemetry larger than the evidence. The rule:

- **always** — any 4xx/5xx, any `POST`/`PUT`/`PATCH`/`DELETE`, anything slower
  than `CITADEL_TELEMETRY_SLOW_REQUEST_MS` (default 1 000 ms)
- **sampled** at `CITADEL_TELEMETRY_SAMPLE_RATE` (default 5 %) — fast successful
  `GET`s
- **never** — successful polling/heartbeat endpoints (`/health`, `/collab/`,
  the log and telemetry viewers polling themselves)

So error rates are exact; total request volume is an estimate. If you need exact
volume, use the Prometheus counters instead.

---

## Reading it

### From the API

```bash
TOKEN=...   # an admin JWT

# The improvement dashboard: failing routes, slow routes, recurring errors,
# task outcomes, LLM spend, UI crashes — all in one call.
curl -sH "Authorization: Bearer $TOKEN" \
  'localhost:8000/api/v1/admin/telemetry/summary?hours=24' | jq

# Drill into one thing.
curl -sH "Authorization: Bearer $TOKEN" \
  'localhost:8000/api/v1/admin/telemetry/events?kind=error&hours=168&limit=50' | jq

# A user reports "it said correlation_id c0ffee1234" → the exact traceback.
curl -sH "Authorization: Bearer $TOKEN" \
  'localhost:8000/api/v1/admin/telemetry/events?correlation_id=c0ffee1234' | jq

# Is telemetry itself working?
curl -sH "Authorization: Bearer $TOKEN" \
  localhost:8000/api/v1/admin/telemetry/health | jq
```

`GET /admin/telemetry/health` reports the in-process sink's counters
(`emitted` / `shipped` / `dropped` / `failed` / `queued` / `last_error`) plus the
cluster-wide document count. Note the caveat it returns: with multiple uvicorn
workers each process has its own sink, so the counters describe one worker.

**`dropped` climbing** means the queue is full — Elasticsearch is slower than the
event rate. **`failed` climbing with a `last_error`** means the writes are being
rejected; read the error. **`documents` flat while the platform is busy** means
nothing is reaching the index at all.

### Straight from Elasticsearch

Useful when the API is the thing that is broken.

```bash
ES='-u elastic:$ELASTIC_PASSWORD localhost:9200'

# The 20 most common distinct errors this week.
curl -s $ES '/citadel-telemetry-*/_search' -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"bool": {"filter": [
    {"term": {"kind": "error"}},
    {"range": {"@timestamp": {"gte": "now-7d"}}}
  ]}},
  "aggs": {"sigs": {"terms": {"field": "error.signature", "size": 20}}}
}' | jq '.aggregations.sigs.buckets'

# Which parsers fail, and how often, per artifact type.
curl -s $ES '/citadel-telemetry-*/_search' -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"term": {"kind": "task"}},
  "aggs": {"types": {"terms": {"field": "task.artifact_type", "size": 50},
    "aggs": {"outcome": {"terms": {"field": "outcome"}}}}}
}' | jq '.aggregations.types.buckets'

# What the pilot costs, by what it was asked to do.
curl -s $ES '/citadel-telemetry-*/_search' -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"term": {"kind": "llm"}},
  "aggs": {"purpose": {"terms": {"field": "llm.purpose", "size": 20},
    "aggs": {"cost": {"sum": {"field": "llm.cost_usd"}},
             "p95_ms": {"percentiles": {"field": "duration_ms", "percents": [95]}}}}}
}' | jq '.aggregations.purpose.buckets'
```

### In Kibana

Kibana is already in the stack at `:5601`. Create a data view on
`citadel-telemetry-*` with `@timestamp` as the time field, and the fields above
are all pre-mapped for aggregation.

---

## Questions worth asking regularly

| Question | Where to look |
|---|---|
| What breaks most often? | `summary.top_errors` — ranked by occurrences, with the newest sample and a traceback |
| Which endpoints are failing? | `summary.requests.failing_routes` — route + status-code breakdown |
| What is slow enough that users notice? | `summary.requests.slowest_routes` — ordered by p95, not by average |
| Which parsers are unreliable? | `summary.tasks.by_artifact_type` — failure ratio per artifact type |
| Is anything dead-lettering? | `events?kind=error&q=dead-letter` |
| What is the pilot costing, and is it worth it? | `summary.llm.by_purpose` — cost and failures per kind of call |
| Is the frontend broken for anyone? | `summary.ui` — routes and components, with `app_version` on each event |

A useful habit: pull `summary?hours=168` weekly. The top three entries of
`top_errors`, `failing_routes` and `by_artifact_type` are a work list assembled
from what actually happened, not from what anyone remembered to file.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CITADEL_TELEMETRY_ENABLED` | `true` | Master switch. `false` makes every emit a no-op. |
| `CITADEL_TELEMETRY_RETENTION_DAYS` | `30` | ILM delete phase, and the explicit prune window. |
| `CITADEL_TELEMETRY_SAMPLE_RATE` | `0.05` | Fraction of fast successful GETs recorded. |
| `CITADEL_TELEMETRY_SLOW_REQUEST_MS` | `1000` | Above this a request is always recorded. |
| `CITADEL_TELEMETRY_UI_RATE_LIMIT` | `30` | Browser error reports accepted per IP per minute. |

Storage: indices are daily (`citadel-telemetry-2026.08.31`), one shard, no
replica. Retention is enforced twice over — an ILM policy with a delete phase,
and an explicit daily prune from the API, so a cluster without ILM (or without
`manage_ilm` privilege) still stays bounded.

---

## Design notes

**Telemetry never breaks the thing it measures.** Every emit is a
`put_nowait` onto a bounded queue drained by a daemon thread; a full queue drops
the newest event rather than applying backpressure to a request or a parse.
Every public function in `citadel_contracts/telemetry.py` swallows its own
exceptions. A dead Elasticsearch degrades telemetry to a drop counter and
nothing else.

**Fork-safe by construction.** The Celery worker runs a *prefork* pool: it
imports the module, then forks the children that execute tasks. A shipper
thread started before the fork does not exist in the child, so it would inherit
a queue nothing drains and lose every event it ever recorded. The thread
therefore starts on the first `emit`, not at construction — each process starts
its own the first time it has something to say — and an `os.register_at_fork`
hook rebuilds the queue and shipper in the child for the case where the parent
had already started one.

**Mappings are explicit, `dynamic` is `false`.** The index template carries the
*envelope* only — the fields every event has by construction. Everything else is
merged in from the advertisements at startup. An undeclared field is still
stored and readable in `_source`; it just cannot be grouped on until somebody
declares it. That is the mechanism that stops a careless payload blowing up the
field count, and the reason a new tool's fields become aggregatable without
editing the shared package.

**Instrument at the choke point, not at the call site.** Task events come from
Celery's own signals, so a new task type is covered the day it is added. LLM
telemetry hangs off the two shared call wrappers, and `llm.purpose` is read from
the caller's stack frame — because threading a `purpose=` argument through
thirty existing call sites is the kind of change that gets half done and then
reports coverage it does not have.

## Adding telemetry to a tool

Two halves: emit, and advertise.

**Emit** — two lines, and the same code runs unchanged in a standalone CLI
(without `ELASTICSEARCH_URL` the sink is disabled and every call is a no-op):

```python
from citadel_contracts.telemetry import init_telemetry, record_task, record_error

init_telemetry("mytool")          # reads ELASTICSEARCH_* from the environment
record_task("mytool.scan", "success", duration_ms=1234, case_id=case_id)
record_error(exc, event="scan_failed", case_id=case_id)
```

**Advertise** — add a `telemetry:` block to the tool's `capabilities.yaml`. This
is what makes the fields aggregatable and puts the panels on the page:

```yaml
telemetry:
  kinds: [scan]                      # event kinds this tool emits
  fields:                            # merged into the index mapping
    - { name: scan.target, type: keyword, label: "Target" }
    - { name: scan.findings, type: long, label: "Findings" }
  panels:                            # rendered generically by the frontend
    - key: scan_by_target
      label: "Scans by target"
      hint: "which targets fail most"
      type: table                    # table | stat | timeseries
      kind: scan
      group_by: scan.target
      order_by: "Failed"             # a metric label; default is count
      metrics:
        - { op: count, label: "Runs" }
        - { op: count, label: "Failed", where: { outcome: failure }, tone: bad }
        - { op: avg, field: duration_ms, label: "Avg", unit: ms }
        - { op: p95, field: duration_ms, label: "p95", unit: ms }
```

Field types: `keyword` (the only thing you can group by), `text`, `long`,
`integer`, `short`, `double`, `float`, `boolean`, `date`, `flattened`.
Metric ops: `count`, `sum`, `avg`, `min`, `max`, `p95`. Units (`ms`, `usd`,
`percent`) are formatting hints; `tone: bad` colours a non-zero value red.
`where` takes an exact value, a list, or a range (`{gte: 400}`).

The manifest is validated: an unknown type or op, a `table` without a
`group_by`, a `group_by` on a `text` field, or a duplicate panel key are all
reported by `GET /admin/telemetry/contract` and by
`tools/citadel_contracts/test_capabilities.py` rather than silently producing an
empty panel.

A tool may declare fields and panels **without** declaring a kind, to extend
another tool's events — that is how Anvil adds `task.module` to Sluice's `task`.
