"""Parse throughput / failure-rate metrics — per artifact type.

Exercises the metrics wiring added on top of observability.py's Prometheus
registry:

  * observability.record_parse() — the shared helper both
    tasks/ingest_task.py (Babel plugins) and tasks/module_task.py (analysis
    modules) call on their success/failure/skipped/cancelled paths, labeled
    by artifact type.
  * robustness.to_dead_letter() — records a dead-letter counter when a task
    is parked after exhausting its retries.

ingest_task.py / module_task.py themselves import celery, redis-py and the
minio SDK, none of which are available in this dependency-light test gate
(see scripts/run_tests.sh) — so this suite verifies the metrics primitives
they call directly, at the same level of isolation as test_observability.py
and test_robustness.py.

Runnable standalone (python3 tests/test_parse_metrics.py) to match the
dependency-light suite convention in scripts/run_tests.sh.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import observability as obs  # noqa: E402
import robustness  # noqa: E402


class FakeRedis:
    """Minimal in-memory stand-in for redis.Redis (only what robustness touches)."""

    def __init__(self) -> None:
        self.lists: dict[str, list] = {}

    def lpush(self, key: str, *values) -> int:
        lst = self.lists.setdefault(key, [])
        for v in values:
            lst.insert(0, v)
        return len(lst)

    def ltrim(self, key: str, start: int, end: int) -> bool:
        lst = self.lists.get(key, [])
        self.lists[key] = lst[start : end + 1] if end != -1 else lst[start:]
        return True

    def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))


def _hist_count(name: str, labels: dict) -> int:
    key = obs.METRICS._key(name, labels)
    return obs.METRICS._hist_count.get(key, 0)


def _counter_value(name: str, labels: dict) -> float:
    key = obs.METRICS._key(name, labels)
    return obs.METRICS._counters.get(key, 0.0)


# ── observability.record_parse / record_dead_letter ─────────────────────────


def test_record_parse_success_increments_counters_and_histogram():
    atype = f"test_success_{uuid.uuid4().hex[:8]}"
    before_ok = _counter_value("parser_parse_total", {"artifact_type": atype, "status": "success"})
    before_hist = _hist_count("parser_parse_duration_seconds", {"artifact_type": atype})
    before_events = _counter_value("parser_events_normalized_total", {"artifact_type": atype})

    obs.record_parse(atype, "success", 0.42, events_normalized=17)

    assert (
        _counter_value("parser_parse_total", {"artifact_type": atype, "status": "success"})
        == before_ok + 1
    )
    assert _hist_count("parser_parse_duration_seconds", {"artifact_type": atype}) == before_hist + 1
    assert (
        _counter_value("parser_events_normalized_total", {"artifact_type": atype})
        == before_events + 17
    )

    rendered = obs.METRICS.render_prometheus()
    assert f'parser_parse_total{{artifact_type="{atype}",status="success"}}' in rendered
    assert f'parser_parse_duration_seconds_bucket{{artifact_type="{atype}"' in rendered
    assert f'parser_events_normalized_total{{artifact_type="{atype}"}}' in rendered


def test_record_parse_failure_increments_failure_counter_not_success():
    atype = f"test_failure_{uuid.uuid4().hex[:8]}"
    obs.record_parse(atype, "failure", 1.5)

    assert _counter_value("parser_parse_total", {"artifact_type": atype, "status": "failure"}) == 1
    assert _counter_value("parser_parse_total", {"artifact_type": atype, "status": "success"}) == 0
    # No events were normalized on a failed parse.
    assert _counter_value("parser_events_normalized_total", {"artifact_type": atype}) == 0


def test_record_parse_is_per_artifact_type():
    a1, a2 = f"type_a_{uuid.uuid4().hex[:6]}", f"type_b_{uuid.uuid4().hex[:6]}"
    obs.record_parse(a1, "success", 0.1, events_normalized=5)
    obs.record_parse(a2, "failure", 0.2)

    assert _counter_value("parser_parse_total", {"artifact_type": a1, "status": "success"}) == 1
    assert _counter_value("parser_parse_total", {"artifact_type": a1, "status": "failure"}) == 0
    assert _counter_value("parser_parse_total", {"artifact_type": a2, "status": "failure"}) == 1
    assert _counter_value("parser_parse_total", {"artifact_type": a2, "status": "success"}) == 0


def test_record_dead_letter_counter():
    task = f"test.task.{uuid.uuid4().hex[:8]}"
    before = _counter_value("worker_dead_letter_total", {"task": task})
    obs.record_dead_letter(task)
    assert _counter_value("worker_dead_letter_total", {"task": task}) == before + 1
    assert f'worker_dead_letter_total{{task="{task}"}}' in obs.METRICS.render_prometheus()


# ── the same outcomes, mirrored into durable telemetry ───────────────────────
# The Prometheus counters above reset with the process. record_parse also writes
# to citadel-telemetry-*, which is what keeps "this parser has been failing all
# week" answerable after a worker restart.
#
# No pytest fixtures here — this module is also run standalone by
# scripts/run_tests.sh, which calls every test_* with no arguments.


def _capturing_sink():
    """Install a telemetry sink whose bulk writes are captured, not sent."""
    from citadel_contracts import telemetry as tel

    tel.reset_telemetry()
    sink = tel.TelemetrySink("processor", "http://es.invalid", flush_interval=0.05)
    sink.sent = []
    sink._request = lambda m, p, b=None, c="application/json": sink.sent.append(b) or {}
    tel._SINK = sink
    return sink


def _telemetry_docs(sink):
    import json

    sink.close()
    return [
        json.loads(line)
        for body in sink.sent
        for line in body.decode().strip().split("\n")[1::2]
    ]


def test_record_parse_also_emits_a_task_event():
    from citadel_contracts import telemetry as tel

    sink = _capturing_sink()
    try:
        atype = f"test_tel_{uuid.uuid4().hex[:8]}"
        obs.record_parse(atype, "failure", 1.5, case_id="case-abc", plugin="evtx_plugin")

        doc = _telemetry_docs(sink)[0]
        assert doc["kind"] == "task"
        assert doc["task.name"] == "parse"
        assert doc["outcome"] == "failure"
        assert doc["task.artifact_type"] == atype
        assert doc["task.plugin"] == "evtx_plugin"
        assert doc["case_id"] == "case-abc"
        # seconds in, milliseconds out
        assert doc["duration_ms"] == 1500.0
    finally:
        tel.reset_telemetry()


def test_record_dead_letter_also_emits_an_error_event():
    from citadel_contracts import telemetry as tel

    sink = _capturing_sink()
    try:
        task = f"test.task.{uuid.uuid4().hex[:8]}"
        obs.record_dead_letter(task)

        doc = _telemetry_docs(sink)[0]
        assert doc["kind"] == "error"
        assert doc["event"] == "dead_letter"
        assert doc["task.name"] == task
    finally:
        tel.reset_telemetry()


def test_a_broken_telemetry_sink_never_breaks_a_parse():
    from citadel_contracts import telemetry as tel

    tel.reset_telemetry()
    saved = obs.record_task
    obs.record_task = lambda *a, **kw: 1 / 0
    try:
        atype = f"test_safe_{uuid.uuid4().hex[:8]}"
        obs.record_parse(atype, "success", 0.1, events_normalized=3)
        # The Prometheus counter still moved — telemetry failing is not a parse
        # failing.
        assert (
            _counter_value("parser_parse_total", {"artifact_type": atype, "status": "success"})
            == 1
        )
    finally:
        obs.record_task = saved


# ── robustness.to_dead_letter wiring ─────────────────────────────────────────


def test_to_dead_letter_records_metric():
    r = FakeRedis()
    task = f"ingest.process_artifact.{uuid.uuid4().hex[:8]}"
    before = _counter_value("worker_dead_letter_total", {"task": task})
    robustness.to_dead_letter(
        r, task_name=task, task_id="abc123", args=["job1"], error=RuntimeError("boom"), retries=3
    )
    assert _counter_value("worker_dead_letter_total", {"task": task}) == before + 1
    # The dead-letter entry itself is still written — metrics never replace it.
    assert r.llen(robustness.DEAD_LETTER_KEY) == 1


def test_to_dead_letter_missing_observability_is_non_fatal():
    """robustness must dead-letter successfully even if metrics recording breaks."""
    saved = robustness._obs
    robustness._obs = None
    try:
        r = FakeRedis()
        robustness.to_dead_letter(
            r, task_name="t", task_id="1", args=[], error=RuntimeError("x"), retries=3
        )
        assert r.llen(robustness.DEAD_LETTER_KEY) == 1
    finally:
        robustness._obs = saved


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
