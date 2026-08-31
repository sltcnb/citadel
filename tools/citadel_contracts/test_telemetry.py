"""Tests for the shared telemetry sink. Standalone-runnable.

The behaviour that matters here is mostly negative — telemetry must never raise
into a caller, never block one, and never grow without bound — so most of these
assert what does *not* happen.

Pure stdlib (the sink is too), so this runs in the dependency-light gate as
well as under pytest.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tools/ for the package
from citadel_contracts import telemetry as t  # noqa: E402


def _sink(**kw) -> t.TelemetrySink:
    """A running sink whose transport is captured instead of sent."""
    sink = t.TelemetrySink("test", "http://es.invalid", flush_interval=0.05, **kw)
    sink.sent = []

    def _fake_request(method, path, body=None, content_type="application/json"):
        sink.sent.append((method, path, body))
        return {}

    sink._request = _fake_request
    return sink


def _docs(sink) -> list[dict]:
    """Every document across every bulk body the sink shipped."""
    out = []
    for _method, path, body in sink.sent:
        if path != "/_bulk":
            continue
        lines = body.decode().strip().split("\n")
        out.extend(json.loads(line) for line in lines[1::2])
    return out


def _as_singleton(sink) -> None:
    """Point the module-level helpers at this sink."""
    t._SINK = sink


# ── disabled / degraded paths ────────────────────────────────────────────────


def test_sink_without_es_url_is_disabled_and_emit_is_a_noop():
    sink = t.TelemetrySink("test", "")
    assert sink.enabled is False
    sink.emit(t.KIND_ERROR, message="boom")  # must not raise
    assert sink.stats["emitted"] == 0


def test_module_level_emit_without_init_is_a_noop():
    t.reset_telemetry()
    t.record_error(ValueError("no sink configured"))  # must not raise
    assert t.get_sink() is None


def test_transport_failure_is_counted_not_raised():
    sink = t.TelemetrySink("test", "http://es.invalid", flush_interval=0.05)

    def _boom(*_a, **_kw):
        raise OSError("connection refused")

    sink._request = _boom
    sink.emit(t.KIND_ERROR, message="boom")
    sink.close()
    assert sink.stats["failed"] == 1
    assert "connection refused" in (sink._last_error or "")


def test_full_queue_drops_instead_of_blocking():
    sink = t.TelemetrySink("test", "http://es.invalid", queue_size=2, enabled=True)
    sink.close()  # stop the drain thread so the queue genuinely fills
    for _ in range(10):
        sink.emit(t.KIND_ERROR, message="x")
    assert sink.stats["dropped"] >= 8


def test_bulk_item_errors_count_as_failed_not_shipped():
    sink = t.TelemetrySink("test", "http://es.invalid", flush_interval=0.05)
    sink._request = lambda *a, **kw: {
        "errors": True,
        "items": [
            {"index": {"error": {"reason": "mapper_parsing_exception"}}},
            {"index": {"status": 201}},
        ],
    }
    sink.emit(t.KIND_ERROR, message="a")
    sink.emit(t.KIND_ERROR, message="b")
    sink.close()
    assert sink.stats["failed"] == 1
    assert sink.stats["shipped"] == 1


# ── the write path ───────────────────────────────────────────────────────────


def test_emit_ships_a_bulk_body_with_a_daily_index():
    sink = _sink()
    sink.emit(t.KIND_ERROR, message="boom")
    sink.close()
    assert ("POST", "/_bulk") in [(m, p) for m, p, _ in sink.sent]
    header = json.loads(sink.sent[0][2].decode().split("\n")[0])
    assert header["index"]["_index"].startswith(f"{t.INDEX_PREFIX}-")


def test_every_document_carries_timestamp_service_and_kind():
    sink = _sink()
    sink.emit(t.KIND_REQUEST, event="http_request")
    sink.close()
    doc = _docs(sink)[0]
    assert doc["service"] == "test"
    assert doc["kind"] == t.KIND_REQUEST
    assert doc["@timestamp"].endswith("Z")


def test_none_values_are_dropped_so_absent_stays_absent():
    sink = _sink()
    sink.emit(t.KIND_TASK, event="parse", case_id=None)
    sink.close()
    assert "case_id" not in _docs(sink)[0]


def test_long_fields_are_truncated():
    sink = _sink()
    sink.emit(t.KIND_ERROR, message="x" * 50_000)
    sink.close()
    assert len(_docs(sink)[0]["message"]) < 3000


def test_labels_are_passed_through_untouched():
    sink = _sink()
    sink.emit(t.KIND_TASK, labels={"celery_state": "SUCCESS", "n": 3})
    sink.close()
    assert _docs(sink)[0]["labels"] == {"celery_state": "SUCCESS", "n": 3}


def test_batches_are_shipped_together():
    sink = _sink(batch_size=5)
    for i in range(5):
        sink.emit(t.KIND_ERROR, message=f"boom {i}")
    sink.close()
    assert len(_docs(sink)) == 5


# ── helper field shapes ──────────────────────────────────────────────────────


def test_record_request_marks_5xx_as_failure_and_4xx_as_success():
    sink = _sink()
    _as_singleton(sink)
    try:
        t.record_request("GET", "/api/v1/cases/abc", 500, 12.5, route="/api/v1/cases/{case_id}")
        t.record_request("GET", "/api/v1/cases/abc", 404, 3.0)
        sink.close()
        five, four = _docs(sink)
        assert five["outcome"] == "failure"
        assert five["http.route"] == "/api/v1/cases/{case_id}"
        assert five["duration_ms"] == 12.5
        # A 404 is the API working correctly; only 5xx is the platform's fault.
        assert four["outcome"] == "success"
    finally:
        t.reset_telemetry()


def test_record_error_captures_type_stack_and_correlation_id():
    sink = _sink()
    _as_singleton(sink)
    try:
        t.record_error(ValueError("bad case 991"), stack="Traceback...", correlation_id="c0ffee")
        sink.close()
        doc = _docs(sink)[0]
        assert doc["error.type"] == "ValueError"
        assert doc["correlation_id"] == "c0ffee"
        assert doc["error.stack"] == "Traceback..."
        assert doc["outcome"] == "failure"
    finally:
        t.reset_telemetry()


def test_record_llm_totals_tokens():
    sink = _sink()
    _as_singleton(sink)
    try:
        t.record_llm("anthropic", "claude", prompt_tokens=100, completion_tokens=50, cost_usd=0.01)
        sink.close()
        doc = _docs(sink)[0]
        assert doc["llm.total_tokens"] == 150
        assert doc["llm.cost_usd"] == 0.01
    finally:
        t.reset_telemetry()


def test_caller_fields_override_helper_defaults_without_raising():
    # The helpers set dotted fields themselves AND forward **fields. Building
    # that with two ** unpackings made a duplicate key a TypeError; merging
    # makes the caller's value win, which is what a call site overriding
    # task.name actually wants.
    sink = _sink()
    _as_singleton(sink)
    try:
        t.record_task("parse", "success", 10.0, **{"task.name": "ingest.parse_file"})
        sink.close()
        doc = _docs(sink)[0]
        assert doc["task.name"] == "ingest.parse_file"
        assert doc["event"] == "parse"
    finally:
        t.reset_telemetry()


# ── error grouping ───────────────────────────────────────────────────────────


def test_two_occurrences_of_one_bug_share_a_signature():
    same = [
        ("case 123 not found", "case 456 not found"),
        ("object at 0xdeadbeef", "object at 0xcafef00d"),
        ("key 'abc' missing", "key 'xyz' missing"),
        ("job 7f3a9b2c1d4e5f failed", "job 1a2b3c4d5e6f70 failed"),
    ]
    for a, b in same:
        assert t.error_signature("ValueError", a) == t.error_signature("ValueError", b), (a, b)


def test_different_bugs_do_not_share_a_signature():
    assert t.error_signature("ValueError", "bad input") != t.error_signature(
        "KeyError", "bad input"
    )


# ── index management ─────────────────────────────────────────────────────────


def test_ensure_index_template_installs_policy_and_template():
    sink = _sink()
    assert sink.ensure_index_template(retention_days=7) is True
    paths = [p for _m, p, _b in sink.sent]
    assert f"/_ilm/policy/{t.ILM_POLICY_NAME}" in paths
    assert f"/_index_template/{t.TEMPLATE_NAME}" in paths
    template = json.loads(
        next(b for _m, p, b in sink.sent if p == f"/_index_template/{t.TEMPLATE_NAME}")
    )
    assert template["index_patterns"] == [t.INDEX_PATTERN]
    assert template["template"]["settings"]["index.lifecycle.name"] == t.ILM_POLICY_NAME
    sink.close()


def test_ensure_index_template_survives_a_cluster_without_ilm():
    sink = t.TelemetrySink("test", "http://es.invalid", flush_interval=0.05)
    calls = []

    def _request(method, path, body=None, content_type="application/json"):
        calls.append(path)
        if path.startswith("/_ilm/"):
            raise OSError("security_exception: missing manage_ilm")
        return {}

    sink._request = _request
    # The template must still be installed; only the lifecycle setting is lost.
    assert sink.ensure_index_template() is True
    assert f"/_index_template/{t.TEMPLATE_NAME}" in calls
    sink.close()


def test_prune_deletes_only_indices_past_the_window():
    now = datetime.now(UTC)
    old = f"{t.INDEX_PREFIX}-{now - timedelta(days=60):%Y.%m.%d}"
    recent = f"{t.INDEX_PREFIX}-{now - timedelta(days=1):%Y.%m.%d}"
    sink = t.TelemetrySink("test", "http://es.invalid", flush_interval=0.05)
    deleted = []

    def _request(method, path, body=None, content_type="application/json"):
        if method == "GET":
            return {old: {}, recent: {}, "citadel-telemetry-not-a-date": {}}
        deleted.append(path)
        return {}

    sink._request = _request
    assert sink.prune_old_indices(retention_days=30) == [old]
    assert deleted == [f"/{old}"]
    sink.close()


# ── fork safety ──────────────────────────────────────────────────────────────
# Celery runs a prefork pool: the worker imports the module, then forks the
# children that execute tasks. A shipper thread started before the fork does
# not exist in the child, which would silently queue every worker event forever.


def test_the_shipper_thread_starts_lazily_not_at_construction():
    sink = t.TelemetrySink("test", "http://es.invalid", flush_interval=0.05)
    try:
        assert sink._thread is None
        sink.emit(t.KIND_ERROR, message="boom")
        assert sink._thread is not None and sink._thread.is_alive()
    finally:
        sink.close()


def test_close_is_safe_on_a_sink_that_never_emitted():
    t.TelemetrySink("test", "http://es.invalid").close()  # must not raise


def test_after_fork_gives_the_child_a_clean_queue_and_a_live_shipper():
    sink = _sink()
    # What a fork hands the child: a copy of the parent's buffer (which the
    # parent is still going to ship) and a thread object for a thread that does
    # not exist in this process.
    sink._queue.put_nowait({"message": "still the parent's to ship"})
    sink.stats["emitted"] = 5

    sink._after_fork()

    assert sink._thread is None
    assert sink._queue.qsize() == 0
    assert sink.stats["emitted"] == 0

    sink.emit(t.KIND_ERROR, message="child event")
    sink.close()
    assert [d["message"] for d in _docs(sink)] == ["child event"]


def test_the_fork_hook_is_registered_and_tolerates_no_sink():
    t.reset_telemetry()
    t._reinit_after_fork()  # no sink installed — a no-op, not a crash


def test_a_real_fork_ships_from_the_child():
    """End-to-end: fork after the parent has already started its shipper."""
    import os

    if not hasattr(os, "fork"):
        return
    sink = _sink()
    sink.emit(t.KIND_ERROR, message="parent event")  # starts the parent thread
    t._SINK = sink
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child — never returns
        code = b"FAIL"
        try:
            t._reinit_after_fork()  # what os.register_at_fork does for real
            sink.sent = []
            sink.emit(t.KIND_ERROR, message="child event")
            sink.close()
            if any(b"child event" in body for _m, _p, body in sink.sent):
                code = b"OK"
        except BaseException:
            code = b"FAIL"
        finally:
            os.write(write_fd, code)
            os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as fh:
        result = fh.read()
    os.waitpid(pid, 0)
    sink.close()
    t.reset_telemetry()
    assert result == b"OK", result


# ── singleton ────────────────────────────────────────────────────────────────


def test_init_telemetry_is_idempotent():
    t.reset_telemetry()
    try:
        first = t.init_telemetry("api", es_url="", enabled=False)
        second = t.init_telemetry("processor", es_url="", enabled=False)
        assert first is second
        assert second.service == "api"
    finally:
        t.reset_telemetry()


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
