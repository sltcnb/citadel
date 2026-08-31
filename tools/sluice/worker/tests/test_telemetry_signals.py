"""Worker telemetry wired to Celery's own signals.

Instrumenting the signals rather than the task bodies means a new task type is
covered the day it is added and no task can forget to report that it failed.
The part that is easy to get wrong is attribution: `case_id` sits at a
different positional index in every task, so these tests pin that a parse is
filed under its case and not under a job id.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# The worker runs flat under /app; mirror that for the test.
_WORKER = Path(__file__).resolve().parents[1]
for _p in (str(_WORKER), str(_WORKER.parents[2])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("CITADEL_TELEMETRY_ENABLED", "false")
os.environ.setdefault("CITADEL_LOG_TO_REDIS", "false")

celery_app = pytest.importorskip("celery_app")
from citadel_contracts import telemetry as t  # noqa: E402


# The real task signatures — case_id is at index 1 for three of them and at
# index 0 for the fourth, which is exactly the trap.
def _process_artifact(self, job_id, case_id, minio_object_key, original_filename): ...
def _maybe_run_detections(self, case_id, _attempts=0, _token=None): ...
def _run_module(self, run_id, case_id, module_id, source_files, params=None): ...
def _run_harvest(self, run_id, case_id, level="complete", **kw): ...


class _Task:
    """Stands in for a bound Celery task."""

    def __init__(self, name, run, routing_key="ingest", retries=0):
        self.name = name
        self.run = run
        self.request = type(
            "_Req", (), {"delivery_info": {"routing_key": routing_key}, "retries": retries}
        )()


@pytest.fixture(autouse=True)
def _clear_signature_cache():
    celery_app._CASE_ARG_INDEX.clear()
    yield
    celery_app._CASE_ARG_INDEX.clear()


@pytest.fixture
def sink(monkeypatch):
    t.reset_telemetry()
    s = t.TelemetrySink("processor", "http://es.invalid", flush_interval=0.05)
    s.sent = []
    s._request = lambda m, p, b=None, c="application/json": s.sent.append(b) or {}
    monkeypatch.setattr(t, "_SINK", s)
    yield s
    t.reset_telemetry()


def _docs(sink):
    sink.close()
    return [
        json.loads(line)
        for body in sink.sent
        for line in body.decode().strip().split("\n")[1::2]
    ]


@pytest.mark.parametrize(
    "name, fn, args",
    [
        ("ingest.process_artifact", _process_artifact, ("job-1", "case-abc", "key", "f.evtx")),
        ("ingest.maybe_run_detections", _maybe_run_detections, ("case-abc",)),
        ("module.run", _run_module, ("run-9", "case-abc", "yara", [])),
        ("harvest.run_harvest", _run_harvest, ("run-9", "case-abc")),
    ],
)
def test_case_id_is_read_from_the_signature_not_a_fixed_position(name, fn, args):
    assert celery_app._case_id_of(_Task(name, fn), {}, args) == "case-abc"


def test_case_id_kwarg_wins_over_positional():
    task = _Task("ingest.process_artifact", _process_artifact)
    assert celery_app._case_id_of(task, {"case_id": "case-kw"}, ("job-1", "case-pos")) == "case-kw"


def test_a_task_without_a_case_id_parameter_is_not_misattributed():
    def _no_case(self, thing_id, other): ...
    assert celery_app._case_id_of(_Task("x.y", _no_case), {}, ("a", "b")) == ""


def test_signature_index_is_cached_per_task_name():
    task = _Task("ingest.process_artifact", _process_artifact)
    celery_app._case_id_of(task, {}, ("job-1", "case-abc"))
    assert celery_app._CASE_ARG_INDEX["ingest.process_artifact"] == 1


def test_postrun_records_one_task_event(sink):
    task = _Task("ingest.process_artifact", _process_artifact, retries=2)
    celery_app._telemetry_task_prerun(task_id="t1")
    celery_app._telemetry_task_postrun(
        task_id="t1", task=task, args=("job-1", "case-abc", "k", "f"), kwargs={}, state="SUCCESS"
    )
    doc = _docs(sink)[0]
    assert doc["kind"] == "task"
    assert doc["outcome"] == "success"
    assert doc["task.name"] == "ingest.process_artifact"
    assert doc["task.queue"] == "ingest"
    assert doc["task.retries"] == 2
    assert doc["case_id"] == "case-abc"
    assert doc["labels"] == {"celery_state": "SUCCESS"}


def test_a_non_success_state_is_recorded_as_a_failure(sink):
    task = _Task("module.run", _run_module)
    celery_app._telemetry_task_prerun(task_id="t2")
    celery_app._telemetry_task_postrun(
        task_id="t2", task=task, args=("run-9", "case-abc", "yara", []),
        kwargs={}, state="FAILURE",
    )
    doc = _docs(sink)[0]
    assert doc["outcome"] == "failure"
    assert doc["labels"] == {"celery_state": "FAILURE"}


def test_failure_signal_records_the_exception_with_its_traceback(sink):
    celery_app._telemetry_task_failure(
        task_id="t3",
        exception=ValueError("boom"),
        args=("job-1", "case-abc", "k", "f"),
        kwargs={},
        einfo="Traceback (most recent call last): …",
        sender=_Task("ingest.process_artifact", _process_artifact),
    )
    doc = _docs(sink)[0]
    assert doc["kind"] == "error"
    assert doc["event"] == "task_failure"
    assert doc["error.type"] == "ValueError"
    assert doc["correlation_id"] == "t3"
    assert doc["case_id"] == "case-abc"
    assert "Traceback" in doc["error.stack"]


def test_postrun_without_a_prerun_does_not_raise(sink):
    # Worker restarts and lost signals happen; a missing start time must not
    # take the task down with it.
    celery_app._telemetry_task_postrun(
        task_id="never-started", task=_Task("x.y", _run_module), args=(), kwargs={}, state="SUCCESS"
    )
    assert _docs(sink)[0]["duration_ms"] == 0.0


def test_prerun_start_times_are_not_leaked(sink):
    celery_app._telemetry_task_prerun(task_id="t4")
    assert "t4" in celery_app._TASK_STARTS
    celery_app._telemetry_task_postrun(
        task_id="t4", task=_Task("x.y", _run_module), args=(), kwargs={}, state="SUCCESS"
    )
    assert "t4" not in celery_app._TASK_STARTS
