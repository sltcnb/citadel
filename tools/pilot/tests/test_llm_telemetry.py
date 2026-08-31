"""Per-call LLM telemetry.

Redis counters already told us the total. What they could not tell us is which
*kind* of call is slow, expensive or failing — so every call now also lands in
the telemetry index tagged with its purpose. These tests pin the two things
that are easy to get subtly wrong: that the purpose is the calling endpoint
(not an internal helper), and that a provider failure is recorded on its way
past rather than silently disappearing into the caller's except block.
"""

from __future__ import annotations

import json

import pilot.service as svc
import pytest
from citadel_contracts import telemetry as t

CFG = {"provider": "anthropic", "model": "claude-opus-5", "api_key": "k"}


@pytest.fixture
def sink(monkeypatch):
    """A telemetry sink whose bulk writes are captured instead of sent."""
    t.reset_telemetry()
    s = t.TelemetrySink("api", "http://es.invalid", flush_interval=0.05)
    s.sent = []
    s._request = lambda m, p, b=None, c="application/json": s.sent.append(b) or {}
    monkeypatch.setattr(t, "_SINK", s)
    yield s
    t.reset_telemetry()


def _docs(sink) -> list[dict]:
    sink.close()
    return [
        json.loads(line)
        for body in sink.sent
        for line in body.decode().strip().split("\n")[1::2]
    ]


def test_purpose_is_the_calling_endpoint_not_the_llm_plumbing(sink, monkeypatch):
    monkeypatch.setattr(
        svc,
        "_call_llm_with_system_impl",
        lambda cfg, s, u, max_tokens=600, json_mode=False: (
            svc._track_llm_usage("anthropic", cfg["model"], 120, 45) or "answer"
        ),
    )

    def investigate_case():  # stands in for the real endpoint
        return svc._call_llm_with_system(CFG, "system", "user")

    assert investigate_case() == "answer"
    doc = _docs(sink)[0]
    assert doc["kind"] == "llm"
    assert doc["outcome"] == "success"
    assert doc["llm.purpose"] == "investigate_case"
    assert doc["llm.total_tokens"] == 165
    assert doc["labels"] == {"component": "pilot"}
    assert doc["duration_ms"] is not None


def test_a_provider_failure_is_recorded_and_still_raised(sink, monkeypatch):
    def _timeout(*_a, **_kw):
        raise TimeoutError("read timeout")

    monkeypatch.setattr(svc, "_call_llm_with_system_impl", _timeout)

    def generate_yara_rule():
        return svc._call_llm_with_system(CFG, "system", "user")

    with pytest.raises(TimeoutError):
        generate_yara_rule()

    doc = _docs(sink)[0]
    assert doc["outcome"] == "failure"
    assert doc["llm.purpose"] == "generate_yara_rule"
    assert "read timeout" in doc["message"]


def test_call_llm_is_wrapped_too(sink, monkeypatch):
    monkeypatch.setattr(
        svc,
        "_call_llm_impl",
        lambda cfg, prompt: svc._track_llm_usage("ollama", "llama3", 10, 5) or "ok",
    )

    def analyze_module_run():
        return svc._call_llm(CFG, "prompt")

    assert analyze_module_run() == "ok"
    assert _docs(sink)[0]["llm.purpose"] == "analyze_module_run"


def test_telemetry_being_broken_does_not_break_an_llm_call(monkeypatch):
    # The whole point of a best-effort sink: if recording throws, the analyst
    # still gets their answer.
    t.reset_telemetry()

    def _explode(*_a, **_kw):
        raise RuntimeError("telemetry is on fire")

    monkeypatch.setattr(t, "emit", _explode)
    monkeypatch.setattr(svc, "record_llm", _explode, raising=False)
    monkeypatch.setattr(
        svc, "_call_llm_with_system_impl", lambda *a, **k: "answer"
    )
    assert svc._call_llm_with_system(CFG, "system", "user") == "answer"


def test_redis_usage_counters_still_run_when_telemetry_is_disabled(monkeypatch):
    # The dashboard's rolling counters predate telemetry and must keep working
    # on their own; telemetry is additive, not a replacement.
    t.reset_telemetry()
    calls = {}

    class _FakeRedis:
        def hincrby(self, key, field, n=1):
            calls[field] = calls.get(field, 0) + n

        def hincrbyfloat(self, *a):
            pass

        def expire(self, *a):
            pass

    monkeypatch.setattr(svc, "_redis", lambda: _FakeRedis())
    svc._track_llm_usage("anthropic", "claude-opus-5", 10, 5)
    assert calls["total_calls"] == 1
    assert calls["total_tokens"] == 15
