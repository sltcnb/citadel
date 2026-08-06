"""Tests for _index_module_findings_to_es (the unified findings store writer).

Regression: hit constructors stamp their unique key as ``id``, but the writer
read ``hit["fo_id"]`` — always missing — so the dedup_key degraded to
``{run_id}:{rule_title}`` and every same-title hit in a run produced the same
deterministic finding id, overwriting each other in ES (500 hits → ~40 docs).
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("celery")

_WORKER_ROOT = Path(__file__).resolve().parents[1]
_TASKS_DIR = _WORKER_ROOT / "tasks"
_TOOLS_DIR = _WORKER_ROOT.parents[1]  # tools/sluice/worker -> tools/

for _p in (str(_WORKER_ROOT), str(_TASKS_DIR), str(_TOOLS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import module_task as mt
except ModuleNotFoundError:
    pytest.skip("module_task's hard dependency chain is unavailable", allow_module_level=True)


def _capture_bulk(monkeypatch) -> list[str]:
    """Intercept the ES _bulk POST body."""
    bodies: list[str] = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def _fake_urlopen(req, timeout=None):
        bodies.append(req.data.decode())
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
    return bodies


def _docs_by_id(body: str) -> dict[str, dict]:
    lines = [json.loads(line) for line in body.splitlines() if line.strip()]
    actions, docs = lines[0::2], lines[1::2]
    return {a["index"]["_id"]: d for a, d in zip(actions, docs, strict=True)}


def test_findings_keep_distinct_same_title_hits(monkeypatch):
    """Two hits with the same rule_title but distinct ids must index as two
    separate finding documents, not overwrite each other."""
    bodies = _capture_bulk(monkeypatch)
    hits = [
        {"id": "hit-aaa", "rule_title": "Same Rule", "level": "high", "timestamp": ""},
        {"id": "hit-bbb", "rule_title": "Same Rule", "level": "high", "timestamp": ""},
    ]

    n = mt._index_module_findings_to_es("case1", "run1", "yara", hits, "2026-08-01T00:00:00Z")

    assert n == 2
    indexed = _docs_by_id(bodies[0])
    assert len(indexed) == 2  # distinct ES _ids — no collapse
    evidences = sorted(tuple(d["evidence"]) for d in indexed.values())
    assert evidences == [("hit-aaa",), ("hit-bbb",)]


def test_findings_prefer_fo_id_over_id(monkeypatch):
    """A hit that carries a real fo_id keeps it for evidence and dedup."""
    bodies = _capture_bulk(monkeypatch)
    hits = [
        {
            "id": "hit-aaa",
            "fo_id": "event-123",
            "rule_title": "Some Rule",
            "level": "medium",
            "timestamp": "",
        }
    ]

    mt._index_module_findings_to_es("case1", "run1", "yara", hits, "2026-08-01T00:00:00Z")

    (doc,) = _docs_by_id(bodies[0]).values()
    assert doc["evidence"] == ["event-123"]


def test_findings_fall_back_to_title_when_no_id(monkeypatch):
    """A hit with neither fo_id nor id still indexes (dedup by title, as
    before) — the fix must not break id-less hits."""
    bodies = _capture_bulk(monkeypatch)
    hits = [{"rule_title": "Bare Rule", "level": "low", "timestamp": ""}]

    n = mt._index_module_findings_to_es("case1", "run1", "yara", hits, "2026-08-01T00:00:00Z")

    assert n == 1
    (doc,) = _docs_by_id(bodies[0]).values()
    assert doc["evidence"] == []
    assert doc["message"] == "Bare Rule"
