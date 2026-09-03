"""Elasticsearch bulk indexing must not lose evidence silently.

_bulk answers HTTP 200 even when individual documents are rejected (mapping
conflict, field type mismatch). Those rejections used to be logged and then
swallowed, so an ingest job reported success while events were missing from the
case — for a tool whose output is evidence that is the worst outcome, because an
analyst cannot tell an empty result from a dropped one.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sluice" / "worker"))

from utils.es_bulk import ESBulkIndexer, ESBulkPartialFailure  # noqa: E402


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _Session:
    """Stands in for requests.Session, returning a scripted _bulk response."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def post(self, *_a, **_kw):
        self.calls += 1
        return _Resp(self.payload)


def _indexer(payload):
    ix = ESBulkIndexer.__new__(ESBulkIndexer)   # skip __init__ (opens sockets)
    ix.es_url = "http://es:9200"
    ix._session = _Session(payload)
    return ix


EVENTS = [
    {"fo_id": "a", "artifact_type": "evtx", "message": "one"},
    {"fo_id": "b", "artifact_type": "evtx", "message": "two"},
]


def test_clean_bulk_returns_the_indexed_count():
    ix = _indexer({"errors": False, "items": []})
    assert ix.bulk_index("case1", EVENTS) == 2


def test_empty_event_list_is_a_no_op():
    ix = _indexer({"errors": False, "items": []})
    assert ix.bulk_index("case1", []) == 0
    assert ix._session.calls == 0


def test_rejected_document_raises_instead_of_being_swallowed():
    ix = _indexer({
        "errors": True,
        "items": [
            {"index": {"_id": "a", "status": 201}},
            {"index": {"_id": "b", "status": 400,
                       "error": {"type": "mapper_parsing_exception",
                                 "reason": "failed to parse field [ts]"}}},
        ],
    })
    with pytest.raises(ESBulkPartialFailure) as exc:
        ix.bulk_index("case1", EVENTS)
    assert exc.value.failed == 1
    assert exc.value.total == 2


def test_failure_names_the_dropped_document_so_it_is_attributable():
    ix = _indexer({
        "errors": True,
        "items": [{"index": {"_id": "fo-123", "status": 400,
                             "error": {"type": "mapper_parsing_exception",
                                       "reason": "bad field"}}}],
    })
    with pytest.raises(ESBulkPartialFailure) as exc:
        ix.bulk_index("case1", EVENTS[:1])
    message = str(exc.value)
    assert "fo-123" in message
    assert "mapper_parsing_exception" in message


def test_it_is_a_runtime_error_so_task_retry_paths_catch_it():
    assert issubclass(ESBulkPartialFailure, RuntimeError)
