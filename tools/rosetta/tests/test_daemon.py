"""Daemon tests — EVTX + syslog ForensicEvent files -> ECS via a fake sink, offline."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rosetta.daemon import Daemon  # noqa: E402


class ListSink:
    """Offline sink that just collects docs (no network)."""

    def __init__(self):
        self.docs = []

    def write(self, docs):
        self.docs.extend(docs)


class FlakySink:
    """Fails the first N writes to exercise backpressure/spool retry."""

    def __init__(self, fail_times):
        self.fail_times = fail_times
        self.docs = []

    def write(self, docs):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("sink down")
        self.docs.extend(docs)


def _write(p: Path, events):
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")


EVTX = {"timestamp": "2026-01-02T03:04:05Z", "message": "logon", "artifact_type": "windows_event"}
SYSLOG = {
    "timestamp": "2026-01-02T03:04:06Z",
    "message": "sshd accepted",
    "artifact_type": "syslog",
}


def test_daemon_normalizes_evtx_and_syslog(tmp_path):
    sink = ListSink()
    _write(tmp_path / "a.jsonl", [EVTX, SYSLOG])
    d = Daemon(tmp_path, sink, ecs_version="8.11")
    stats = d.run(once=True)
    assert stats["events_in"] == 2 and stats["events_out"] == 2
    # ECS event.category was assigned on at least one doc (may be list or str).
    assert any(doc.get("event", {}).get("category") for doc in sink.docs)
    assert all(doc["@timestamp"] for doc in sink.docs)
    assert all(doc["ecs"]["version"] == "8.11" for doc in sink.docs)


def test_backpressure_spools_then_retries(tmp_path):
    sink = FlakySink(fail_times=1)
    _write(tmp_path / "a.jsonl", [EVTX])
    d = Daemon(tmp_path, sink, ecs_version="8.11")
    d.scan_once()  # first write fails -> spilled
    assert d.stats["spilled"] == 1 and not sink.docs
    d.scan_once()  # spool retried -> delivered
    assert sink.docs and d.stats["spilled"] == 0


def test_file_seen_once(tmp_path):
    sink = ListSink()
    _write(tmp_path / "a.jsonl", [EVTX])
    d = Daemon(tmp_path, sink)
    d.scan_once()
    d.scan_once()  # second pass must not re-emit
    assert len(sink.docs) == 1


if __name__ == "__main__":
    import tempfile

    n = 0
    for fn in [
        test_daemon_normalizes_evtx_and_syslog,
        test_backpressure_spools_then_retries,
        test_file_seen_once,
    ]:
        with tempfile.TemporaryDirectory() as td:
            fn(Path(td))
            n += 1
            print(f"PASS  {fn.__name__}")
    print(f"\n{n}/{n} passed")
