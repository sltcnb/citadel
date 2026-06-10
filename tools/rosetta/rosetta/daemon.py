"""Rosetta daemon — watch a directory, normalize new ForensicEvent JSONL to ECS.

    rosetta daemon --watch /var/log/forensic --es http://es:9200
    rosetta daemon --watch ./incoming -o ./ecs/out.jsonl --once

Each new ``*.jsonl`` file that appears in the watch directory is read, every
ForensicEvent line is normalized to ECS, and the resulting docs are handed to a
**sink**. Sinks are injectable so tests run offline against a list. A bounded,
disk-backed buffer provides backpressure: if the sink rejects a batch the docs
spill to ``<watch>/.rosetta_spool`` and are retried on the next pass instead of
being lost.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Protocol

from .normalize import Normalizer, load_fieldmap


class Sink(Protocol):
    """Where normalized ECS docs go. ``write`` may raise to signal backpressure."""

    def write(self, docs: list[dict[str, Any]]) -> None: ...


class FileSink:
    """Append ECS docs as JSONL to a single output file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, docs: list[dict[str, Any]]) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            for d in docs:
                fh.write(json.dumps(d, ensure_ascii=False, default=str) + "\n")


class ESSink:
    """Bulk-index ECS docs into Elasticsearch. ``session`` is injectable (tests
    pass a fake with ``.post``); raises on a non-2xx so the buffer retries."""

    def __init__(self, url: str, index: str = "citadel-events", session: Any = None) -> None:
        self.url = url.rstrip("/")
        self.index = index
        if session is None:
            import requests  # lazy: only needed for real ES output

            session = requests.Session()
        self.session = session

    def write(self, docs: list[dict[str, Any]]) -> None:
        lines = []
        for d in docs:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(d, default=str))
        body = "\n".join(lines) + "\n"
        resp = self.session.post(
            f"{self.url}/_bulk",
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        status = getattr(resp, "status_code", 200)
        if status >= 300:
            raise RuntimeError(f"ES bulk failed: HTTP {status}")


class _Spool:
    """Disk-backed overflow buffer for docs a sink could not accept (backpressure)."""

    def __init__(self, root: Path, max_docs: int = 100_000) -> None:
        self.dir = root / ".rosetta_spool"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_docs = max_docs

    def spill(self, docs: list[dict[str, Any]]) -> None:
        if not docs:
            return
        # Cap retained docs so a wedged sink can't fill the disk unbounded.
        f = self.dir / f"spool_{int(time.time() * 1000)}.jsonl"
        with f.open("w", encoding="utf-8") as fh:
            for d in docs[: self.max_docs]:
                fh.write(json.dumps(d, default=str) + "\n")

    def drain(self) -> list[tuple[Path, list[dict[str, Any]]]]:
        out = []
        for f in sorted(self.dir.glob("spool_*.jsonl")):
            docs = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
            out.append((f, docs))
        return out


class Daemon:
    def __init__(
        self,
        watch: str | Path,
        sink: Sink,
        *,
        ecs_version: str | None = None,
        fieldmap_path: str | None = None,
        glob: str = "*.jsonl",
    ) -> None:
        self.watch = Path(watch)
        self.watch.mkdir(parents=True, exist_ok=True)
        self.sink = sink
        self.glob = glob
        self.normalizer = Normalizer(load_fieldmap(fieldmap_path), ecs_version=ecs_version)
        self.spool = _Spool(self.watch)
        self._seen: set[str] = set()
        self.stats = {"files": 0, "events_in": 0, "events_out": 0, "spilled": 0}

    def _normalize_file(self, path: Path) -> list[dict[str, Any]]:
        docs = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            self.stats["events_in"] += 1
            try:
                docs.append(self.normalizer.normalize(json.loads(line)))
            except json.JSONDecodeError:
                continue
        return docs

    def _emit(self, docs: list[dict[str, Any]]) -> None:
        if not docs:
            return
        try:
            self.sink.write(docs)
            self.stats["events_out"] += len(docs)
        except Exception:
            self.spool.spill(docs)  # backpressure: keep, retry next pass
            self.stats["spilled"] += len(docs)

    def scan_once(self) -> dict[str, int]:
        """One pass: retry the spool, then process newly-seen files."""
        for f, docs in self.spool.drain():
            try:
                self.sink.write(docs)
                self.stats["events_out"] += len(docs)
                self.stats["spilled"] -= len(docs)
                f.unlink()
            except Exception:
                break  # sink still down; leave the rest spooled
        for path in sorted(self.watch.glob(self.glob)):
            key = f"{path.name}:{path.stat().st_mtime_ns}"
            if key in self._seen:
                continue
            self._seen.add(key)
            self.stats["files"] += 1
            self._emit(self._normalize_file(path))
        return dict(self.stats)

    def run(self, interval: float = 2.0, once: bool = False) -> dict[str, int]:
        self.scan_once()
        while not once:
            time.sleep(interval)
            self.scan_once()
        return dict(self.stats)
