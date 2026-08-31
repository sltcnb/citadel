"""Product telemetry — durable, queryable signal about how the platform behaves.

This is the *improvement* channel, and it is deliberately not the same thing as
``logship``:

* ``logship`` is a capped Redis ring buffer (2 000 lines) for tailing a service
  live in the admin console. It answers "what is happening right now?" and is
  gone after a restart or a busy hour.
* ``telemetry`` writes structured events to Elasticsearch, where they survive
  restarts and can be **aggregated**. It answers "which endpoint fails most
  often, which parser is slowest, what does the pilot actually cost, what broke
  in the browser last week?" — the questions you have to answer before you can
  decide what to improve.

Design constraints, in priority order:

1. **Never break the caller.** Every public function swallows its own errors.
   A dead Elasticsearch degrades telemetry to a drop counter, nothing else.
2. **Never block the caller.** ``emit`` puts a dict on a bounded queue
   (microseconds); a daemon thread bulk-ships batches. A full queue drops the
   newest event rather than applying backpressure to a request or a parse.
3. **Stdlib only.** Same rule as the rest of citadel_contracts, so the API, the
   Celery workers and any standalone tool can all import it.

Documents use dotted field names (``http.status_code``); Elasticsearch expands
those into an object on index, so the flat call site stays readable.
"""

from __future__ import annotations

import atexit
import base64
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

# ── Index / policy naming ─────────────────────────────────────────────────────
INDEX_PREFIX = "citadel-telemetry"
INDEX_PATTERN = f"{INDEX_PREFIX}-*"
TEMPLATE_NAME = INDEX_PREFIX
ILM_POLICY_NAME = f"{INDEX_PREFIX}-retention"

#: Event kinds. Anything else is accepted but won't be summarised by the
#: admin telemetry endpoints, so prefer one of these.
KIND_ERROR = "error"        # an exception the platform did not expect
KIND_REQUEST = "request"    # one HTTP request through the API
KIND_TASK = "task"          # one Celery task / parse / module run
KIND_LLM = "llm"            # one call to a language-model backend
KIND_UI = "ui"              # something the browser reported
KINDS = (KIND_ERROR, KIND_REQUEST, KIND_TASK, KIND_LLM, KIND_UI)

# Field-length caps. Telemetry must not become the biggest index in the
# cluster, and a runaway stack trace is the usual way that happens.
_MAX_MSG = 2000
_MAX_STACK = 8000
_MAX_FIELD = 1024


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _index_for(ts: datetime | None = None) -> str:
    d = ts or datetime.now(UTC)
    return f"{INDEX_PREFIX}-{d:%Y.%m.%d}"


def _truncate(value: Any, limit: int = _MAX_FIELD) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…[truncated]"
    return value


# ── Index template ────────────────────────────────────────────────────────────
# `dynamic: false` on purpose: unknown fields are kept verbatim in _source (so
# nothing a caller sends is ever lost) but are not indexed, so a careless
# `labels` payload can never blow up the field count the way an unbounded
# dynamic mapping would. Add a mapping here when you want to aggregate on a
# field, not before.
_TEMPLATE_BODY: dict = {
    "index_patterns": [INDEX_PATTERN],
    "priority": 200,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "10s",
        },
        "mappings": {
            "dynamic": False,
            "properties": {
                "@timestamp": {"type": "date"},
                "service": {"type": "keyword"},
                "kind": {"type": "keyword"},
                "event": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "duration_ms": {"type": "float"},
                "message": {"type": "text"},
                "case_id": {"type": "keyword"},
                "correlation_id": {"type": "keyword"},
                "host": {"type": "keyword"},
                "version": {"type": "keyword"},
                "error": {
                    "properties": {
                        # `type` + a keyword-normalised `signature` are what you
                        # group by; `message` stays text for reading.
                        "type": {"type": "keyword"},
                        "message": {"type": "text"},
                        "signature": {"type": "keyword"},
                        "stack": {"type": "text", "index": False},
                    }
                },
                "http": {
                    "properties": {
                        "method": {"type": "keyword"},
                        # `route` is the templated path (/cases/{case_id}) —
                        # low cardinality, the one you aggregate on. `path` is
                        # the concrete URL, for reading a single event.
                        "route": {"type": "keyword"},
                        "path": {"type": "keyword"},
                        "status_code": {"type": "short"},
                    }
                },
                "user": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "role": {"type": "keyword"},
                    }
                },
                "task": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "id": {"type": "keyword"},
                        "queue": {"type": "keyword"},
                        "artifact_type": {"type": "keyword"},
                        "plugin": {"type": "keyword"},
                        "module": {"type": "keyword"},
                        "events": {"type": "long"},
                        "retries": {"type": "short"},
                    }
                },
                "llm": {
                    "properties": {
                        "provider": {"type": "keyword"},
                        "model": {"type": "keyword"},
                        "purpose": {"type": "keyword"},
                        "prompt_tokens": {"type": "long"},
                        "completion_tokens": {"type": "long"},
                        "total_tokens": {"type": "long"},
                        "cost_usd": {"type": "double"},
                        "tokens_per_second": {"type": "float"},
                    }
                },
                "ui": {
                    "properties": {
                        "route": {"type": "keyword"},
                        "component": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "user_agent": {"type": "keyword"},
                        "app_version": {"type": "keyword"},
                    }
                },
                "labels": {"type": "flattened"},
            },
        },
    },
}


class TelemetrySink:
    """Buffered, non-blocking Elasticsearch writer for telemetry events.

    One per process. ``emit`` is safe to call from an asyncio event loop, a
    Celery prefork child, or a plain thread — it only touches a queue.
    """

    def __init__(
        self,
        service: str,
        es_url: str,
        *,
        username: str = "",
        password: str = "",
        enabled: bool = True,
        queue_size: int = 5000,
        batch_size: int = 100,
        flush_interval: float = 2.0,
        timeout: float = 10.0,
    ) -> None:
        self.service = service
        self.es_url = (es_url or "").rstrip("/")
        self.enabled = bool(enabled and self.es_url)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.timeout = timeout
        self._auth_header = ""
        if username and password:
            raw = f"{username}:{password}".encode()
            self._auth_header = "Basic " + base64.b64encode(raw).decode()
        self.queue_size = queue_size
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._thread_lock = threading.Lock()
        # Counters surfaced by the admin telemetry health endpoint — the only
        # way to notice that telemetry itself is broken.
        self.stats = {"emitted": 0, "shipped": 0, "dropped": 0, "failed": 0}
        self._last_error: str = ""

    # ── lifecycle ────────────────────────────────────────────────────────────
    # The shipper thread starts on the first emit, not in __init__. Celery runs
    # a *prefork* pool: the worker imports this module, then forks children that
    # execute the tasks. A thread started before the fork does not exist in the
    # child — it would inherit a queue nothing drains and lose every event it
    # ever recorded. Starting lazily means each process starts its own thread
    # the first time it actually has something to say. `_after_fork` below is
    # the backstop for the case where the parent did emit before forking.
    def _start(self) -> None:
        with self._thread_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name=f"citadel-telemetry-{self.service}", daemon=True
            )
            self._thread.start()
            atexit.register(self.close)

    def _after_fork(self) -> None:
        """Rebuild this sink inside a freshly forked child.

        The child inherits a *copy* of the parent's queue whose contents the
        parent is still responsible for shipping, and a thread object for a
        thread that does not exist here. Drop both and start clean.
        """
        self._queue = queue.Queue(maxsize=self.queue_size)
        self._stop = threading.Event()
        self._thread_lock = threading.Lock()
        self._thread = None
        self.stats = {"emitted": 0, "shipped": 0, "dropped": 0, "failed": 0}

    def close(self, timeout: float = 3.0) -> None:
        """Flush what is buffered and stop the shipper. Safe to call twice, and
        on a sink whose thread never started."""
        if not self._thread:
            self._stop.set()
            return
        self._stop.set()
        try:
            self._thread.join(timeout=timeout)
        except Exception:
            pass
        self._thread = None

    # ── write path ───────────────────────────────────────────────────────────
    def emit(self, kind: str, **fields: Any) -> None:
        """Queue one event. Never raises, never blocks."""
        if not self.enabled:
            return
        try:
            doc: dict[str, Any] = {
                "@timestamp": _now_iso(),
                "service": self.service,
                "kind": kind,
            }
            for key, value in fields.items():
                if value is None:
                    continue
                # `labels` is a flattened object; leave its shape alone.
                doc[key] = value if key == "labels" else _truncate(value)
            if self._thread is None or not self._thread.is_alive():
                self._start()
            self.stats["emitted"] += 1
            self._queue.put_nowait(doc)
        except queue.Full:
            # Shedding the newest event is the right trade: telemetry must never
            # slow down ingest or a request just because ES is behind.
            self.stats["dropped"] += 1
        except Exception:
            self.stats["dropped"] += 1

    def _run(self) -> None:
        batch: list[dict] = []
        deadline = time.monotonic() + self.flush_interval
        while not self._stop.is_set():
            timeout = max(0.05, deadline - time.monotonic())
            try:
                batch.append(self._queue.get(timeout=timeout))
            except queue.Empty:
                pass
            if batch and (len(batch) >= self.batch_size or time.monotonic() >= deadline):
                self._ship(batch)
                batch = []
                deadline = time.monotonic() + self.flush_interval
        # Drain on shutdown so the last events of a run aren't lost.
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self._ship(batch)

    def _ship(self, batch: list[dict]) -> None:
        try:
            lines: list[str] = []
            for doc in batch:
                lines.append(json.dumps({"index": {"_index": _index_for()}}))
                lines.append(json.dumps(doc, default=str))
            body = ("\n".join(lines) + "\n").encode()
            resp = self._request("POST", "/_bulk", body, "application/x-ndjson")
            # A bulk call can be HTTP 200 with per-document failures (a mapping
            # conflict, say). Counting those as shipped would hide the problem.
            if resp.get("errors"):
                failed = sum(
                    1
                    for item in resp.get("items", [])
                    if (item.get("index") or {}).get("error")
                )
                self.stats["failed"] += failed
                self.stats["shipped"] += len(batch) - failed
                first = next(
                    (
                        (i.get("index") or {}).get("error")
                        for i in resp.get("items", [])
                        if (i.get("index") or {}).get("error")
                    ),
                    None,
                )
                if first:
                    self._last_error = str(first)[:300]
            else:
                self.stats["shipped"] += len(batch)
        except Exception as exc:
            self.stats["failed"] += len(batch)
            self._last_error = f"{type(exc).__name__}: {exc}"[:300]

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> dict:
        headers = {"Content-Type": content_type}
        if self._auth_header:
            headers["Authorization"] = self._auth_header
        req = urllib.request.Request(
            f"{self.es_url}{path}", data=body, headers=headers, method=method
        )
        # Deliberately urlopen and not the process-wide opener installed by
        # services.elasticsearch — telemetry carries its own scoped credentials
        # and must not depend on another module's global state.
        opener = urllib.request.build_opener()
        with opener.open(req, timeout=self.timeout) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    # ── index management ─────────────────────────────────────────────────────
    def ensure_index_template(self, retention_days: int = 30) -> bool:
        """Install the ILM policy + index template. Best-effort, idempotent."""
        if not self.enabled:
            return False
        template = json.loads(json.dumps(_TEMPLATE_BODY))
        try:
            policy = {
                "policy": {
                    "phases": {
                        "hot": {"actions": {}},
                        "delete": {
                            "min_age": f"{max(1, retention_days)}d",
                            "actions": {"delete": {}},
                        },
                    }
                }
            }
            self._request(
                "PUT", f"/_ilm/policy/{ILM_POLICY_NAME}", json.dumps(policy).encode()
            )
            template["template"]["settings"]["index.lifecycle.name"] = ILM_POLICY_NAME
        except Exception as exc:
            # No ILM (OSS distribution, or no manage_ilm privilege) is fine —
            # prune_old_indices() below is the fallback, called by the API's
            # retention loop.
            self._last_error = f"ilm: {type(exc).__name__}: {exc}"[:300]
        try:
            self._request(
                "PUT",
                f"/_index_template/{TEMPLATE_NAME}",
                json.dumps(template).encode(),
            )
            return True
        except Exception as exc:
            self._last_error = f"template: {type(exc).__name__}: {exc}"[:300]
            return False

    def prune_old_indices(self, retention_days: int = 30) -> list[str]:
        """Delete telemetry indices older than the retention window.

        The belt to ILM's braces: clusters without ILM (or without the privilege
        to define a policy) would otherwise accumulate a daily index forever.
        Returns the names actually deleted.
        """
        if not self.enabled:
            return []
        cutoff = datetime.now(UTC) - timedelta(days=max(1, retention_days))
        deleted: list[str] = []
        try:
            resp = self._request(
                "GET",
                f"/{INDEX_PATTERN}/_settings?filter_path=*.settings.index.provided_name",
            )
            for name in resp:
                suffix = name[len(INDEX_PREFIX) + 1 :]
                try:
                    when = datetime.strptime(suffix, "%Y.%m.%d").replace(tzinfo=UTC)
                except ValueError:
                    continue
                if when < cutoff:
                    try:
                        self._request("DELETE", f"/{name}")
                        deleted.append(name)
                    except Exception:
                        pass
        except Exception as exc:
            self._last_error = f"prune: {type(exc).__name__}: {exc}"[:300]
        return deleted

    def health(self) -> dict:
        return {
            "enabled": self.enabled,
            "service": self.service,
            "queued": self._queue.qsize(),
            "last_error": self._last_error or None,
            **self.stats,
        }


# ── Process-wide singleton ────────────────────────────────────────────────────
_SINK: TelemetrySink | None = None
_SINK_LOCK = threading.Lock()


def init_telemetry(
    service: str,
    *,
    es_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    enabled: bool | None = None,
) -> TelemetrySink:
    """Create (once) the process-wide sink. Later calls return the same one.

    Reads ``ELASTICSEARCH_URL`` / ``ELASTICSEARCH_USERNAME`` /
    ``ELASTICSEARCH_PASSWORD`` and ``CITADEL_TELEMETRY_ENABLED`` from the
    environment unless overridden — so a tool gets working telemetry with a
    one-line call and no config plumbing.
    """
    global _SINK
    with _SINK_LOCK:
        if _SINK is not None:
            return _SINK
        _SINK = TelemetrySink(
            service,
            es_url if es_url is not None else os.getenv("ELASTICSEARCH_URL", ""),
            username=username
            if username is not None
            else os.getenv("ELASTICSEARCH_USERNAME", ""),
            password=password
            if password is not None
            else os.getenv("ELASTICSEARCH_PASSWORD", ""),
            enabled=_env_flag("CITADEL_TELEMETRY_ENABLED", True)
            if enabled is None
            else enabled,
        )
        return _SINK


def get_sink() -> TelemetrySink | None:
    """The process sink, or None when telemetry was never initialised."""
    return _SINK


def _reinit_after_fork() -> None:
    """Give a forked child its own queue and shipper.

    Registered once at import so it covers every fork the process makes —
    Celery's prefork pool above all, but also anything else that forks after
    the sink has already started shipping.
    """
    sink = _SINK
    if sink is not None:
        try:
            sink._after_fork()
        except Exception:  # noqa: BLE001 — never break a fork over telemetry
            pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reinit_after_fork)


def reset_telemetry() -> None:
    """Tear down the singleton — for tests, which need a fresh sink per case."""
    global _SINK
    with _SINK_LOCK:
        if _SINK is not None:
            _SINK.close(timeout=1.0)
        _SINK = None


def emit(kind: str, **fields: Any) -> None:
    """Emit one event through the process sink; a no-op if there isn't one."""
    sink = _SINK
    if sink is not None:
        sink.emit(kind, **fields)


def retention_days() -> int:
    try:
        return max(1, int(os.getenv("CITADEL_TELEMETRY_RETENTION_DAYS", "30")))
    except ValueError:
        return 30


# ── Typed helpers ─────────────────────────────────────────────────────────────
# Call sites use these rather than raw emit() so field names stay consistent
# across api / workers / tools — an aggregation is only as good as the
# discipline of the thing writing the documents.


def _merge(base: dict, extra: dict) -> dict:
    """Caller-supplied fields win over the helper's defaults, and a duplicate
    key is an override rather than a ``TypeError`` from two ``**`` unpackings."""
    merged = dict(base)
    merged.update(extra)
    return merged


def error_signature(exc_type: str, message: str) -> str:
    """A stable, low-cardinality key for "the same error happening again".

    Digits, hex ids, UUIDs and quoted values are the parts that differ between
    two occurrences of one bug, so they are replaced before the string becomes
    a keyword you can group by.
    """
    import re

    sig = f"{exc_type}: {message}"
    sig = re.sub(r"0x[0-9a-fA-F]+", "<addr>", sig)
    sig = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<id>", sig)
    sig = re.sub(r"\b\d+\b", "<n>", sig)
    sig = re.sub(r"'[^']*'", "'<v>'", sig)
    return sig[:200]


def record_error(
    exc: BaseException | None = None,
    *,
    event: str = "unhandled_exception",
    message: str = "",
    stack: str = "",
    correlation_id: str = "",
    **fields: Any,
) -> None:
    """Record an exception the platform did not expect."""
    exc_type = type(exc).__name__ if exc is not None else "Error"
    msg = message or (str(exc) if exc is not None else "")
    emit(KIND_ERROR, **_merge(
        {
            "event": event,
            "outcome": "failure",
            "correlation_id": correlation_id or None,
            "message": _truncate(msg, _MAX_MSG),
            "error.type": exc_type,
            "error.message": _truncate(msg, _MAX_MSG),
            "error.signature": error_signature(exc_type, msg),
            "error.stack": _truncate(stack, _MAX_STACK) if stack else None,
        },
        fields,
    ))


def record_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    *,
    route: str = "",
    user: str = "",
    role: str = "",
    case_id: str = "",
    **fields: Any,
) -> None:
    """Record one HTTP request. Callers decide what to sample; this just writes."""
    emit(KIND_REQUEST, **_merge(
        {
            "event": "http_request",
            "outcome": "failure" if status_code >= 500 else "success",
            "duration_ms": round(float(duration_ms), 2),
            "case_id": case_id or None,
            "http.method": method,
            "http.path": path,
            "http.route": route or path,
            "http.status_code": int(status_code),
            "user.name": user or None,
            "user.role": role or None,
        },
        fields,
    ))


def record_task(
    name: str,
    outcome: str,
    duration_ms: float,
    *,
    task_id: str = "",
    queue_name: str = "",
    artifact_type: str = "",
    plugin: str = "",
    module: str = "",
    events: int | None = None,
    case_id: str = "",
    retries: int | None = None,
    message: str = "",
    **fields: Any,
) -> None:
    """Record one background unit of work — a Celery task, parse, or module run."""
    emit(KIND_TASK, **_merge(
        {
            "event": name,
            "outcome": outcome,
            "duration_ms": round(float(duration_ms), 2),
            "case_id": case_id or None,
            "message": _truncate(message, _MAX_MSG) if message else None,
            "task.name": name,
            "task.id": task_id or None,
            "task.queue": queue_name or None,
            "task.artifact_type": artifact_type or None,
            "task.plugin": plugin or None,
            "task.module": module or None,
            "task.events": events,
            "task.retries": retries,
        },
        fields,
    ))


def record_llm(
    provider: str,
    model: str,
    *,
    outcome: str = "success",
    purpose: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    cost_usd: float | None = None,
    duration_ms: float | None = None,
    tokens_per_second: float | None = None,
    message: str = "",
    **fields: Any,
) -> None:
    """Record one LLM call — cost, size, latency and whether it worked.

    Redis already keeps rolling usage counters for the dashboard; this keeps the
    *per-call* record, which is what tells you which prompt purpose is slow,
    expensive, or failing.
    """
    total = int(prompt_tokens or 0) + int(completion_tokens or 0)
    emit(KIND_LLM, **_merge(
        {
            "event": "llm_call",
            "outcome": outcome,
            "duration_ms": round(float(duration_ms), 2) if duration_ms is not None else None,
            "message": _truncate(message, _MAX_MSG) if message else None,
            "llm.provider": provider or "unknown",
            "llm.model": model or "unknown",
            "llm.purpose": purpose or None,
            "llm.prompt_tokens": int(prompt_tokens or 0),
            "llm.completion_tokens": int(completion_tokens or 0),
            "llm.total_tokens": total,
            "llm.cost_usd": float(cost_usd) if cost_usd is not None else None,
            "llm.tokens_per_second": tokens_per_second,
        },
        fields,
    ))


def record_ui_event(
    event: str,
    *,
    message: str = "",
    route: str = "",
    component: str = "",
    source: str = "",
    stack: str = "",
    user_agent: str = "",
    app_version: str = "",
    user: str = "",
    outcome: str = "failure",
    **fields: Any,
) -> None:
    """Record something the browser reported (a render crash, a failed request)."""
    emit(KIND_UI, **_merge(
        {
            "event": event,
            "outcome": outcome,
            "message": _truncate(message, _MAX_MSG),
            "error.type": "UIError",
            "error.message": _truncate(message, _MAX_MSG),
            "error.signature": error_signature("UIError", message),
            "error.stack": _truncate(stack, _MAX_STACK) if stack else None,
            "ui.route": route or None,
            "ui.component": component or None,
            "ui.source": source or None,
            "ui.user_agent": _truncate(user_agent, 300) if user_agent else None,
            "ui.app_version": app_version or None,
            "user.name": user or None,
        },
        fields,
    ))
