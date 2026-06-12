"""Structured-log shipping — shared by every tool + the platform.

Dependency-free (the redis client is injected). A tool calls
``attach_redis_logs(service, redis_client)`` and its log records are mirrored,
as JSON, to a capped Redis stream ``citadel:logs:<service>`` that the admin
console reads. Lives in citadel_contracts so api, the worker, and any tool use
the same shipping path without importing each other.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """One JSON object per record."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for k, v in getattr(record, "extra_fields", {}).items():
            payload[k] = v
        return json.dumps(payload, default=str)


def setup_json_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


def log_stream_key(service: str) -> str:
    """Redis stream key for a service's recent logs (read by the admin viewer)."""
    return f"citadel:logs:{service}"


class RedisLogHandler(logging.Handler):
    """Ship structured records to a capped Redis stream (a ring buffer).

    Best-effort: never raises into the app, and degrades to a no-op if redis is
    unavailable. Capped via XADD MAXLEN so it can't grow unbounded.
    """

    def __init__(self, service: str, redis_client, *, maxlen: int = 2000,
                 level: int = logging.INFO) -> None:
        super().__init__(level)
        self.service = service
        self.redis = redis_client
        self.maxlen = maxlen
        self.key = log_stream_key(service)
        self.setFormatter(JsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ts = datetime.fromtimestamp(record.created, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            fields = {
                "svc": self.service,
                "ts": ts,
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
            if record.exc_info:
                fields["exc"] = self.formatException(record.exc_info)
            # `line` kept for backward compatibility with older viewers.
            fields["line"] = self.format(record)
            self.redis.xadd(
                self.key, fields, maxlen=self.maxlen, approximate=True
            )
        except Exception:
            pass  # logging must never break the app


def _async_handler(target: logging.Handler) -> logging.Handler:
    """Wrap a (possibly slow) handler so emission happens on a background thread.

    The Redis ``xadd`` in RedisLogHandler is synchronous; calling it directly
    from request/event-loop code blocks until the round-trip completes. A
    QueueHandler just enqueues the record (microseconds, no I/O) and a single
    QueueListener thread drains the queue into the real handler — so logging
    never sits in a hot path. One listener per wrapped handler, started once.
    """
    import queue
    from logging.handlers import QueueHandler, QueueListener

    q: queue.Queue = queue.Queue(maxsize=10000)
    qh = QueueHandler(q)
    qh.setLevel(target.level)
    listener = QueueListener(q, target, respect_handler_level=True)
    listener.daemon = True
    listener.start()
    # Keep a ref so the listener thread isn't GC'd.
    qh._listener = listener  # type: ignore[attr-defined]
    return qh


def attach_redis_logs(service: str, redis_client, *, level: int = logging.INFO) -> None:
    """Attach a non-blocking RedisLogHandler to the root logger (plus stdout).

    Also lowers the root logger level to `level` when it is currently higher
    (e.g. uvicorn's default WARNING) — otherwise INFO records are filtered at the
    logger before ever reaching the handler, so the api/processor streams stay
    empty while a tool's own dedicated logger (set to INFO) still ships.
    """
    root = logging.getLogger()
    if root.level == logging.NOTSET or root.level > level:
        root.setLevel(level)
    root.addHandler(_async_handler(RedisLogHandler(service, redis_client, level=level)))


# Per-tool log streams: each tool's activity goes to citadel:logs:<tool> so the
# admin console can show tool-specific logs. Lazy + cached — one handler per
# tool per process. The logger does NOT propagate to root, so a tool's lines
# land only in its own stream (not duplicated into api/processor).
_TOOL_LOGGERS: set = set()


def tool_logger(tool: str, redis_client, *, level: int = logging.INFO):
    """Return a logger whose records ship to citadel:logs:<tool>."""
    lg = logging.getLogger(f"citadel.tool.{tool}")
    if tool not in _TOOL_LOGGERS:
        lg.addHandler(_async_handler(RedisLogHandler(tool, redis_client, level=level)))
        lg.setLevel(level)
        lg.propagate = True  # also reach stdout/root for cluster logs
        _TOOL_LOGGERS.add(tool)
    return lg
