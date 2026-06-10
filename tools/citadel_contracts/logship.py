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
            self.redis.xadd(
                self.key,
                {"svc": self.service, "level": record.levelname,
                 "logger": record.name, "line": self.format(record)},
                maxlen=self.maxlen, approximate=True,
            )
        except Exception:
            pass  # logging must never break the app


def attach_redis_logs(service: str, redis_client, *, level: int = logging.INFO) -> None:
    """Attach a RedisLogHandler to the root logger (in addition to stdout)."""
    logging.getLogger().addHandler(
        RedisLogHandler(service, redis_client, level=level))
