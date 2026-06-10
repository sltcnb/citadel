"""Observability for the Citadel worker — stdlib-only, zero hard deps.

Provides the three things every tool in the suite should expose (ROADMAP §4
Observability), without requiring prometheus_client / OTel to be installed:

  * **structured logs**  — ``setup_json_logging()`` emits one JSON object per line.
  * **metrics**          — a tiny counter/gauge registry rendered in the
    Prometheus text exposition format (``render_prometheus()``).
  * **health**           — ``start_health_server(port, checks)`` serves
    ``/healthz`` (liveness), ``/readyz`` (runs the supplied readiness checks) and
    ``/metrics`` on a background thread.

If ``prometheus_client`` / OpenTelemetry are present a richer exporter can be
layered on top; this module guarantees a baseline that always works.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


# ── structured logs ──────────────────────────────────────────────────────────
class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
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
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


# Redis stream key for a service's recent logs — read by the admin log viewer.
def log_stream_key(service: str) -> str:
    return f"citadel:logs:{service}"


class RedisLogHandler(logging.Handler):
    """Ship structured log records to a capped Redis stream so an admin can tail
    a tool's recent logs from the console. Best-effort: never raises into the
    app, and degrades to a no-op if redis is unavailable.

    Capped via XADD MAXLEN so it can't grow unbounded (a ring buffer).
    """

    def __init__(
        self, service: str, redis_client, *, maxlen: int = 2000, level: int = logging.INFO
    ) -> None:
        super().__init__(level)
        self.service = service
        self.redis = redis_client
        self.maxlen = maxlen
        self.key = log_stream_key(service)
        self.setFormatter(_JsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.redis.xadd(
                self.key,
                {
                    "svc": self.service,
                    "level": record.levelname,
                    "logger": record.name,
                    "line": self.format(record),
                },
                maxlen=self.maxlen,
                approximate=True,
            )
        except Exception:
            pass  # logging must never break the app


def attach_redis_logs(service: str, redis_client, *, level: int = logging.INFO) -> None:
    """Attach a RedisLogHandler to the root logger (in addition to stdout)."""
    logging.getLogger().addHandler(RedisLogHandler(service, redis_client, level=level))


# ── metrics registry ─────────────────────────────────────────────────────────
class Metrics:
    """Minimal counter/gauge registry with Prometheus text rendering."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple], float] = {}
        self._gauges: dict[tuple[str, tuple], float] = {}
        self._help: dict[str, str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(name: str, labels: dict | None) -> tuple[str, tuple]:
        return name, tuple(sorted((labels or {}).items()))

    def inc(
        self, name: str, value: float = 1.0, *, labels: dict | None = None, help: str = ""
    ) -> None:
        with self._lock:
            self._help.setdefault(name, help or name)
            self._counters[self._key(name, labels)] = (
                self._counters.get(self._key(name, labels), 0.0) + value
            )

    def gauge(self, name: str, value: float, *, labels: dict | None = None, help: str = "") -> None:
        with self._lock:
            self._help.setdefault(name, help or name)
            self._gauges[self._key(name, labels)] = value

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for kind, store in (("counter", self._counters), ("gauge", self._gauges)):
                seen: set[str] = set()
                for (name, labels), val in sorted(store.items()):
                    if name not in seen:
                        lines.append(f"# HELP {name} {self._help.get(name, name)}")
                        lines.append(f"# TYPE {name} {kind}")
                        seen.add(name)
                    lbl = ("{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}") if labels else ""
                    lines.append(f"{name}{lbl} {val}")
        return "\n".join(lines) + "\n"


METRICS = Metrics()


# ── health server ─────────────────────────────────────────────────────────────
def _make_handler(checks: dict[str, Callable[[], bool]]):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silence default stderr logging
            return

        def _send(self, code: int, body: str, ctype: str = "application/json"):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("/healthz", "/health"):
                self._send(200, json.dumps({"status": "ok"}))
            elif self.path.rstrip("/") in ("/readyz", "/ready"):
                results = {name: bool(fn()) for name, fn in checks.items()}
                ok = all(results.values()) if results else True
                self._send(
                    200 if ok else 503,
                    json.dumps({"status": "ok" if ok else "degraded", "checks": results}),
                )
            elif self.path.rstrip("/") == "/metrics":
                self._send(200, METRICS.render_prometheus(), "text/plain; version=0.0.4")
            else:
                self._send(404, json.dumps({"error": "not found"}))

    return _Handler


def start_health_server(
    port: int = 9100, checks: dict[str, Callable[[], bool]] | None = None
) -> HTTPServer:
    """Start the health/metrics server on a daemon thread; returns the server."""
    server = HTTPServer(("0.0.0.0", port), _make_handler(checks or {}))
    threading.Thread(target=server.serve_forever, daemon=True, name="citadel-health").start()
    return server
