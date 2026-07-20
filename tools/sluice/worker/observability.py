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
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer


# ── structured logs ──────────────────────────────────────────────────────────
# Log shipping is shared via citadel_contracts so api + every tool use the same
# path. Bootstrap sys.path so it resolves however this module is loaded
# (dev tree: walk up to the monorepo's tools/ dir; container/standalone:
# pip-installed or PYTHONPATH=/app).
import sys as _sys
from pathlib import Path as _Path

_cp = next(
    (p for p in _Path(__file__).resolve().parents
     if (p / "citadel_contracts" / "__init__.py").exists()),
    None,
)
if _cp is not None and str(_cp) not in _sys.path:
    _sys.path.insert(0, str(_cp))

from citadel_contracts.logship import (  # noqa: E402,F401
    JsonFormatter as _JsonFormatter,
    RedisLogHandler,
    attach_redis_logs,
    log_stream_key,
    setup_json_logging,
)


# ── metrics registry ─────────────────────────────────────────────────────────
#: Default histogram bucket boundaries (seconds) — spans sub-second parses up
#: to the multi-minute end of the distribution (large EVTX/registry hives,
#: memory images). Shared by every histogram unless the caller overrides it.
DEFAULT_DURATION_BUCKETS: tuple[float, ...] = (
    0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600,
)


class Metrics:
    """Minimal counter/gauge/histogram registry with Prometheus text rendering."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple], float] = {}
        self._gauges: dict[tuple[str, tuple], float] = {}
        # histogram bucket counts: (name, labels) -> {bucket_le: count}
        self._hist_buckets: dict[tuple[str, tuple], dict[float, int]] = {}
        self._hist_sum: dict[tuple[str, tuple], float] = {}
        self._hist_count: dict[tuple[str, tuple], int] = {}
        self._hist_bounds: dict[str, tuple[float, ...]] = {}
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

    def observe(
        self,
        name: str,
        value: float,
        *,
        labels: dict | None = None,
        buckets: tuple[float, ...] = DEFAULT_DURATION_BUCKETS,
        help: str = "",
    ) -> None:
        """Record one observation (e.g. a parse duration) into a histogram."""
        key = self._key(name, labels)
        with self._lock:
            self._help.setdefault(name, help or name)
            self._hist_bounds.setdefault(name, buckets)
            bucket_counts = self._hist_buckets.setdefault(key, {b: 0 for b in buckets})
            for b in buckets:
                if value <= b:
                    bucket_counts[b] += 1
            self._hist_sum[key] = self._hist_sum.get(key, 0.0) + value
            self._hist_count[key] = self._hist_count.get(key, 0) + 1

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

            seen_hist: set[str] = set()
            for (name, labels), bucket_counts in sorted(self._hist_buckets.items()):
                if name not in seen_hist:
                    lines.append(f"# HELP {name} {self._help.get(name, name)}")
                    lines.append(f"# TYPE {name} histogram")
                    seen_hist.add(name)
                base_labels = list(labels)
                for b in self._hist_bounds.get(name, DEFAULT_DURATION_BUCKETS):
                    lbl_items = [*base_labels, ("le", b)]
                    lbl = "{" + ",".join(f'{k}="{v}"' for k, v in lbl_items) + "}"
                    lines.append(f"{name}_bucket{lbl} {bucket_counts.get(b, 0)}")
                inf_lbl_items = [*base_labels, ("le", "+Inf")]
                inf_lbl = "{" + ",".join(f'{k}="{v}"' for k, v in inf_lbl_items) + "}"
                lines.append(f"{name}_bucket{inf_lbl} {self._hist_count.get((name, labels), 0)}")
                lbl = ("{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}") if labels else ""
                lines.append(f"{name}_sum{lbl} {self._hist_sum.get((name, labels), 0.0)}")
                lines.append(f"{name}_count{lbl} {self._hist_count.get((name, labels), 0)}")
        return "\n".join(lines) + "\n"


METRICS = Metrics()


# ── parse pipeline metrics (per artifact type) ───────────────────────────────
# Shared by tasks/ingest_task.py (Babel plugins) and tasks/module_task.py
# (analysis modules) so both parse pipelines report through the same names.
#
#   parser_parse_total{artifact_type, status}   — status: success|failure|skipped
#   parser_parse_duration_seconds{artifact_type} — histogram, seconds
#   parser_events_normalized_total{artifact_type} — events successfully indexed/normalized
#   worker_dead_letter_total{task}               — tasks parked on the dead-letter queue
def record_parse(
    artifact_type: str,
    status: str,
    duration_seconds: float,
    *,
    events_normalized: int = 0,
) -> None:
    """Record one parse attempt's outcome for a given artifact type.

    Called once per parse attempt from the ingest and module task pipelines.
    ``status`` is typically one of "success", "failure", "skipped", or
    "cancelled" (module runs cancelled by an analyst).
    """
    atype = artifact_type or "unknown"
    METRICS.inc(
        "parser_parse_total",
        labels={"artifact_type": atype, "status": status},
        help="Parse attempts per artifact type and outcome",
    )
    METRICS.observe(
        "parser_parse_duration_seconds",
        duration_seconds,
        labels={"artifact_type": atype},
        help="Parse duration in seconds per artifact type",
    )
    if events_normalized:
        METRICS.inc(
            "parser_events_normalized_total",
            events_normalized,
            labels={"artifact_type": atype},
            help="Events successfully normalized/indexed per artifact type",
        )


def record_dead_letter(task_name: str) -> None:
    """Record a task being parked on the dead-letter queue."""
    METRICS.inc(
        "worker_dead_letter_total",
        labels={"task": task_name or "unknown"},
        help="Tasks parked on the dead-letter queue, by task name",
    )


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
