"""Centralized logging setup for the Citadel API.

Replaces a bare ``logging.basicConfig`` with a single, consistent configuration
driven by ``LOG_LEVEL`` (and optional ``LOG_JSON``). Goals:

* One concise formatter for the whole process (timestamp, level, logger, msg).
* Every remaining INFO line carries real signal — high-frequency poll/health/
  access noise is filtered or demoted to DEBUG so the log stream is useful.
* Compose with, and never clobber, the existing ``citadel.tools`` Redis
  log-ship handler and the ``citadel.api`` access logger (those are attached at
  startup in ``main.py`` and must keep shipping).

``configure_logging`` is idempotent — safe to call more than once.
"""

from __future__ import annotations

import json
import logging
import sys

from config import settings

# Substrings of access-log paths whose per-request lines are pure heartbeat
# noise. The access logger ("citadel.api") is demoted so these never reach the
# default INFO stream; the log-ship handler still forwards what it's given.
_NOISY_ACCESS_SUBSTRINGS = (
    "/health",
    "/collab/",
    "/ai/agent/active",
    "/ai/results",
    "/metrics/dashboard",
    "/metrics/history",
    "/admin/logs",           # the log viewer polling itself
    "/tools/capabilities",   # capability poll flooding
    "/cti/iocs/stats",
    "/license/info",
)

_CONFIGURED = False


class _JsonFormatter(logging.Formatter):
    """One JSON object per line — suited to log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class _AccessNoiseFilter(logging.Filter):
    """Drop access-log lines for high-frequency poll/health endpoints.

    Applied to the ``citadel.api`` access logger so meaningful orchestration
    still shows up, but the viewer's own polling and heartbeats don't flood.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return not any(s in msg for s in _NOISY_ACCESS_SUBSTRINGS)


def _formatter() -> logging.Formatter:
    if settings.LOG_JSON:
        return _JsonFormatter()
    return logging.Formatter(
        fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def configure_logging() -> None:
    """Install the root handler/formatter and quiet known-noisy loggers."""
    global _CONFIGURED
    level = getattr(logging, settings.LOG_LEVEL, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Replace any handler installed by a prior basicConfig with a single stream
    # handler using our formatter. Preserve third-party handlers we recognise
    # (the Redis log-ship handler subclasses logging.Handler and is attached to
    # named loggers, not root — so it is untouched here).
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_formatter())
    root.addHandler(handler)

    # ── Access logger: keep INFO, but strip poll/health heartbeat lines ──────
    access = logging.getLogger("citadel.api")
    access.setLevel(logging.INFO)
    if not any(isinstance(f, _AccessNoiseFilter) for f in access.filters):
        access.addFilter(_AccessNoiseFilter())

    # ── Quiet chatty third-party libraries down to WARNING ───────────────────
    for noisy in (
        "urllib3",
        "urllib3.connectionpool",
        "botocore",
        "s3transfer",
        "elasticsearch",
        "elastic_transport",
        "minio",
        "uvicorn.access",  # our CoreHTTPMiddleware emits the meaningful access line
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True
    logging.getLogger(__name__).debug("Logging configured (level=%s json=%s)",
                                      settings.LOG_LEVEL, settings.LOG_JSON)
