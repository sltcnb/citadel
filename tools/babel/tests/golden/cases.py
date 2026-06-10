"""Golden-file case registry for the Babel parser harness.

Each :class:`GoldenCase` ties a parser to a checked-in fixture input and the
expected normalized ``ForensicEvent`` stream (``expected/<id>.json``).

Determinism
-----------
Parsers may inject non-deterministic data that must not leak into a golden:

* ``fo_id`` — a fresh UUID per event. Stripped via :data:`VOLATILE_KEYS`.
* file-mtime timestamps — some parsers (e.g. ``netstat``) stamp events with the
  source file's mtime. Cases that rely on this set ``fixed_mtime`` so the
  harness pins the fixture's mtime before parsing, making output reproducible.

To (re)generate goldens after an intentional parser change::

    cd tools && BABEL_REGEN_GOLDEN=1 python -m pytest plugins/tests/test_golden.py

Review the diff before committing — the whole point is that a human signs off.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from babel.access_log.access_log_plugin import AccessLogPlugin
from babel.base_plugin import BasePlugin
from babel.netstat.netstat_plugin import NetstatPlugin
from babel.suricata.suricata_plugin import SuricataPlugin
from babel.zeek.zeek_plugin import ZeekPlugin

HERE = Path(__file__).resolve().parent
FIXTURES_DIR = HERE / "fixtures"
EXPECTED_DIR = HERE / "expected"

# Per-event keys that are non-deterministic and stripped before comparison.
VOLATILE_KEYS: frozenset[str] = frozenset({"fo_id"})


@dataclass(frozen=True)
class GoldenCase:
    """One parser-against-fixture golden test."""

    id: str
    plugin_cls: type[BasePlugin]
    fixture: str
    # If set, the fixture's mtime is pinned to this epoch before parsing so
    # mtime-derived timestamps are reproducible.
    fixed_mtime: float | None = None
    # Optional per-event transform applied before comparison (rarely needed).
    scrub: Callable[[dict[str, Any]], dict[str, Any]] | None = field(default=None)

    @property
    def fixture_path(self) -> Path:
        return FIXTURES_DIR / self.fixture

    @property
    def expected_path(self) -> Path:
        return EXPECTED_DIR / f"{self.id}.json"


# A fixed, well-known epoch (2023-09-15T12:34:56Z) for mtime-stamped parsers.
_FIXED_MTIME = 1694781296.0

CASES: list[GoldenCase] = [
    GoldenCase(id="zeek_conn", plugin_cls=ZeekPlugin, fixture="conn.log"),
    GoldenCase(id="suricata_eve", plugin_cls=SuricataPlugin, fixture="eve.json"),
    GoldenCase(id="access_log_combined", plugin_cls=AccessLogPlugin, fixture="access.log"),
    GoldenCase(
        id="netstat_ss",
        plugin_cls=NetstatPlugin,
        fixture="ss.txt",
        fixed_mtime=_FIXED_MTIME,
    ),
]

# ── Binary-format golden cases ───────────────────────────────────────────────
# Binary parsers (EVTX/LNK/Prefetch/Registry/MFT) need (a) a real binary fixture
# committed under fixtures/binary/ and (b) the parser's runtime library. Rather
# than fabricate invalid binaries, these cases are registered and SKIP cleanly
# (with a reason) until an operator drops a real sample in; then they run and
# golden-compare exactly like the text cases. See fixtures/binary/README.md.
BINARY_FIXTURES_DIR = FIXTURES_DIR / "binary"

BINARY_CASES: list[dict[str, str]] = [
    {
        "id": "evtx_security",
        "module": "plugins.evtx.evtx_plugin",
        "cls": "EvtxPlugin",
        "fixture": "Security.evtx",
        "lib": "Evtx",
    },
    {
        "id": "lnk_recent",
        "module": "plugins.lnk.lnk_plugin",
        "cls": "LnkPlugin",
        "fixture": "recent.lnk",
        "lib": "LnkParse3",
    },
    {
        "id": "prefetch_app",
        "module": "plugins.prefetch.prefetch_plugin",
        "cls": "PrefetchPlugin",
        "fixture": "APP.pf",
        "lib": "ctypes",
    },
    {
        "id": "registry_ntuser",
        "module": "plugins.registry.registry_plugin",
        "cls": "RegistryPlugin",
        "fixture": "NTUSER.DAT",
        "lib": "regipy",
    },
    {
        "id": "mft_record",
        "module": "plugins.mft.mft_plugin",
        "cls": "MftPlugin",
        "fixture": "MFT",
        "lib": "ctypes",
    },
]


def binary_case_status(case: dict) -> tuple[bool, str]:
    """Return ``(runnable, reason)`` for a binary golden case.

    Runnable only when both the committed fixture exists and the parser's
    runtime library imports; otherwise a clear skip reason."""
    import importlib

    fixture = BINARY_FIXTURES_DIR / case["fixture"]
    if not fixture.exists():
        return False, f"fixture missing: fixtures/binary/{case['fixture']}"
    try:
        importlib.import_module(case["lib"])
    except Exception:
        return False, f"runtime lib not installed: {case['lib']}"
    return True, "ok"


def load_binary_plugin(case: dict) -> type[BasePlugin]:
    import importlib

    mod = importlib.import_module(case["module"])
    return getattr(mod, case["cls"])
