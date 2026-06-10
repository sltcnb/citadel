"""Anvil module contract — backward-compatible re-export of the shared contract.

The canonical definition now lives in ``citadel_contracts.module`` so Anvil
modules and the platform depend on the same contract without importing each
other (symmetry with the Babel parser contract). Existing modules keep working:

    from base import BaseModule, Result, RunContext, iter_local_files, wrap_legacy

still resolves via this shim. A small path bootstrap makes the import work
however the module is loaded (the sandbox runs them by path).
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

# citadel_contracts sits two levels up from tools/anvil/base.py (at tools/),
# and at /app in the container image.
_contracts_parent = _Path(__file__).resolve().parents[1]
if str(_contracts_parent) not in _sys.path:
    _sys.path.insert(0, str(_contracts_parent))

from citadel_contracts.module import (  # noqa: E402,F401
    LEVELS,
    SCHEMA_PATH,
    Artifact,
    BaseModule,
    Finding,
    Result,
    RunContext,
    iter_local_files,
    result_from_hits,
    severity_int,
    wrap_legacy,
)

__all__ = [
    "LEVELS",
    "SCHEMA_PATH",
    "Artifact",
    "BaseModule",
    "Finding",
    "Result",
    "RunContext",
    "iter_local_files",
    "result_from_hits",
    "severity_int",
    "wrap_legacy",
]
