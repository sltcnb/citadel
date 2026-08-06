"""Pytest bootstrap for the Scribe test-suite.

The ``scribe`` package lives at ``tools/scribe/scribe`` (package-in-wrapper
layout), so the wrapper directory must be on ``sys.path`` for ``import scribe``
to resolve. The repo-root conftest already arranges this for the aggregated
run, but it is not loaded when pytest targets this directory directly
(``pytest tools/scribe/tests`` from the repo root) — mirror what the other
tools (babel, augur) do and insert it here.
"""

from __future__ import annotations

import sys
from pathlib import Path

# tests/ -> tools/scribe/
_TOOL_DIR = Path(__file__).resolve().parents[1]
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))
