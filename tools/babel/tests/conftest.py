"""Pytest bootstrap for the Babel parser test-suite.

Babel modules import each other as ``from babel.<x> import ...`` — i.e. the
package root is ``tools/`` (the parent of ``plugins/``). When pytest is invoked
from anywhere other than ``tools/`` that directory is not on ``sys.path``, so we
add it here. This keeps the tests runnable both standalone
(``cd tools && pytest plugins``) and from the repo root.
"""

from __future__ import annotations

import sys
from pathlib import Path

# tests/ -> plugins/ -> tools/
_TOOLS_DIR = Path(__file__).resolve().parents[2]
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
