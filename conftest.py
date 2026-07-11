"""Repo-root pytest bootstrap.

The tools/ tree ships several independently packaged tools. Some use a
"package-in-wrapper" layout (e.g. the ``scribe`` package lives at
``tools/scribe/scribe``), while others (Babel) expect ``tools/`` itself on
``sys.path`` so ``import babel`` resolves to ``tools/babel``.

When a per-tool conftest inserts ``tools/`` onto ``sys.path`` (Babel does this),
the wrapper directories such as ``tools/scribe`` turn into *namespace* packages
that shadow the real package. In production every tool is laid out flat under
``/app`` (PYTHONPATH=/app) so this never happens.

To mirror that flat layout for the aggregated test run we prepend each wrapper
directory that contains a like-named sub-package. Because this conftest lives at
the rootdir it runs before any per-tool conftest, so the correct package always
wins even after ``tools/`` is later added.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_TOOLS = _ROOT / "tools"


def _bootstrap_paths() -> None:
    candidates = [_ROOT / "api", _TOOLS]
    if _TOOLS.is_dir():
        for tool in sorted(_TOOLS.iterdir()):
            if not tool.is_dir():
                continue
            # package-in-wrapper layout: tools/<tool>/<tool>/__init__.py
            if (tool / tool.name / "__init__.py").exists():
                candidates.append(tool)
    for path in candidates:
        p = str(path)
        if path.exists() and p not in sys.path:
            sys.path.insert(0, p)


_bootstrap_paths()
