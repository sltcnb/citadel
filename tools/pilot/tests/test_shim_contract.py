"""Guard the pilot → api shim's import contract.

``api/routers/llm_config.py`` is a compatibility shim: it mirrors *every* name in
``pilot/service.py`` — public and private — into its own namespace so that
``from routers.llm_config import _get_config, _auto_broaden, …`` keeps resolving
after the engine moved into the ``pilot`` package.

The consequence is easy to forget, and it bit during this change: **every
top-level name in service.py is part of a public import contract.** Removing one
that looks internal (a helper whose last in-module caller went away, so a linter
reports it unused) breaks importers at collection time, with an error that points
at the shim rather than at the edit that caused it:

    ImportError: cannot import name '_auto_broaden' from 'routers.llm_config'

That failure only shows up in the fakeredis backend job, which needs FastAPI +
pydantic and so cannot run in the dependency-light gate. This test reproduces the
same guarantee statically — no imports, no pydantic — so the breakage is caught
in the gate that runs everywhere.

Runnable standalone (python3 tools/pilot/tests/test_shim_contract.py).
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO = next(
    (p for p in Path(__file__).resolve().parents if (p / "tools" / "pilot").exists()),
    Path(__file__).resolve().parents[3],
)
_SERVICE = _REPO / "tools" / "pilot" / "pilot" / "service.py"
_SHIM = _REPO / "api" / "routers" / "llm_config.py"
_API_ROUTERS = _REPO / "api" / "routers"


def _toplevel_bound_names(path: Path) -> set[str]:
    """Names a module binds at import time — what ``vars(module)`` would expose.

    Covers defs, classes, assignments and imports, including those inside a
    top-level ``try/except ImportError`` (the optional-dependency pattern
    service.py uses for its own package-vs-bare-module import).
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bound: set[str] = set()

    def visit(nodes) -> None:
        for node in nodes:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                bound.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        bound.add(t.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                bound.add(node.target.id)
            elif isinstance(node, ast.Import | ast.ImportFrom):
                for a in node.names:
                    bound.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.Try):
                visit(node.body)
                for handler in node.handlers:
                    visit(handler.body)
                visit(node.orelse)
                visit(node.finalbody)
            elif isinstance(node, ast.If):
                visit(node.body)
                visit(node.orelse)

    visit(tree.body)
    return bound


def _is_template(path: Path) -> bool:
    """Cookiecutter scaffolding holds un-rendered ``{{ }}`` source, not valid Python.

    Same exclusion ruff and the plugin loader apply (see pyproject's
    ``extend-exclude`` and plugin_loader._is_template_path).
    """
    s = str(path)
    return "{{" in s or "cookiecutter" in s or f"{Path('/')}template{Path('/')}" in s.replace(
        "\\", "/"
    ) or "/template/" in s.replace("\\", "/")


def _names_imported_from_shim(path: Path) -> set[str]:
    """Names a module imports from ``routers.llm_config``. Unparseable → none."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and "llm_config" in node.module:
            names |= {a.name for a in node.names if a.name != "*"}
    return names


def test_every_name_imported_from_the_shim_exists_in_service():
    """The contract itself: nothing imports a name service.py no longer binds."""
    bound = _toplevel_bound_names(_SERVICE)
    assert bound, "failed to parse service.py — the check would silently pass"

    broken: dict[str, list[str]] = {}
    for py in sorted(_REPO.glob("api/**/*.py")) + sorted(_REPO.glob("tools/**/*.py")):
        if py == _SHIM or not py.is_file() or _is_template(py):
            continue
        missing = sorted(n for n in _names_imported_from_shim(py) if n not in bound)
        if missing:
            broken[str(py.relative_to(_REPO))] = missing

    assert not broken, (
        "these modules import names from routers.llm_config that pilot/service.py "
        "no longer binds — they will fail at import time:\n"
        + "\n".join(f"  {mod}: {', '.join(names)}" for mod, names in broken.items())
    )


def test_shim_still_mirrors_the_whole_namespace():
    """If the shim stops bulk-mirroring, the check above would be vacuous."""
    src = _SHIM.read_text(encoding="utf-8")
    assert "globals().update(" in src, "shim no longer bulk-mirrors service.py's namespace"
    assert "vars(_service)" in src, "shim no longer sources its names from pilot.service"


def test_query_strategy_helpers_are_reachable_through_the_shim():
    """The specific names this change moved out of service.py must still resolve.

    They now live in pilot/query_strategy.py and are re-imported by service.py.
    A future cleanup that drops one as "unused" — it has no in-module caller —
    would break api/routers/test_pilot_agent.py, which is how this test earned
    its place.
    """
    bound = _toplevel_bound_names(_SERVICE)
    for name in ("_auto_broaden", "_broaden_ladder", "_query_fields", "_coverage_warning"):
        assert name in bound, (
            f"{name} is not bound in service.py — it is re-exported through the shim, "
            "so removing the import breaks importers even though nothing in "
            "service.py calls it"
        )


def test_pilot_test_modules_are_discoverable():
    """Sanity: the api-side pilot tests exist, so the contract has real consumers.

    Asserted because an earlier assumption that "pilot has no tests" is exactly
    what led to the contract being broken.
    """
    found = sorted(p.name for p in _API_ROUTERS.glob("test_pilot*.py"))
    assert found, "expected api/routers/test_pilot*.py to exist"


if __name__ == "__main__":
    n = 0
    for name in sorted(k for k in dict(globals()) if k.startswith("test_")):
        globals()[name]()
        n += 1
        print(f"PASS  {name}")
    print(f"\n{n}/{n} passed")
