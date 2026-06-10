"""MIME-type coverage report across every Babel parser.

Discovers all ``*_plugin.py`` modules under ``plugins/`` and reports which
parsers declare ``SUPPORTED_MIME_TYPES`` versus which route purely by
extension/filename.

Discovery is **static** (via :mod:`ast`) rather than by importing the modules,
because many parsers have heavy optional runtime deps (pytsk3, pyewf, redis,
…) that aren't installed in a lint/test sandbox. A MIME-coverage audit must
work regardless, so we read the class attributes straight from source.

Run as a script for a human-readable table::

    cd tools && python -m babel.tests.mime_coverage

Exit code is non-zero if any parser is *uncovered* — i.e. declares no MIME
types AND no extensions AND no handled filenames AND does not override
``can_handle`` (which would make it unroutable).
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

PLUGINS_DIR = Path(__file__).resolve().parents[1]

# Parsers that intentionally declare no MIME types because they route by
# filename, extension, or are pure behavioural fallbacks. Kept explicit so a
# *new* gap is never silently excused.
INTENTIONALLY_NO_MIME: frozenset[str] = frozenset(
    {
        "ios",  # heterogeneous SQLite/plist artifacts, matched by filename
        "browser",  # generic SQLite/JSON stores, matched by exact filename
        "strings",  # last-resort catch-all (can_handle -> True)
        "log2timeline",  # generic timeline fallback, routed by extension
    }
)


@dataclass(frozen=True)
class ParserInfo:
    name: str
    module: str
    mime_types: tuple[str, ...]
    extensions: tuple[str, ...]
    handled_filenames: tuple[str, ...]
    overrides_can_handle: bool

    @property
    def has_mime(self) -> bool:
        return bool(self.mime_types)

    @property
    def is_routable(self) -> bool:
        """Can the loader ever select this parser?"""
        return (
            self.has_mime
            or bool(self.extensions)
            or bool(self.handled_filenames)
            or self.overrides_can_handle
        )

    @property
    def is_gap(self) -> bool:
        """A real coverage gap: no MIME and not deliberately exempt."""
        return not self.has_mime and self.name not in INTENTIONALLY_NO_MIME


def _iter_plugin_modules() -> Iterable[Path]:
    for path in sorted(PLUGINS_DIR.glob("*/*_plugin.py")):
        if "__pycache__" in path.parts:
            continue
        yield path


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    """Map of module-level ``NAME = <value>`` assignments (for reference resolution)."""
    out: dict[str, ast.AST] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = stmt.value
    return out


def _str_list(node: ast.AST | None, consts: dict[str, ast.AST] | None = None) -> tuple[str, ...]:
    """Best-effort static extraction of a tuple of string literals.

    Handles list/tuple/set literals, ``list(...)/sorted(...)/frozenset(...)``
    wrappers, set unions (``A | B``), and module-level name references — the
    handful of patterns Babel parsers actually use to build their class attrs.
    """
    consts = consts or {}
    if node is None:
        return ()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, ast.Name) and node.id in consts:
        return _str_list(consts[node.id], consts)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out: list[str] = []
        for el in node.elts:
            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                out.append(el.value)
            elif isinstance(el, ast.Name):
                out.extend(_str_list(el, consts))
        return tuple(out)
    if isinstance(node, ast.Call) and node.args:
        # list(...), sorted(...), frozenset({...}), set(...), tuple(...)
        return _str_list(node.args[0], consts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _str_list(node.left, consts) + _str_list(node.right, consts)
    return ()


def _is_base_plugin_subclass(cls: ast.ClassDef) -> bool:
    for base in cls.bases:
        if isinstance(base, ast.Name) and base.id == "BasePlugin":
            return True
        if isinstance(base, ast.Attribute) and base.attr == "BasePlugin":
            return True
    return False


def _class_assignments(cls: ast.ClassDef) -> dict[str, ast.AST]:
    """Map of simple class-level ``NAME = <value>`` and ``NAME: T = <value>``."""
    out: dict[str, ast.AST] = {}
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                out[stmt.target.id] = stmt.value
    return out


def _defines_method(cls: ast.ClassDef, name: str) -> bool:
    return any(isinstance(s, ast.FunctionDef) and s.name == name for s in cls.body)


def _handled_filename_literals(cls: ast.ClassDef) -> tuple[str, ...]:
    """Best-effort: pull string literals returned by get_handled_filenames()."""
    for stmt in cls.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "get_handled_filenames":
            lits: list[str] = []
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    lits.append(sub.value)
            return tuple(lits)
    return ()


def discover_parsers() -> list[ParserInfo]:
    infos: list[ParserInfo] = []
    for path in _iter_plugin_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        consts = _module_constants(tree)
        mod_name = ".".join(path.relative_to(PLUGINS_DIR.parent).with_suffix("").parts)
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not _is_base_plugin_subclass(node):
                continue
            attrs = _class_assignments(node)
            name_node = attrs.get("PLUGIN_NAME")
            name = (
                name_node.value
                if isinstance(name_node, ast.Constant) and isinstance(name_node.value, str)
                else node.name
            )
            infos.append(
                ParserInfo(
                    name=name,
                    module=mod_name,
                    mime_types=_str_list(attrs.get("SUPPORTED_MIME_TYPES"), consts),
                    extensions=_str_list(attrs.get("SUPPORTED_EXTENSIONS"), consts),
                    handled_filenames=_handled_filename_literals(node),
                    overrides_can_handle=_defines_method(node, "can_handle"),
                )
            )
    return sorted(infos, key=lambda i: i.name)


def build_report() -> dict:
    parsers = discover_parsers()
    with_mime = [p for p in parsers if p.has_mime]
    gaps = [p for p in parsers if p.is_gap]
    unroutable = [p for p in parsers if not p.is_routable]
    return {
        "total": len(parsers),
        "with_mime": len(with_mime),
        "intentional_no_mime": [p.name for p in parsers if not p.has_mime and not p.is_gap],
        "gaps": [p.name for p in gaps],
        "unroutable": [p.name for p in unroutable],
        "parsers": parsers,
    }


def main() -> int:
    report = build_report()
    parsers: list[ParserInfo] = report["parsers"]
    width = max(len(p.name) for p in parsers)
    print(f"{'parser':<{width}}  mime  ext  file  can_handle  mime_types")
    print("-" * (width + 50))
    for p in parsers:
        flag = "ok " if p.has_mime else ("EXEMPT" if p.name in INTENTIONALLY_NO_MIME else "GAP")
        print(
            f"{p.name:<{width}}  {flag:<5} "
            f"{len(p.extensions):>3}  {len(p.handled_filenames):>4}  "
            f"{'yes' if p.overrides_can_handle else 'no':<10}  "
            f"{', '.join(p.mime_types) if p.mime_types else '-'}"
        )
    pct = 100.0 * report["with_mime"] / report["total"] if report["total"] else 0.0
    print("-" * (width + 50))
    print(
        f"{report['with_mime']}/{report['total']} parsers declare MIME types "
        f"({pct:.0f}%); {len(report['intentional_no_mime'])} intentionally exempt; "
        f"{len(report['gaps'])} gaps; {len(report['unroutable'])} unroutable."
    )
    if report["gaps"]:
        print("GAPS (declare SUPPORTED_MIME_TYPES or add to INTENTIONALLY_NO_MIME):")
        for name in report["gaps"]:
            print(f"  - {name}")
    return 1 if report["gaps"] or report["unroutable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
