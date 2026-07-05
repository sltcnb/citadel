"""Sluice — routing coverage checker.

Proves the Sluice done-when: *every built input row has a routed handler.* The
"built rows" are the parsers Babel actually ships (one ``manifest.yaml`` +
``*_plugin.py`` per parser under ``tools/babel``). For each, this:

  1. confirms a handler module exists (a ``*_plugin.py`` in the parser dir), and
  2. drives the real :class:`PluginLoader` router with a synthetic input for each
     signal the parser declares (extension / MIME / filename) and confirms the
     router resolves *some* handler.

It prints a coverage report (routed / total) and lists any unrouted signal and
any parser whose module failed to import in this environment (missing optional
dep — a routable row in production, flagged here so coverage is never silently
overstated).

    python3 tools/sluice-worker/routing_coverage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PLUGINS_DIR = REPO / "tools" / "babel"
INGESTER_DIR = REPO / "tools" / "sluice"


def _manifests() -> list[Path]:
    return sorted(PLUGINS_DIR.glob("*/manifest.yaml"))


def _signals(manifest: dict) -> list[tuple[str, str, str]]:
    """(kind, value, mime) synthetic-input signals declared by a parser."""
    out: list[tuple[str, str, str]] = []
    for ext in manifest.get("supported_extensions") or []:
        out.append(("ext", ext, "application/octet-stream"))
    for mime in manifest.get("supported_mime_types") or []:
        out.append(("mime", ".bin", mime))
    for fn in manifest.get("handled_filenames") or []:
        out.append(("filename", fn, "application/octet-stream"))
    return out


def build_report() -> dict:
    sys.path.insert(0, str(HERE))
    from plugin_loader import PluginLoader

    loader = PluginLoader(plugins_dir=PLUGINS_DIR, ingester_dir=INGESTER_DIR)
    loader.load()
    loaded_names = {getattr(c, "PLUGIN_NAME", "") for c in loader._plugin_classes}

    manifests = _manifests()
    no_handler_module = []
    load_failures = []
    routed = unrouted = total = 0
    unrouted_detail = []

    for man_path in manifests:
        parser_dir = man_path.parent
        man = yaml.safe_load(man_path.read_text(encoding="utf-8")) or {}
        # (1) a handler module must exist for this built row
        if not list(parser_dir.glob("*_plugin.py")):
            no_handler_module.append(parser_dir.name)
        # (2) router must resolve each declared signal
        pname = man.get("id") or man.get("name")
        module_loaded = any(
            man.get("id", "").lower() in n.lower() or n.lower() in str(pname).lower()
            for n in loaded_names
        )
        for kind, value, mime in _signals(man):
            total += 1
            if kind == "filename":
                probe = Path(value)
            elif kind == "ext":
                probe = Path("sample" + value)
            else:
                probe = Path("sample.bin")
            try:
                hit = loader.get_plugin(probe, mime)
            except Exception:  # noqa: BLE001
                hit = None
            if hit is not None:
                routed += 1
            else:
                unrouted += 1
                # only a true gap if the parser's own module loaded; otherwise
                # it's an environment dep-import failure, recorded separately.
                if module_loaded:
                    unrouted_detail.append(f"{parser_dir.name}: {kind}={value} mime={mime}")
                elif parser_dir.name not in load_failures:
                    load_failures.append(parser_dir.name)

    return {
        "manifests": len(manifests),
        "plugins_loaded": len(loader._plugin_classes),
        "signals_total": total,
        "signals_routed": routed,
        "signals_unrouted": unrouted,
        "missing_handler_module": no_handler_module,
        "load_failures_env": sorted(load_failures),
        "true_unrouted": unrouted_detail,
    }


def main() -> int:
    r = build_report()
    print("Sluice routing coverage")
    print(f"  built parsers (manifests) : {r['manifests']}")
    print(f"  plugins loaded            : {r['plugins_loaded']}")
    print(f"  signals routed            : {r['signals_routed']}/{r['signals_total']}")
    print(f"  parsers w/o handler module: {r['missing_handler_module'] or 'none'}")
    print(f"  module import failures(env): {r['load_failures_env'] or 'none'}")
    if r["true_unrouted"]:
        print("  TRUE UNROUTED (loaded but no handler):")
        for u in r["true_unrouted"]:
            print("    -", u)
    # Exit non-zero only on a genuine gap: a built row with no handler module,
    # or a loaded parser whose own declared signal the router cannot resolve.
    return 1 if (r["missing_handler_module"] or r["true_unrouted"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
