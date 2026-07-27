"""Sluice — collection coverage checker (the other half of the bijection).

``routing_coverage.py`` proves: *every parser Babel ships is reachable.*
This proves the direction that actually loses evidence: *every artifact Talon
collects reaches the parser that understands it.*

The failure it exists to catch is silent. An artifact with no parser does not
error — the ``strings`` catch-all claims it (``can_handle`` → True, priority 1),
emits a bag of printable strings, and the run reports success. ``mft/C_$MFT``
sat in exactly that state: collected on every Windows host, routed to strings,
filesystem timeline gone, nothing anywhere saying so.

For each row in :mod:`collection_inventory` this:

  1. materialises the sample under its real bundle arcname (content-sniffing
     parsers read the file before claiming it, so a placeholder proves nothing);
  2. asks the real :class:`PluginLoader` router which parser claims it;
  3. compares that against the parser the row declares.

Three ways to fail, all genuine drift:

  * **misrouted** — a row declares parser X, the router picked Y (or nothing).
    Either the collector's arcname changed or a ``can_handle`` regressed.
  * **undeclared gap** — a row declares parser X but landed on a generic
    fallback. X no longer claims what Talon writes.
  * **stale gap** — a row declared ``parser=None`` now routes to a real parser.
    The debt was paid; close the ledger entry.

    python3 tools/sluice/worker/collection_coverage.py [-v]
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = next((p for p in HERE.parents if (p / "tools" / "babel").exists()), HERE.parents[2])
PLUGINS_DIR = REPO / "tools" / "babel"
INGESTER_DIR = REPO / "tools" / "sluice"

# Parsers that claim by shape rather than by artifact: landing here means the
# artifact's structure was never decoded. `strings` is the floor (can_handle →
# True); the rest are shape-generic readers, useful but not artifact-aware.
GENERIC_PARSERS = frozenset(
    {"strings", "json_file", "log2timeline", "plaso", "archive", "ndjson"}
)

# `timestamped_log` is deliberately NOT generic here: for an application log
# whose only structure IS "timestamp + message" (Teams, TeamViewer, CBS.log),
# extracting that pair is a complete parse, not a fallback.


def _materialise(root: Path, arcname: str, sample: bytes) -> Path:
    """Write *sample* at *arcname* under *root*, preserving the real basename.

    The basename is what routing keys off — ``$MFT`` vs ``C_$MFT`` is the whole
    bug this checker exists for — so it must survive verbatim. Windows ADS
    (``x.exe:Zone.Identifier``) cannot be a POSIX filename, so the colon is
    mapped the same way the ingest stage flattens it.
    """
    rel = Path(arcname.replace(":", "__"))
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(sample)
    return dest


def _parse_check(loader, artifacts) -> list[str]:
    """Find parsers that claim an artifact and then yield nothing.

    Claiming and emitting zero events is worse than not claiming: the router
    reports a hit, the run reports success, and the artifact is consumed without
    producing a single timeline entry — so it never reaches the ``strings``
    floor that would at least have surfaced its contents. It is the exact
    failure the ``container_sockets.txt`` entry had (matched by name, no
    handler behind it).

    A parser whose optional dependency is absent (no ``mft``, no ``pytsk3``)
    raises ``PluginFatalError`` and is skipped — that is an environment
    limitation, not a coverage gap.
    """
    from citadel_contracts.parser import PluginContext, PluginFatalError

    offenders: list[str] = []
    with tempfile.TemporaryDirectory(prefix="citadel-parsecheck-") as td:
        root = Path(td)
        for art in artifacts:
            if art.parser is None or art.empty_ok:
                continue
            path = _materialise(root, art.path, art.sample)
            try:
                cls = loader.get_plugin(path, art.mime)
            except Exception:  # noqa: BLE001
                continue
            if cls is None or getattr(cls, "PLUGIN_NAME", None) != art.parser:
                continue  # routing drift, already reported by the caller
            ctx = PluginContext(
                case_id="coverage", job_id="coverage", source_file_path=path, source_minio_url=""
            )
            try:
                plugin = cls(ctx)
                plugin.setup()
                try:
                    empty = next(iter(plugin.parse()), None) is None
                finally:
                    plugin.teardown()
            except PluginFatalError:
                continue  # optional dependency missing in this environment
            except Exception:  # noqa: BLE001 - a raising parser is its own suite's problem
                continue
            if empty:
                offenders.append(f"{art.path}: {art.parser} claims it but yields 0 events")
    return offenders


def build_report(verbose: bool = False) -> dict:
    sys.path.insert(0, str(HERE))
    from collection_inventory import ARTIFACTS
    from plugin_loader import PluginLoader

    loader = PluginLoader(plugins_dir=PLUGINS_DIR, ingester_dir=INGESTER_DIR)
    loader.load()
    loaded = {getattr(c, "PLUGIN_NAME", "") for c in loader._plugin_classes}

    misrouted: list[str] = []
    undeclared_gap: list[str] = []
    stale_gap: list[str] = []
    unknown_parser: list[str] = []
    routed: list[tuple[str, str]] = []
    gaps: list[tuple[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="citadel-coverage-") as td:
        root = Path(td)
        for art in ARTIFACTS:
            path = _materialise(root, art.path, art.sample)
            try:
                hit = loader.get_plugin(path, art.mime)
            except Exception:  # noqa: BLE001 - a raising can_handle is a routing miss
                hit = None
            actual = getattr(hit, "PLUGIN_NAME", None) if hit else None

            if art.parser is None:
                # Declared gap: expected to land on a generic fallback.
                if actual and actual not in GENERIC_PARSERS:
                    stale_gap.append(
                        f"{art.path}: now claimed by {actual} — close the ledger entry"
                    )
                else:
                    gaps.append((art.path, actual or "NONE"))
                continue

            # A declared parser that Babel does not ship at all is a typo in the
            # ledger, not a routing result — surface it separately.
            if art.parser not in loaded:
                unknown_parser.append(f"{art.path}: declares parser {art.parser!r}, not loaded")
                continue

            if actual == art.parser:
                routed.append((art.path, actual))
            elif actual is None or actual in GENERIC_PARSERS:
                undeclared_gap.append(
                    f"{art.path}: expected {art.parser}, fell through to {actual or 'NONE'}"
                )
            else:
                misrouted.append(f"{art.path}: expected {art.parser}, got {actual}")

    categories = {a.category for a in ARTIFACTS}
    return {
        "silent_empty": _parse_check(loader, ARTIFACTS),
        "artifacts": len(ARTIFACTS),
        "categories": len(categories),
        "plugins_loaded": len(loaded),
        "routed": routed,
        "declared_gaps": gaps,
        "misrouted": misrouted,
        "undeclared_gap": undeclared_gap,
        "stale_gap": stale_gap,
        "unknown_parser": unknown_parser,
        "verbose": verbose,
    }


def main() -> int:
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    r = build_report(verbose)
    total = r["artifacts"]
    ok = len(r["routed"])
    gaps = len(r["declared_gaps"])

    print("Sluice collection coverage (Talon → Babel)")
    print(f"  collected artifact shapes : {total} across {r['categories']} categories")
    print(f"  parsers loaded            : {r['plugins_loaded']}")
    print(f"  routed to declared parser : {ok}/{total}")
    print(f"  declared open gaps        : {gaps}/{total}")

    if verbose and r["routed"]:
        print("\n  ROUTED:")
        for path, parser in r["routed"]:
            print(f"    {parser:<18} {path}")
    if r["declared_gaps"]:
        print("\n  OPEN GAPS (no dedicated parser — see collection_inventory.py):")
        for path, actual in r["declared_gaps"]:
            print(f"    {actual:<18} {path}")

    failed = False
    for label, key in (
        ("MISROUTED (claimed by the wrong parser)", "misrouted"),
        ("UNDECLARED GAP (declared parser no longer claims it)", "undeclared_gap"),
        ("STALE GAP (now parsed — close the ledger entry)", "stale_gap"),
        ("UNKNOWN PARSER (ledger names a parser Babel does not ship)", "unknown_parser"),
        ("SILENT EMPTY (parser claims the artifact but yields no events)", "silent_empty"),
    ):
        if r[key]:
            failed = True
            print(f"\n  {label}:")
            for line in r[key]:
                print(f"    - {line}")

    if not failed:
        print("\n  no drift: every collected shape reaches its declared parser.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
