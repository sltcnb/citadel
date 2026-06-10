"""Augur command-line interface.

    augur enrich iocs.json -o enriched.stix.json

By default sources run *offline* (no HTTP session): any source that needs the
network reports an ``error`` verdict and contributes no weight, so the command
always produces a valid bundle. Pass ``--online`` to attach a real
``requests`` session and live API keys (from flags or environment).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .cache import TTLCache
from .enricher import Enricher
from .io import load_iocs
from .scoring import _SEVERITY_BANDS  # noqa: F401 (kept for help/reference)
from .sources import BUILTIN_SOURCES
from .stix import build_bundle


def _build_session(online: bool):
    if not online:
        return None
    try:
        import requests
    except ImportError:  # pragma: no cover
        sys.stderr.write("augur: --online requires the 'requests' package\n")
        raise SystemExit(2)
    return requests.Session()


def _make_sources(selected: list[str], online: bool):
    session = _build_session(online)
    sources = []
    for name in selected:
        cls = BUILTIN_SOURCES.get(name)
        if cls is None:
            raise SystemExit(f"augur: unknown source '{name}' (have: {', '.join(BUILTIN_SOURCES)})")
        env_key = os.environ.get(f"AUGUR_{name.upper()}_API_KEY", "")
        sources.append(cls(api_key=env_key, session=session))
    return sources


def cmd_enrich(args: argparse.Namespace) -> int:
    iocs = load_iocs(args.input)
    if not iocs:
        sys.stderr.write("augur: no IOCs found in input\n")
        return 1

    selected = args.sources or list(BUILTIN_SOURCES)
    sources = _make_sources(selected, args.online)
    enricher = Enricher(sources, cache=TTLCache(ttl_seconds=args.cache_ttl))

    enriched = enricher.enrich_all(iocs)
    bundle = build_bundle(enriched)

    out = json.dumps(bundle, indent=2)
    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        dest = args.output
    else:
        sys.stdout.write(out + "\n")
        dest = "<stdout>"

    n_ind = sum(1 for o in bundle["objects"] if o["type"] == "indicator")
    malicious = sum(1 for e in enriched if e.score >= 0.5)
    sys.stderr.write(
        f"augur: enriched {len(iocs)} IOC(s) via {len(sources)} source(s) "
        f"({malicious} malicious) -> {n_ind} STIX indicators in {dest} "
        f"[cache hits={enricher.cache.hits}]\n"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="augur", description="Citadel intel enrichment CLI")
    p.add_argument("--version", action="version", version=f"augur {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    enr = sub.add_parser("enrich", help="Enrich IOCs and export a STIX 2.1 bundle")
    enr.add_argument("input", help="IOC input file (JSON)")
    enr.add_argument("-o", "--output", default="-", help="Output STIX bundle path ('-' for stdout)")
    enr.add_argument(
        "-s",
        "--source",
        dest="sources",
        action="append",
        choices=list(BUILTIN_SOURCES),
        help="Restrict to a source (repeatable)",
    )
    enr.add_argument(
        "--online", action="store_true", help="Make live HTTP calls (default: offline)"
    )
    enr.add_argument("--cache-ttl", type=float, default=3600.0, help="Enrichment cache TTL seconds")
    enr.set_defaults(func=cmd_enrich)

    src = sub.add_parser("sources", help="List available enrichment sources")
    src.set_defaults(func=cmd_sources)
    return p


def cmd_sources(_args: argparse.Namespace) -> int:
    for name, cls in BUILTIN_SOURCES.items():
        types = ", ".join(t.value for t in cls.supported_types)
        sys.stdout.write(f"{name:12s} weight={cls.weight:<4} types=[{types}]\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
