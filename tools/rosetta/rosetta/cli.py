"""Rosetta command-line interface.

rosetta normalize events.jsonl --ecs 8.11 -o ecs.jsonl
rosetta --version
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import IO

from . import __version__
from .normalize import Normalizer, load_fieldmap


def _open_out(path: str | None) -> IO[str]:
    if path is None or path == "-":
        return sys.stdout
    return open(path, "w", encoding="utf-8")


def _normalize_stream(args: argparse.Namespace) -> int:
    fieldmap = load_fieldmap(args.map)
    normalizer = Normalizer(fieldmap, ecs_version=args.ecs)

    infile = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    out = _open_out(args.output)
    n_in = n_out = n_err = 0
    try:
        for lineno, line in enumerate(infile, 1):
            line = line.strip()
            if not line:
                continue
            n_in += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                n_err += 1
                print(f"rosetta: line {lineno}: invalid JSON: {exc}", file=sys.stderr)
                continue
            doc = normalizer.normalize(event)
            out.write(json.dumps(doc, ensure_ascii=False, default=str) + "\n")
            n_out += 1
    finally:
        if infile is not sys.stdin:
            infile.close()
        if out is not sys.stdout:
            out.close()

    print(
        f"rosetta: normalized {n_out}/{n_in} events to ECS {normalizer.ecs_version}"
        + (f" ({n_err} errors)" if n_err else ""),
        file=sys.stderr,
    )
    return 1 if n_err and n_out == 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rosetta",
        description="Canonicalize ForensicEvent JSONL into ECS v8 JSONL.",
    )
    parser.add_argument("--version", action="version", version=f"rosetta {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    norm = sub.add_parser("normalize", help="ForensicEvent JSONL -> ECS JSONL")
    norm.add_argument("input", help="input JSONL path, or '-' for stdin")
    norm.add_argument("--ecs", default=None, help="ECS version to pin (e.g. 8.11)")
    norm.add_argument("-o", "--output", default="-", help="output JSONL path (default: stdout)")
    norm.add_argument("--map", default=None, help="custom field-map yaml (default: bundled)")
    norm.set_defaults(func=_normalize_stream)

    dae = sub.add_parser("daemon", help="watch a dir; normalize new JSONL -> ECS sink")
    dae.add_argument("--watch", required=True, help="directory to watch for *.jsonl")
    dae.add_argument("--ecs", default=None, help="ECS version to pin (e.g. 8.11)")
    dae.add_argument("--es", default=None, help="Elasticsearch URL (bulk sink)")
    dae.add_argument("-o", "--output", default=None, help="file sink path (if no --es)")
    dae.add_argument("--map", default=None, help="custom field-map yaml")
    dae.add_argument("--interval", type=float, default=2.0, help="poll interval seconds")
    dae.add_argument("--once", action="store_true", help="scan once and exit")
    dae.set_defaults(func=_run_daemon)

    return parser


def _run_daemon(args: argparse.Namespace) -> int:
    from .daemon import Daemon, ESSink, FileSink

    if args.es:
        sink: object = ESSink(args.es)
    elif args.output:
        sink = FileSink(args.output)
    else:
        print("rosetta daemon: need --es URL or -o file sink", file=sys.stderr)
        return 2
    daemon = Daemon(args.watch, sink, ecs_version=args.ecs, fieldmap_path=args.map)
    stats = daemon.run(interval=args.interval, once=args.once)
    print(f"rosetta daemon: {stats}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
