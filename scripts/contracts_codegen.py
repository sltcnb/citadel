#!/usr/bin/env python3
"""Generate TypeScript types from the JSON-Schema contracts.

Single source of truth: ``contracts/*.schema.json`` → ``frontend/src/contracts/*.ts``.
Eliminates hand-maintained, drift-prone event types in the frontend. Run in CI /
pre-commit so the generated types always track the schemas.

    scripts/contracts_codegen.py            # write frontend/src/contracts/*.ts
    scripts/contracts_codegen.py --check    # fail if generated output is stale

Supports the subset of JSON Schema the contracts use: object/properties/required,
primitive types (incl. type unions), enums, arrays, and additionalProperties.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
OUT_DIR = ROOT / "frontend" / "src" / "contracts"

# schema file -> exported TS interface name
SCHEMAS = {
    "forensic_event.schema.json": "ForensicEvent",
    "bundle_manifest.schema.json": "ArtifactBundleManifest",
    "brick.schema.json": "BrickManifest",
}

_PRIM = {"string": "string", "integer": "number", "number": "number",
         "boolean": "boolean", "null": "null"}


def _ts_type(schema: dict, indent: int = 0) -> str:
    t = schema.get("type")
    if "enum" in schema:
        return " | ".join(json.dumps(v) for v in schema["enum"])
    if isinstance(t, list):
        return " | ".join(_PRIM.get(x, "unknown") for x in t)
    if t == "array":
        return f"{_ts_type(schema.get('items', {}), indent)}[]"
    if t == "object" or "properties" in schema:
        return _object_type(schema, indent)
    if t in _PRIM:
        return _PRIM[t]
    return "unknown"


def _object_type(schema: dict, indent: int) -> str:
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    pad = "  " * (indent + 1)
    lines = ["{"]
    for name, sub in props.items():
        opt = "" if name in required else "?"
        desc = sub.get("description")
        if desc:
            lines.append(f"{pad}/** {desc} */")
        key = name if name.isidentifier() else json.dumps(name)
        lines.append(f"{pad}{key}{opt}: {_ts_type(sub, indent + 1)};")
    ap = schema.get("additionalProperties", False)
    if ap is True:
        lines.append(f"{pad}[key: string]: unknown;")
    elif isinstance(ap, dict):
        lines.append(f"{pad}[key: string]: {_ts_type(ap, indent + 1)};")
    lines.append("  " * indent + "}")
    return "\n".join(lines)


def _render(schema_file: str, iface: str) -> str:
    schema = json.loads((CONTRACTS / schema_file).read_text(encoding="utf-8"))
    title = schema.get("title", iface)
    sid = schema.get("$id", schema_file)
    body = _object_type(schema, 0)
    return (f"// AUTO-GENERATED from contracts/{schema_file} — do not edit by hand.\n"
            f"// Regenerate: scripts/contracts_codegen.py\n"
            f"// Contract: {sid}\n\n"
            f"/** {title} */\n"
            f"export interface {iface} {body}\n")


def generate() -> dict[str, str]:
    out = {f"{iface[0].lower() + iface[1:]}.ts": _render(f, iface)
           for f, iface in SCHEMAS.items()}
    index = "// AUTO-GENERATED — do not edit.\n" + "".join(
        f"export type {{ {iface} }} from './{iface[0].lower() + iface[1:]}';\n"
        for iface in SCHEMAS.values())
    out["index.ts"] = index
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate TS types from JSON-Schema contracts.")
    ap.add_argument("--check", action="store_true", help="fail if output is stale")
    ap.add_argument("--out", default=str(OUT_DIR))
    args = ap.parse_args(argv)
    out_dir = Path(args.out)
    files = generate()

    if args.check:
        stale = []
        for name, content in files.items():
            p = out_dir / name
            if not p.exists() or p.read_text(encoding="utf-8") != content:
                stale.append(name)
        if stale:
            print(f"stale generated contracts: {stale}\n  run scripts/contracts_codegen.py")
            return 1
        print("TS contracts up to date")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")
    print(f"Wrote {len(files)} TS contract files to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
