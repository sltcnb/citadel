#!/usr/bin/env python3
"""Generate the field inventory a detection rule is allowed to reference.

A rule that queries a field no parser ever writes is worse than a missing rule:
it looks like coverage, runs clean, and reports zero hits forever. Real examples
this catches (all were shipping in the corpus):

    registry.key         → the plugin writes registry.key_path
    registry.value       → the plugin writes registry.matched_value
    lnk.target           → the plugin writes lnk.target_path
    mft.full_path        → the plugin writes mft.filepath
    syslog.message       → the plugin writes syslog.raw_message
    prefetch.path        → no such field; it writes prefetch.executable_name
    hindsight.visit.*    → the hindsight module indexes no such sub-object

The inventory is derived from the parsers themselves — Babel plugin literals, the
declarative cloud_audit mapping specs, and the shared ECS sub-objects in the
Elasticsearch index template — so it cannot drift from what is actually indexed.

    python3 tools/sigil/sigil_inventory.py            # write field_inventory.json
    python3 tools/sigil/sigil_inventory.py --print    # dump to stdout
    python3 tools/sigil/sigil_inventory.py --check    # fail if the file is stale

Because it parses source rather than importing it (plugins pull in optional
native deps), extraction is deliberately textual and errs on the side of
including a field: a false "exists" only weakens the lint, while a false
"missing" would block a legitimate rule.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = next((p for p in HERE.parents if (p / "tools" / "babel").exists()), HERE.parents[1])
BABEL = REPO / "tools" / "babel"
TEMPLATE = REPO / "elasticsearch" / "index_templates" / "fo-cases-template.json"
MODULE_TASK = REPO / "tools" / "sluice" / "worker" / "tasks" / "module_task.py"
INVENTORY = HERE / "field_inventory.json"

# Top-level keys every event carries (BasePlugin.make_event + the index template).
_ALWAYS = {
    "fo_id", "case_id", "artifact_type", "timestamp", "timestamp_desc", "message",
    "ingested_at", "ingest_job_id", "source_file", "os", "tags", "analyst_note",
    "is_flagged", "is_pinned", "pin_note", "raw", "host", "user", "process",
    "network", "file", "registry", "http", "dns", "email", "url", "severity",
    "level", "mitre", "techniques", "evidence", "kind", "source_feature",
}


def _brace_block(text: str, start: int) -> str:
    """Return the source between the brace at *start* and its match."""
    depth, out = 0, []
    for ch in text[start:]:
        if ch == "{":
            depth += 1
            if depth == 1:
                continue
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        if depth >= 1:
            out.append(ch)
    return "".join(out)


def _subobject_keys(text: str, name: str) -> set[str]:
    """Keys written inside every ``"<name>": { ... }`` literal in *text*.

    Also follows one level of indirection — ``"mft": mft_record`` where
    ``mft_record = { ... }`` is built earlier. Without that, a parser using the
    variable form looks like it emits nothing, the index template's (possibly
    stale) declaration is left standing as the only source, and rules get written
    against field names nothing ever populates. That is exactly what happened
    with the MFT pack: the template declares file_path/file_name/created while
    the parser writes filepath/filename/created_at.
    """
    keys: set[str] = set()
    for m in re.finditer(rf'"{re.escape(name)}":\s*\{{', text):
        block = _brace_block(text, m.end() - 1)
        keys |= set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', block))
    # Variable form: "<name>": some_var  →  some_var = { ... }
    for m in re.finditer(rf'"{re.escape(name)}":\s*(\*\*)?([a-z_][a-z0-9_]*)\s*[,}}]', text):
        var = m.group(2)
        for a in re.finditer(rf"\b{re.escape(var)}\s*=\s*\{{", text):
            block = _brace_block(text, a.end() - 1)
            keys |= set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', block))
    return keys


def build() -> dict:
    artifact_types: set[str] = set()
    fields: dict[str, set[str]] = {}

    # ── Shared ECS sub-objects, from the index template (authoritative) ──
    tpl = json.loads(TEMPLATE.read_text())
    for name, spec in tpl["template"]["mappings"]["properties"].items():
        if isinstance(spec, dict) and "properties" in spec:
            fields.setdefault(name, set()).update(spec["properties"].keys())

    # ── Babel python plugins ──
    # Sub-object keys are attributed ONLY to the plugin that owns the artifact
    # type, and the owning plugin REPLACES rather than extends the inventory for
    # its own namespace. Unioning across every file that happened to contain a
    # `"mft": {` literal is how this tool once reported mft.file_path / file_name
    # (picked up from an unrelated module) when the parser actually emits
    # filepath / filename — and a rule was "fixed" onto the wrong name as a
    # result. A wrong name is worse than a missing entry: it looks authoritative.
    owned: dict[str, set[str]] = {}
    for path in sorted(BABEL.glob("*/*_plugin.py")):
        text = path.read_text(errors="replace")
        own_types = set(re.findall(r'DEFAULT_ARTIFACT_TYPE\s*=\s*"([a-z0-9_]+)"', text))
        own_types |= set(re.findall(r'"artifact_type":\s*"([a-z0-9_]+)"', text))
        own_types |= set(re.findall(r'artifact_type=["\']([a-z0-9_]+)', text))
        artifact_types |= own_types
        # Only namespaces this plugin actually emits, and only from this plugin.
        for name in own_types | {path.parent.name}:
            keys = _subobject_keys(text, name)
            if keys:
                owned.setdefault(name, set()).update(keys)
        # Shared ECS sub-objects the plugin populates: additive, since several
        # parsers legitimately contribute to host/user/process/network.
        for name in ("host", "user", "process", "network", "file", "http", "registry"):
            keys = _subobject_keys(text, name)
            if keys:
                fields.setdefault(name, set()).update(keys)
    for name, keys in owned.items():
        fields[name] = keys  # authoritative: the owning plugin wins outright

    # ── Declarative cloud/identity mapping specs ──
    specs_dir = BABEL / "cloud_audit" / "specs"
    if specs_dir.is_dir():
        try:
            import yaml
        except ImportError:
            yaml = None  # type: ignore
        if yaml is not None:
            for path in sorted(specs_dir.glob("*.yaml")):
                doc = yaml.safe_load(path.read_text()) or {}
                at = doc.get("artifact_type")
                if not at:
                    continue
                artifact_types.add(at)
                # attributes land under evt[artifact_type]; fields are dotted ECS paths.
                fields.setdefault(at, set()).update((doc.get("attributes") or {}).keys())
                for target in (doc.get("fields") or {}):
                    if "." in target:
                        head, leaf = target.split(".", 1)
                        fields.setdefault(head, set()).add(leaf)

    # ── Module-produced artifact types (module runs index their own hits) ──
    if MODULE_TASK.exists():
        mt = MODULE_TASK.read_text(errors="replace")
        m = re.search(r"_MODULE_ARTIFACT_TYPE[^{]*\{(.*?)\n\}", mt, re.S)
        if m:
            artifact_types |= set(re.findall(r':\s*"([a-z0-9_]+)"', m.group(1)))
        # Built-in module ids double as artifact types (see _generic_module_index_to_es).
        m = re.search(r"RUNNERS\s*=\s*\{(.*?)\n\s{8}\}", mt, re.S)
        if m:
            artifact_types |= set(re.findall(r'"([a-z0-9_]+)":', m.group(1)))
        m = re.search(r"_ES_RUNNERS\s*=\s*\{(.*?)\n\s{8}\}", mt, re.S)
        if m:
            artifact_types |= set(re.findall(r'"([a-z0-9_]+)":', m.group(1)))
        # Every module hit is indexed with these keys under its artifact type.
        for at in ("cti_match",):
            fields.setdefault(at, set())
    # A module's sub-object always carries the generic hit shape.
    _MODULE_HIT_KEYS = {"level", "level_int", "rule_title", "section"}
    for at in ("hayabusa", "yara", "volatility", "hindsight", "regripper", "wintriage",
               "cuckoo", "cti_match", "browser_report", "auth_summary",
               "network_summary", "rare_process"):
        artifact_types.add(at)
        fields.setdefault(at, set()).update(_MODULE_HIT_KEYS)

    artifact_types |= {"finding", "detection"}
    artifact_types |= set(fields)

    return {
        "_generated_by": "tools/sigil/sigil_inventory.py",
        "_note": "Do not hand-edit; regenerate when a parser's output changes.",
        "artifact_types": sorted(artifact_types),
        "always_present": sorted(_ALWAYS),
        "fields": {k: sorted(v) for k, v in sorted(fields.items()) if v},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--print", dest="dump", action="store_true", help="write to stdout")
    ap.add_argument("--check", action="store_true", help="exit 1 if the checked-in file is stale")
    args = ap.parse_args(argv)

    inv = build()
    text = json.dumps(inv, indent=2, sort_keys=False) + "\n"

    if args.dump:
        sys.stdout.write(text)
        return 0
    if args.check:
        if not INVENTORY.exists():
            print(f"{INVENTORY.name} is missing — run sigil_inventory.py", file=sys.stderr)
            return 1
        if INVENTORY.read_text() != text:
            print(
                f"{INVENTORY.name} is stale — a parser's fields changed. "
                "Re-run: python3 tools/sigil/sigil_inventory.py",
                file=sys.stderr,
            )
            return 1
        print(f"{INVENTORY.name} is up to date "
              f"({len(inv['artifact_types'])} artifact types, "
              f"{sum(len(v) for v in inv['fields'].values())} fields).")
        return 0

    INVENTORY.write_text(text)
    print(f"wrote {INVENTORY.relative_to(REPO)} — "
          f"{len(inv['artifact_types'])} artifact types, "
          f"{sum(len(v) for v in inv['fields'].values())} fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
