"""Cloud & identity audit-log parser — one parser, many sources.

Cloud and identity logs (AWS CloudTrail, Microsoft Entra / O365, GCP, Okta, …)
are all JSON. The hard part isn't reading them, it's *mapping* each provider's
shape onto the canonical timeline. So this parser carries no provider logic at
all: it loads declarative mapping specs from ``specs/*.yaml`` and drives the
shared :mod:`citadel_contracts.mapping` engine. Supporting a new source is a new
YAML file — no code change, no new parser, no new image.

Files may be a single object, a JSON array, an envelope (``{"Records":[…]}``,
``{"value":[…]}``), or JSON Lines — the engine's ``iter_records`` handles all of
them. ``can_handle`` samples the file and only claims it when a record matches a
known spec, so plain JSON still falls through to the generic ndjson parser.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError

# base_plugin has already put the citadel_contracts package on sys.path.
from citadel_contracts import (  # noqa: E402
    MappingSpec,
    apply_mapping,
    detect_spec,
    iter_records,
)

_SPECS_DIR = Path(__file__).resolve().parent / "specs"
_SAMPLE_BYTES = 256 * 1024  # how much of a file to read when sniffing the source


def _load_specs() -> list[MappingSpec]:
    """Load every spec under specs/*.yaml. Missing yaml or a bad file is
    non-fatal — the parser just supports fewer sources."""
    specs: list[MappingSpec] = []
    try:
        import yaml
    except ImportError:
        return specs
    if not _SPECS_DIR.is_dir():
        return specs
    for path in sorted(_SPECS_DIR.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
            if isinstance(doc, dict) and doc.get("name"):
                specs.append(MappingSpec.from_dict(doc))
        except Exception:  # noqa: BLE001 — one bad spec must not break the rest
            continue
    return specs


# Loaded once at import; cheap and stable across a parse run.
_SPECS: list[MappingSpec] = _load_specs()


def _decode_records(path: Path) -> list[dict]:
    """Best-effort decode of a cloud-log file into record dicts.

    Tries whole-document JSON first (object/array/envelope), then falls back to
    JSON Lines. Returns [] if nothing parses.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    text_stripped = text.lstrip()
    if text_stripped[:1] in ("{", "["):
        try:
            return iter_records(json.loads(text))
        except (json.JSONDecodeError, ValueError):
            pass
    # JSON Lines
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            out.extend(iter_records(obj))
    return out


def _sample_records(path: Path) -> list[dict]:
    """Decode just the head of a file for source sniffing (cheap can_handle)."""
    try:
        with open(path, errors="replace") as fh:
            head = fh.read(_SAMPLE_BYTES)
    except OSError:
        return []
    head_stripped = head.lstrip()
    if head_stripped[:1] == "{":
        try:
            return iter_records(json.loads(head))
        except (json.JSONDecodeError, ValueError):
            pass
    if head_stripped[:1] == "[":
        # Truncated array — recover the first complete object.
        depth = 0
        start = head.find("{")
        if start != -1:
            for i in range(start, len(head)):
                if head[i] == "{":
                    depth += 1
                elif head[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return [json.loads(head[start : i + 1])]
                        except (json.JSONDecodeError, ValueError):
                            break
    for line in head.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                return iter_records(obj)
        except (json.JSONDecodeError, ValueError):
            continue
    return []


class CloudAuditPlugin(BasePlugin):
    """Maps cloud/identity audit logs to the timeline via declarative specs."""

    PLUGIN_NAME = "cloud_audit"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "cloud_audit"
    SUPPORTED_EXTENSIONS = [".json", ".jsonl", ".ndjson", ".log"]
    SUPPORTED_MIME_TYPES = ["application/json", "application/x-ndjson"]
    # Beat the generic ndjson/json fallbacks for recognised cloud sources.
    PLUGIN_PRIORITY = 90

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._parsed = 0
        self._skipped = 0
        self._spec: MappingSpec | None = None

    @classmethod
    def get_info(cls) -> dict[str, Any]:
        """Advertise the mapped sources alongside the standard metadata so the
        Ingesters view shows what this one parser actually covers."""
        info = super().get_info()
        info["sources"] = sorted(s.name for s in _SPECS)
        info["description"] = (
            "Cloud & identity audit logs via declarative specs "
            f"({len(_SPECS)} sources: {', '.join(info['sources'])})"
        )
        return info

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        if file_path.suffix.lower() not in cls.SUPPORTED_EXTENSIONS:
            return False
        if not _SPECS:
            return False
        for rec in _sample_records(file_path):
            if detect_spec(rec, _SPECS) is not None:
                return True
        return False

    def _map(self, record: dict) -> dict | None:
        # Fast path: a file is almost always a single source — try the last
        # matching spec before re-detecting across all of them.
        if self._spec is not None and self._spec.detect_match(record):
            spec = self._spec
        else:
            spec = detect_spec(record, _SPECS)
            if spec is None:
                return None
            self._spec = spec
        return apply_mapping(record, spec)

    def parse(self) -> Generator[dict[str, Any], None, None]:
        records = _decode_records(self.ctx.source_file_path)
        if not records:
            raise PluginFatalError("No JSON records found in cloud audit file")
        for record in records:
            evt = self._map(record)
            if evt is None:
                self._skipped += 1
                continue
            evt["fo_id"] = str(uuid.uuid4())
            self._parsed += 1
            yield evt

    def get_stats(self) -> dict[str, Any]:
        return {
            "records_parsed": self._parsed,
            "records_skipped": self._skipped,
            "source": self._spec.name if self._spec else None,
            "specs_loaded": len(_SPECS),
        }
