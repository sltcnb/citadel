"""Capability advertisement contract — how a tool tells Citadel what it can do.

This is the spine of true tool/orchestrator separation. A tool ships a
``capabilities.yaml`` declaring, per platform, the operations it supports and the
inputs each needs. Citadel reads that declaration and *renders the UI from it* —
forms, options, validation — then routes the user's input back to the tool. No
Citadel code knows what Talon collects on Windows; Talon says so, and the
frontend follows. Swap the tool, the UI changes; touch no orchestrator code.

Flow:  tool declares  →  Citadel builds the input form  →  user fills it  →
       Citadel hands input to the tool  →  tool runs  →  output back to Citadel
       →  Citadel shows the user.

The schema is deliberately small and render-oriented (a typed field list), so a
generic frontend form renderer can handle any tool without bespoke components.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Field types the generic frontend renderer understands. Keep this list and the
# renderer in lockstep — adding a type is the only cross-cutting change.
FIELD_TYPES = frozenset(
    {
        "string",       # single-line text
        "text",         # multi-line text
        "int",
        "float",
        "bool",         # checkbox / toggle
        "enum",         # single choice (options)
        "multiselect",  # many choices (options) — e.g. artifact categories
        "path",         # filesystem path
        "host",         # hostname / IP
        "secret",       # masked input
    }
)

# Platform identifiers a capability can target.
PLATFORMS = frozenset({"windows", "linux", "macos", "android", "ios", "cloud", "any"})

# ── Telemetry advertisement ──────────────────────────────────────────────────
# The same principle as the input fields above, applied to observability: no
# Citadel code should know that Pilot emits token counts or that Sluice emits
# parse outcomes. Each component — tool OR platform service, there is no
# privileged path — declares the event kinds it emits, the fields it wants
# indexed, and the panels it wants rendered. The sink builds its index mapping
# from those declarations, the API builds its aggregations from them, and the
# frontend renders them with one generic component. Swap a tool and its panels
# leave with it; plug one in and its panels appear, with no orchestrator change.

#: Elasticsearch types a declared telemetry field may use. Kept small and
#: explicit — the mapping is built from this, so an unknown type would fail at
#: index-template time, far from the manifest that caused it.
TELEMETRY_FIELD_TYPES = frozenset(
    {
        "keyword",    # exact value — the only thing you can group by
        "text",       # free prose, searchable, NOT groupable
        "long", "integer", "short", "double", "float",
        "boolean",
        "date",
        "flattened",  # arbitrary shallow object (labels)
    }
)

#: Aggregations a panel metric may ask for.
TELEMETRY_METRIC_OPS = frozenset({"count", "sum", "avg", "min", "max", "p95"})

#: How a panel is drawn. The frontend has exactly one component per type.
TELEMETRY_PANEL_TYPES = frozenset(
    {
        "table",       # group_by + metrics, one row per bucket
        "stat",        # metrics only, one headline row
        "timeseries",  # date_histogram + metrics
    }
)


@dataclass
class TelemetryField:
    """One field a component emits and wants indexed.

    Undeclared fields still reach Elasticsearch and stay readable in ``_source``
    — the mapping is ``dynamic: false``, not ``strict`` — but they cannot be
    aggregated. Declaring a field is how a tool makes it groupable.
    """

    name: str                    # dotted path, e.g. "llm.purpose"
    type: str = "keyword"
    label: str = ""              # human name, for column headers

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TelemetryField:
        return cls(name=d["name"], type=d.get("type", "keyword"), label=d.get("label", ""))

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type, "label": self.label}


@dataclass
class TelemetryMetric:
    """One column of a panel."""

    op: str                      # count | sum | avg | min | max | p95
    field: str = ""              # required for every op except count
    label: str = ""
    unit: str = ""               # "" | ms | usd | tokens | percent — a format hint
    # Note: `where` cannot use dataclasses.field(default_factory=...) here —
    # the attribute named `field` above shadows it inside this class body.
    where: dict[str, Any] | None = None   # {"outcome": "failure"} → filtered metric
    tone: str = ""               # "" | bad | good — colour hint when non-zero

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TelemetryMetric:
        return cls(
            op=d.get("op", "count"),
            field=d.get("field", ""),
            label=d.get("label", ""),
            unit=d.get("unit", ""),
            where=dict(d.get("where") or {}) or None,
            tone=d.get("tone", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"op": self.op, "field": self.field, "label": self.label,
                "unit": self.unit, "where": self.where or {}, "tone": self.tone}


@dataclass
class TelemetryPanel:
    """One rendered block on the Telemetry page."""

    key: str
    label: str = ""
    hint: str = ""
    type: str = "table"
    kind: str = ""               # restrict to one event kind
    # Extra restriction beyond `kind`. A plain value is an exact match; a dict
    # is a range — {"http.status_code": {"gte": 400}} is how a panel says
    # "only failures" without the orchestrator knowing what a status code is.
    where: dict[str, Any] | None = None
    group_by: str = ""           # terms field — required for type=table
    limit: int = 15
    order_by: str = ""           # metric label to sort desc by; default doc count
    metrics: list[TelemetryMetric] = field(default_factory=list)
    sample: bool = False         # include the newest matching document per bucket
    interval: str = ""           # timeseries only, e.g. "1h"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TelemetryPanel:
        return cls(
            key=d["key"],
            label=d.get("label", d["key"]),
            hint=d.get("hint", ""),
            type=d.get("type", "table"),
            kind=d.get("kind", ""),
            where=dict(d.get("where") or {}) or None,
            group_by=d.get("group_by", ""),
            limit=int(d.get("limit", 15)),
            order_by=d.get("order_by", ""),
            metrics=[TelemetryMetric.from_dict(m) for m in d.get("metrics", []) or []],
            sample=bool(d.get("sample", False)),
            interval=d.get("interval", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "label": self.label, "hint": self.hint, "type": self.type,
            "kind": self.kind, "where": self.where or {},
            "group_by": self.group_by, "limit": self.limit,
            "order_by": self.order_by, "sample": self.sample, "interval": self.interval,
            "metrics": [m.to_dict() for m in self.metrics],
        }


@dataclass
class TelemetryDeclaration:
    """A component's whole telemetry advertisement."""

    kinds: list[str] = field(default_factory=list)
    fields: list[TelemetryField] = field(default_factory=list)
    panels: list[TelemetryPanel] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TelemetryDeclaration:
        return cls(
            kinds=list(d.get("kinds", []) or []),
            fields=[TelemetryField.from_dict(f) for f in d.get("fields", []) or []],
            panels=[TelemetryPanel.from_dict(p) for p in d.get("panels", []) or []],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kinds": self.kinds,
            "fields": [f.to_dict() for f in self.fields],
            "panels": [p.to_dict() for p in self.panels],
        }


@dataclass
class InputField:
    """One render-able input. The frontend builds a control from ``type``."""

    name: str
    type: str = "string"
    label: str = ""
    required: bool = False
    default: Any = None
    options: list[dict[str, str]] = field(default_factory=list)  # [{value,label,desc?}]
    help: str = ""
    placeholder: str = ""
    depends_on: dict[str, Any] | None = None  # {"field": name, "equals": value}
    min: float | None = None
    max: float | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InputField:
        opts = []
        for o in d.get("options", []) or []:
            if isinstance(o, dict):
                # Preserve every key the tool attached (value/label/desc + any
                # presentation hints like `group`). Citadel stays agnostic — it
                # passes the tool's metadata straight through to the UI.
                val = str(o.get("value", o.get("key", "")))
                opt = dict(o)
                opt["value"] = val
                opt.setdefault("label", str(o.get("value", o.get("key", val))))
                opts.append(opt)
            else:
                opts.append({"value": str(o), "label": str(o)})
        return cls(
            name=d["name"],
            type=d.get("type", "string"),
            label=d.get("label", d["name"]),
            required=bool(d.get("required", False)),
            default=d.get("default"),
            options=opts,
            help=d.get("help", ""),
            placeholder=d.get("placeholder", ""),
            depends_on=d.get("depends_on"),
            min=d.get("min"),
            max=d.get("max"),
        )

    def to_dict(self) -> dict[str, Any]:
        out = {
            "name": self.name, "type": self.type, "label": self.label,
            "required": self.required, "default": self.default,
            "options": self.options, "help": self.help, "placeholder": self.placeholder,
        }
        if self.depends_on:
            out["depends_on"] = self.depends_on
        if self.min is not None:
            out["min"] = self.min
        if self.max is not None:
            out["max"] = self.max
        return out


@dataclass
class Capability:
    """One operation the tool can perform (e.g. "collect triage on Windows")."""

    key: str
    label: str = ""
    description: str = ""
    platforms: list[str] = field(default_factory=lambda: ["any"])
    inputs: list[InputField] = field(default_factory=list)
    output: str = ""  # free text: what it returns (e.g. "bundle → Sluice", "download")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Capability:
        return cls(
            key=d["key"],
            label=d.get("label", d["key"]),
            description=d.get("description", d.get("desc", "")),
            platforms=list(d.get("platforms", ["any"])),
            inputs=[InputField.from_dict(f) for f in d.get("inputs", []) or []],
            output=d.get("output", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "label": self.label, "description": self.description,
            "platforms": self.platforms, "output": self.output,
            "inputs": [f.to_dict() for f in self.inputs],
        }


@dataclass
class CapabilityManifest:
    """A tool's full advertisement: identity + per-platform capabilities."""

    tool: str
    kind: str = ""              # collector | parser | analyzer | …
    version: str = "0.0.0"
    description: str = ""
    platforms: list[str] = field(default_factory=list)  # platforms the tool targets
    capabilities: list[Capability] = field(default_factory=list)
    # Presentation hints the tool declares so the Suite UI needs no hardcoded
    # per-tool registry. All optional; Citadel renders generically if absent.
    stage: str = ""             # pipeline stage label (Collect, Parse, …)
    icon: str = ""              # icon NAME (frontend maps name → component)
    role: str = ""              # short one-line role
    surfaces: list[dict] = field(default_factory=list)  # [{label, to}] UI links
    #: What this component emits, and how it wants it shown. None = emits none.
    telemetry: TelemetryDeclaration | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CapabilityManifest:
        caps = [Capability.from_dict(c) for c in d.get("capabilities", []) or []]
        # Platforms = explicit list, else union of capability platforms.
        platforms = d.get("platforms")
        if not platforms:
            seen: list[str] = []
            for c in caps:
                for p in c.platforms:
                    if p not in seen:
                        seen.append(p)
            platforms = seen
        return cls(
            tool=d["tool"],
            kind=d.get("kind", ""),
            version=str(d.get("version", "0.0.0")),
            description=d.get("description", ""),
            platforms=list(platforms),
            capabilities=caps,
            stage=d.get("stage", ""),
            icon=d.get("icon", ""),
            role=d.get("role", ""),
            surfaces=list(d.get("surfaces", []) or []),
            telemetry=(
                TelemetryDeclaration.from_dict(d["telemetry"])
                if isinstance(d.get("telemetry"), dict)
                else None
            ),
        )

    def validate(self) -> list[str]:
        """Return a list of problems (empty = valid). Cheap, render-time safety."""
        errs: list[str] = []
        for c in self.capabilities:
            for p in c.platforms:
                if p not in PLATFORMS:
                    errs.append(f"{self.tool}.{c.key}: unknown platform '{p}'")
            for f in c.inputs:
                if f.type not in FIELD_TYPES:
                    errs.append(f"{self.tool}.{c.key}.{f.name}: unknown field type '{f.type}'")
                if f.type in ("enum", "multiselect") and not f.options:
                    errs.append(f"{self.tool}.{c.key}.{f.name}: {f.type} needs options")
        errs.extend(self._validate_telemetry())
        return errs

    def _validate_telemetry(self) -> list[str]:
        """Catch a malformed telemetry block at render time rather than letting
        it produce an index-template failure or an empty panel later."""
        t = self.telemetry
        if t is None:
            return []
        errs: list[str] = []
        declared = {f.name for f in t.fields}
        for f in t.fields:
            if f.type not in TELEMETRY_FIELD_TYPES:
                errs.append(f"{self.tool}.telemetry.{f.name}: unknown field type '{f.type}'")
        seen: set[str] = set()
        for p in t.panels:
            if p.key in seen:
                errs.append(f"{self.tool}.telemetry: duplicate panel key '{p.key}'")
            seen.add(p.key)
            if p.type not in TELEMETRY_PANEL_TYPES:
                errs.append(f"{self.tool}.telemetry.{p.key}: unknown panel type '{p.type}'")
            if p.type == "table" and not p.group_by:
                errs.append(f"{self.tool}.telemetry.{p.key}: a table panel needs group_by")
            if p.kind and t.kinds and p.kind not in t.kinds:
                errs.append(
                    f"{self.tool}.telemetry.{p.key}: panel filters kind '{p.kind}' "
                    f"which this tool does not declare"
                )
            for m in p.metrics:
                if m.op not in TELEMETRY_METRIC_OPS:
                    errs.append(f"{self.tool}.telemetry.{p.key}: unknown metric op '{m.op}'")
                if m.op != "count" and not m.field:
                    errs.append(f"{self.tool}.telemetry.{p.key}: op '{m.op}' needs a field")
            # A field this tool groups by must be one it declared as a keyword —
            # grouping on a text field silently returns nothing.
            if p.group_by and p.group_by in declared:
                spec = next(f for f in t.fields if f.name == p.group_by)
                if spec.type not in ("keyword", "boolean", "long", "integer", "short"):
                    errs.append(
                        f"{self.tool}.telemetry.{p.key}: cannot group by "
                        f"'{p.group_by}' ({spec.type}) — use a keyword"
                    )
        return errs

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "kind": self.kind, "version": self.version,
            "description": self.description, "platforms": self.platforms,
            "stage": self.stage, "icon": self.icon, "role": self.role,
            "surfaces": self.surfaces,
            "capabilities": [c.to_dict() for c in self.capabilities],
            **({"telemetry": self.telemetry.to_dict()} if self.telemetry else {}),
        }


def manifest_from_dict(d: dict[str, Any]) -> CapabilityManifest:
    """Parse a tool's capability declaration (already-decoded YAML/JSON dict)."""
    return CapabilityManifest.from_dict(d)


# ── Self-registration (the elastic path) ────────────────────────────────────
# A tool (or a deploy step) writes its manifest to fo:capabilities:<tool>; the
# orchestrator reads it and prefers it over any baked-in copy. Re-register →
# the UI updates with no API rebuild. redis client is injected (dep-free).
CAPABILITIES_KEY_PREFIX = "fo:capabilities:"


def capabilities_redis_key(tool: str) -> str:
    return f"{CAPABILITIES_KEY_PREFIX}{tool}"


def register_capability(redis_client, manifest: dict[str, Any]) -> None:
    """Publish a manifest dict to Redis so the orchestrator picks it up live.

    Validates lightly first (must name a tool); raises only on a missing tool
    name so a bad manifest can't register as an anonymous blob.
    """
    import json

    tool = manifest.get("tool")
    if not tool:
        raise ValueError("manifest has no 'tool' name")
    redis_client.set(capabilities_redis_key(tool), json.dumps(manifest))
