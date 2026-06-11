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
    def from_dict(cls, d: dict[str, Any]) -> "InputField":
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
    def from_dict(cls, d: dict[str, Any]) -> "Capability":
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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CapabilityManifest":
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
        return errs

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "kind": self.kind, "version": self.version,
            "description": self.description, "platforms": self.platforms,
            "capabilities": [c.to_dict() for c in self.capabilities],
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
