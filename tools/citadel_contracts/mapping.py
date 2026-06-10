"""Declarative event-mapping engine — turn any structured record into a
contract-compliant ForensicEvent without writing a parser.

A *mapping spec* is plain data (a dict, usually authored as YAML). It says how
to recognise a source (``detect``), where the timestamp lives, how to phrase the
message, and which source paths feed the canonical event fields. Adding support
for a new log source is therefore a data change, not a code change — which is
the whole point: one engine, N sources.

    spec = {
      "name": "aws_cloudtrail",
      "artifact_type": "aws_cloudtrail",
      "detect": {"all": ["eventVersion", "eventSource"]},
      "timestamp": ["eventTime"],
      "message": "{eventName} on {eventSource} by {userIdentity.userName}",
      "fields": {                       # canonical event path  <-  source path|transforms
        "user.name": "userIdentity.userName",
        "network.src_ip": "sourceIPAddress|ip",
      },
      "attributes": {                   # extra columns, namespaced under artifact_type
        "event_name": "eventName",
        "event_source": "eventSource",
      },
    }
    evt = apply_mapping(record, MappingSpec.from_dict(spec))

The engine is dependency-free; callers load specs however they like (YAML, JSON,
Python) and hand dicts in. Timestamp canonicalisation reuses ``parser.iso_z`` so
mapped events match hand-written parsers exactly.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .parser import iso_z

# ── Transform registry ────────────────────────────────────────────────────
# Small, composable value transforms referenced by name in a spec
# ("path|lower|strip"). register_transform() lets a tool add its own — the
# engine stays "able to do anything" without edits here.
_TRANSFORMS: dict[str, Callable[[Any], Any]] = {}


def register_transform(name: str, fn: Callable[[Any], Any]) -> None:
    """Add/override a named transform. Idempotent; last registration wins."""
    _TRANSFORMS[name] = fn


def _coerce_ip(value: Any) -> Any:
    """Strip :port, [..] brackets and %zone so an ES ``ip`` field accepts it."""
    if not isinstance(value, str):
        return value
    v = value.strip().split("%", 1)[0]
    if v.startswith("["):
        v = v[1:].partition("]")[0]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        head, sep, tail = v.rpartition(":")
        if sep and tail.isdigit() and head:
            try:
                return str(ipaddress.ip_address(head))
            except ValueError:
                return value
    return value


def _safe(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
    def wrapped(v: Any) -> Any:
        try:
            return fn(v)
        except (ValueError, TypeError, AttributeError):
            return v
    return wrapped


# Built-ins. Each is defensive — a bad value returns unchanged, never raises.
register_transform("lower", _safe(lambda v: v.lower() if isinstance(v, str) else v))
register_transform("upper", _safe(lambda v: v.upper() if isinstance(v, str) else v))
register_transform("strip", _safe(lambda v: v.strip() if isinstance(v, str) else v))
register_transform("str", _safe(lambda v: str(v)))
register_transform("int", _safe(lambda v: int(v)))
register_transform("float", _safe(lambda v: float(v)))
register_transform("bool", _safe(lambda v: bool(v)))
register_transform("ip", _coerce_ip)
register_transform("basename", _safe(lambda v: re.split(r"[\\/]", str(v))[-1]))
register_transform("first", _safe(lambda v: v[0] if isinstance(v, list) and v else v))
register_transform("last", _safe(lambda v: v[-1] if isinstance(v, list) and v else v))
register_transform("join", _safe(lambda v: ", ".join(map(str, v)) if isinstance(v, list) else v))
register_transform("domain_of", _safe(lambda v: v.split("@", 1)[1] if isinstance(v, str) and "@" in v else v))
register_transform("user_of", _safe(lambda v: v.split("@", 1)[0] if isinstance(v, str) and "@" in v else v))


# ── Path access ───────────────────────────────────────────────────────────
def get_path(record: Any, path: str) -> Any:
    """Resolve a dotted path with optional numeric list indices.

    ``a.b.c`` walks dicts; ``a.0.b`` indexes a list. Returns None on any miss
    so callers never have to guard each hop.
    """
    cur = record
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _parse_value_spec(spec: str) -> tuple[str, list[str]]:
    """Split a ``"path|tf1|tf2"`` value spec into (path, [transforms])."""
    parts = [p.strip() for p in spec.split("|")]
    return parts[0], parts[1:]


def _extract(record: Any, value_spec: str) -> Any:
    """Resolve a value spec against the record and run its transforms."""
    path, tfs = _parse_value_spec(value_spec)
    val = get_path(record, path)
    for name in tfs:
        fn = _TRANSFORMS.get(name)
        if fn is not None:
            val = fn(val)
    return val


_TOKEN = re.compile(r"\{([^}]+)\}")


def render_template(template: str, record: Any) -> str:
    """Fill ``{path|tf}`` tokens from the record; missing → empty string."""
    def sub(m: "re.Match[str]") -> str:
        val = _extract(record, m.group(1))
        return "" if val is None else str(val)
    return _TOKEN.sub(sub, template).strip()


# ── Spec model ────────────────────────────────────────────────────────────
@dataclass
class MappingSpec:
    name: str
    artifact_type: str
    detect: dict[str, Any] = field(default_factory=dict)
    timestamp: list[str] = field(default_factory=list)
    message: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, str] = field(default_factory=dict)
    envelope: list[str] = field(default_factory=list)
    os: str = "cross"
    priority: int = 100

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MappingSpec":
        ts = d.get("timestamp", [])
        if isinstance(ts, str):
            ts = [ts]
        env = d.get("envelope", [])
        if isinstance(env, str):
            env = [env]
        return cls(
            name=d["name"],
            artifact_type=d.get("artifact_type", d["name"]),
            detect=d.get("detect", {}) or {},
            timestamp=list(ts),
            message=d.get("message", ""),
            fields=d.get("fields", {}) or {},
            attributes=d.get("attributes", {}) or {},
            envelope=list(env),
            os=d.get("os", "cross"),
            priority=int(d.get("priority", 100)),
        )

    def detect_match(self, record: Any) -> bool:
        """True if this spec recognises ``record``.

        Rules (all that are present must hold):
          all:        every listed path must resolve to a non-None value
          any:        at least one listed path must be non-None
          equals:     {path: value} — each must equal exactly
          any_equals: {path: [values]} — value must be in the list
        An empty detect block never matches (avoids a greedy catch-all).
        """
        if not self.detect:
            return False
        all_paths = self.detect.get("all", [])
        if all_paths and not all(get_path(record, p) is not None for p in all_paths):
            return False
        any_paths = self.detect.get("any", [])
        if any_paths and not any(get_path(record, p) is not None for p in any_paths):
            return False
        for p, val in (self.detect.get("equals", {}) or {}).items():
            if get_path(record, p) != val:
                return False
        for p, vals in (self.detect.get("any_equals", {}) or {}).items():
            if get_path(record, p) not in vals:
                return False
        return True


def _set_path(target: dict[str, Any], path: str, value: Any) -> None:
    """Set a dotted path in a nested dict, creating intermediate dicts."""
    parts = path.split(".")
    cur = target
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _is_empty(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {}


def apply_mapping(record: dict[str, Any], spec: MappingSpec) -> dict[str, Any]:
    """Map one source record to a contract-compliant event dict.

    Output mirrors ``BasePlugin.make_event``: canonical timestamp/message,
    optional host/user/process/network sub-dicts, the original record as
    ``raw``, and a namespaced attribute block keyed by artifact_type.
    """
    # Timestamp — first non-empty candidate, canonicalised to ...Z.
    ts_val = None
    for p in spec.timestamp:
        ts_val = _extract(record, p)
        if not _is_empty(ts_val):
            break

    at = spec.artifact_type
    evt: dict[str, Any] = {
        "timestamp": iso_z(ts_val) or "",
        "timestamp_desc": "Event Time",
        "message": render_template(spec.message, record) if spec.message else "",
        "artifact_type": at,
        "raw": record,
    }

    # Canonical fields (user.*, network.*, host.*, process.*, …).
    for target, value_spec in spec.fields.items():
        val = _extract(record, value_spec)
        if not _is_empty(val):
            _set_path(evt, target, val)

    # Namespaced attributes → columns / aggregations.
    attrs: dict[str, Any] = {}
    for short, value_spec in spec.attributes.items():
        val = _extract(record, value_spec)
        if not _is_empty(val):
            attrs[short] = val
    if attrs:
        evt[at] = attrs

    if not evt["message"]:
        # Never index a blank row — fall back to a compact attribute summary.
        head = ", ".join(f"{k}={v}" for k, v in list(attrs.items())[:3])
        evt["message"] = f"{spec.name}: {head}" if head else spec.name

    return evt


# ── Source detection + record iteration ─────────────────────────────────────
def detect_spec(record: dict[str, Any], specs: list[MappingSpec]) -> MappingSpec | None:
    """Return the highest-priority spec that recognises the record, else None."""
    for spec in sorted(specs, key=lambda s: s.priority, reverse=True):
        if spec.detect_match(record):
            return spec
    return None


# Common envelope keys that wrap a list of records in exported cloud logs.
_ENVELOPE_KEYS = ("Records", "records", "value", "entries", "items", "data", "logEvents")


def iter_records(obj: Any, envelope: list[str] | None = None) -> "list[dict]":
    """Flatten a decoded JSON document into individual record dicts.

    Handles: a bare list, a single object, and the ``{"Records": [...]}`` /
    ``{"value": [...]}`` style envelopes used by CloudTrail, Azure, GCP, the
    O365 Management API and Graph. ``envelope`` forces a specific wrapper path.
    """
    if isinstance(obj, list):
        return [r for r in obj if isinstance(r, dict)]
    if not isinstance(obj, dict):
        return []
    if envelope:
        for key in envelope:
            inner = get_path(obj, key)
            if isinstance(inner, list):
                return [r for r in inner if isinstance(r, dict)]
    for key in _ENVELOPE_KEYS:
        inner = obj.get(key)
        if isinstance(inner, list) and inner and isinstance(inner[0], dict):
            return [r for r in inner if isinstance(r, dict)]
    return [obj]
