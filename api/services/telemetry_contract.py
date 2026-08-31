"""Telemetry, derived from what each component advertises.

The orchestrator half of the telemetry contract (see
``citadel_contracts.capabilities``). Nothing here knows that Pilot emits token
counts or that Sluice emits parse outcomes: every event kind, indexed field and
rendered panel comes from a ``telemetry:`` block in some component's
``capabilities.yaml``. Platform services advertise through exactly the same
mechanism as tools — there is no built-in path.

Three things are derived from the merged declarations:

* the **index mapping** the sink installs, so a component's own fields are
  aggregatable rather than silently swallowed by ``dynamic: false``;
* the **aggregations** ``/admin/telemetry/summary`` runs;
* the **panels** the frontend draws, generically.

Drop a tool and its panels leave with it. Plug one in and its panels appear.
"""

from __future__ import annotations

import logging
from typing import Any

from citadel_contracts import manifest_from_dict

logger = logging.getLogger(__name__)


class MergedTelemetry:
    """Every component's telemetry advertisement, combined."""

    def __init__(self) -> None:
        self.kinds: list[str] = []
        self.fields: dict[str, dict] = {}          # name -> {"type", "label", "tool"}
        self.panels: list[dict] = []               # panel dict + "tool"
        self.warnings: list[str] = []

    def add(self, tool: str, declaration: dict) -> None:
        for kind in declaration.get("kinds") or []:
            if kind not in self.kinds:
                self.kinds.append(kind)
        for f in declaration.get("fields") or []:
            name = f.get("name")
            if not name:
                continue
            prior = self.fields.get(name)
            if prior and prior["type"] != f.get("type", "keyword"):
                # Two components claiming different types for one field is a
                # real conflict: the first mapping wins and the second's data
                # would be rejected at index time. Say so rather than guess.
                self.warnings.append(
                    f"field '{name}' declared as {prior['type']} by {prior['tool']} "
                    f"and {f.get('type')} by {tool}; keeping {prior['type']}"
                )
                continue
            self.fields.setdefault(
                name, {"type": f.get("type", "keyword"), "label": f.get("label", ""), "tool": tool}
            )
        for p in declaration.get("panels") or []:
            self.panels.append({**p, "tool": tool})

    # ── derived artefacts ────────────────────────────────────────────────────
    def index_properties(self) -> dict:
        """The advertised fields as an Elasticsearch ``properties`` tree."""
        props: dict[str, Any] = {}
        for name, spec in sorted(self.fields.items()):
            node = props
            parts = name.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {"properties": {}})["properties"]
            leaf = {"type": spec["type"]}
            if spec["type"] == "text":
                leaf["index"] = True
            node[parts[-1]] = leaf
        return props

    def panel(self, key: str) -> dict | None:
        return next((p for p in self.panels if p.get("key") == key), None)


def merged(manifests: list[dict]) -> MergedTelemetry:
    """Merge the telemetry block of every manifest that declares one."""
    out = MergedTelemetry()
    for doc in manifests:
        tool = doc.get("tool") or "?"
        decl = doc.get("telemetry")
        if not isinstance(decl, dict):
            continue
        try:
            # Round-trip through the contract so a malformed block is reported
            # rather than half-applied.
            m = manifest_from_dict({**doc, "telemetry": decl})
            problems = [w for w in m.validate() if ".telemetry" in w or "telemetry:" in w]
            if problems:
                out.warnings.extend(problems)
                continue
            out.add(tool, m.telemetry.to_dict() if m.telemetry else {})
        except Exception as exc:  # noqa: BLE001 — one bad manifest must not blind the rest
            out.warnings.append(f"{tool}: unreadable telemetry block: {exc}")
    return out


# ── query construction ───────────────────────────────────────────────────────
# Must stay an int: the order path is "<agg>.<percent>" and Elasticsearch reads
# "m0.95.0" as a nested path, not as the 95th percentile of m0.
_PCT = 95


def _filter_clauses(where: dict | None) -> list[dict]:
    """Turn an advertised ``where`` into Elasticsearch clauses.

    A plain value is a term match; a dict is a range. Declaring it this way is
    what lets a manifest say "only 4xx and 5xx" without any code here knowing
    what an HTTP status code is.
    """
    clauses: list[dict] = []
    for field_name, value in (where or {}).items():
        if isinstance(value, dict):
            clauses.append({"range": {field_name: value}})
        elif isinstance(value, list):
            clauses.append({"terms": {field_name: value}})
        else:
            clauses.append({"term": {field_name: value}})
    return clauses


def _metric_agg(metric: dict) -> tuple[dict, bool]:
    """(aggregation, needs_value_unwrap) for one metric declaration."""
    op = metric.get("op", "count")
    fld = metric.get("field", "")
    where = metric.get("where") or {}

    if op == "count":
        inner: dict = {}
    elif op == "p95":
        inner = {"percentiles": {"field": fld, "percents": [_PCT]}}
    else:
        inner = {op: {"field": fld}}

    if where:
        filt = {"bool": {"filter": _filter_clauses(where)}}
        if not inner:
            return {"filter": filt}, False
        return {"filter": filt, "aggs": {"v": inner}}, True
    return inner, False


def _metric_name(idx: int) -> str:
    return f"m{idx}"


def _order_clause(panel: dict) -> dict:
    """Order a terms agg. Defaults to doc count; a named metric orders by it."""
    order_by = panel.get("order_by") or ""
    if not order_by:
        return {"_count": "desc"}
    for i, m in enumerate(panel.get("metrics") or []):
        if (m.get("label") or "") != order_by:
            continue
        name = _metric_name(i)
        if m.get("where"):
            # A filtered metric orders by its inner value, or its doc count.
            return {f"{name}>v": "desc"} if m.get("op") != "count" else {f"{name}": "desc"}
        # A percentiles agg is multi-valued: the percentile must be named, or
        # Elasticsearch rejects the entire search with invalid_path.
        return {f"{name}.{_PCT}": "desc"} if m.get("op") == "p95" else {name: "desc"}
    return {"_count": "desc"}


def build_aggs(panels: list[dict], interval: str) -> dict:
    """Aggregations for every advertised panel, in one search body."""
    aggs: dict[str, Any] = {}
    for panel in panels:
        metric_aggs: dict[str, Any] = {}
        for i, m in enumerate(panel.get("metrics") or []):
            agg, _ = _metric_agg(m)
            if agg:
                metric_aggs[_metric_name(i)] = agg
        if panel.get("sample"):
            metric_aggs["sample"] = {
                "top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}]}
            }

        ptype = panel.get("type", "table")
        if ptype == "table":
            inner = {
                "buckets": {
                    "terms": {
                        "field": panel["group_by"],
                        "size": int(panel.get("limit", 15)),
                        "order": _order_clause(panel),
                    },
                    **({"aggs": metric_aggs} if metric_aggs else {}),
                }
            }
        elif ptype == "timeseries":
            inner = {
                "buckets": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": panel.get("interval") or interval,
                        "min_doc_count": 0,
                    },
                    **({"aggs": metric_aggs} if metric_aggs else {}),
                }
            }
        else:  # stat
            inner = metric_aggs

        clauses = _filter_clauses(panel.get("where"))
        if panel.get("kind"):
            clauses.insert(0, {"term": {"kind": panel["kind"]}})
        filt = {"bool": {"filter": clauses}} if clauses else {"match_all": {}}
        aggs[panel["key"]] = {"filter": filt, **({"aggs": inner} if inner else {})}
    return aggs


# ── response shaping ─────────────────────────────────────────────────────────
def _metric_value(bucket: dict, name: str, metric: dict) -> Any:
    """Read one metric out of a bucket.

    An unfiltered ``count`` has no sub-aggregation of its own — it IS the
    bucket's doc_count — so it must be read from the bucket rather than from a
    sub-agg that was never created.
    """
    op = metric.get("op", "count")
    where = metric.get("where") or {}
    if op == "count" and not where:
        return bucket.get("doc_count", 0)
    node = bucket.get(name) or {}
    if where:
        if op == "count":
            return node.get("doc_count", 0)
        node = node.get("v") or {}
    if op == "p95":
        values = (node or {}).get("values") or {}
        val = next((v for v in values.values() if v is not None), None)
        return round(val, 1) if val is not None else None
    val = (node or {}).get("value")
    return round(val, 4) if isinstance(val, float) else val


def _columns(panel: dict) -> list[dict]:
    cols = []
    for i, m in enumerate(panel.get("metrics") or []):
        cols.append(
            {
                "key": _metric_name(i),
                "label": m.get("label") or m.get("op", ""),
                "unit": m.get("unit", ""),
                "tone": m.get("tone", ""),
            }
        )
    return cols


def shape(panels: list[dict], aggregations: dict) -> list[dict]:
    """Turn the raw aggregation response into render-ready panels."""
    out = []
    for panel in panels:
        node = (aggregations or {}).get(panel["key"]) or {}
        ptype = panel.get("type", "table")
        metrics = panel.get("metrics") or []
        rows: list[dict] = []

        if ptype == "stat":
            row = {_metric_name(i): _metric_value(node, _metric_name(i), m)
                   for i, m in enumerate(metrics)}
            row["count"] = node.get("doc_count", 0)
            rows = [row]
        else:
            for b in ((node.get("buckets") or {}).get("buckets") or []):
                row = {
                    "key": b.get("key_as_string") or b.get("key"),
                    "count": b.get("doc_count", 0),
                }
                for i, m in enumerate(metrics):
                    row[_metric_name(i)] = _metric_value(b, _metric_name(i), m)
                if panel.get("sample"):
                    hits = (((b.get("sample") or {}).get("hits") or {}).get("hits") or [])
                    row["sample"] = hits[0].get("_source") if hits else None
                rows.append(row)

        out.append(
            {
                "key": panel["key"],
                "label": panel.get("label") or panel["key"],
                "hint": panel.get("hint", ""),
                "type": ptype,
                "tool": panel.get("tool", ""),
                "kind": panel.get("kind", ""),
                "group_by": panel.get("group_by", ""),
                "total": node.get("doc_count", 0),
                "columns": _columns(panel),
                "rows": rows,
            }
        )
    return out
