#!/usr/bin/env python3
"""Build citadel-kibana.ndjson — Kibana 8.x saved objects for the fo-case-* indices.

Ships: two data views (all events + detections-only), three visualizations,
one dashboard ("Citadel — Case Overview"). Import:
  curl -u elastic:$PW -X POST "$KIBANA/kibana/api/saved_objects/_import?overwrite=true" \
       -H "kbn-xsrf: true" -F file=@citadel-kibana.ndjson
"""
import json
import uuid

def _id():
    return uuid.uuid4().hex[:12]

def data_view(title, name):
    return {
        "id": _id(),
        "type": "index-pattern",
        "namespaces": ["default"],
        "attributes": {
            "title": title,
            "name": name,
            "timeFieldName": "timestamp",
        },
        "references": [],
    }

def agg_vis(title, index_ref, series):
    """Agg-based vertical bar/pie. series: list of (label, field, is_date_hist)."""
    metrics = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
    aggs = metrics[:]
    for i, (label, field, is_date) in enumerate(series, start=2):
        if is_date:
            aggs.append({
                "id": str(i), "enabled": True, "type": "date_histogram", "schema": "segment",
                "params": {"field": field, "timeRange": {"from": "now-30d", "to": "now"},
                           "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                           "interval": "auto", "drop_partials": False, "min_doc_count": 1,
                           "extended_bounds": {}},
            })
        else:
            aggs.append({
                "id": str(i), "enabled": True, "type": "terms", "schema": "segment",
                "params": {"field": field, "orderBy": "1", "order": "desc", "size": 10,
                           "otherBucket": True, "otherBucketLabel": "Other", "missingBucket": False},
            })
    state = {
        "title": title, "type": "pie" if "pie" in title.lower() else "histogram",
        "params": {"type": "pie" if "pie" in title.lower() else "histogram",
                   "grid": {"categoryLines": False}, "categoryAxes": [], "valueAxes": [],
                   "seriesParams": [], "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "isVisilibityChangeWithDynamic": False, "labels": {}},
        "aggs": aggs,
    }
    return {
        "id": _id(),
        "type": "visualization",
        "namespaces": ["default"],
        "attributes": {
            "title": title,
            "visState": json.dumps(state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": index_ref, "query": {"query": "", "language": "kuery"}, "filter": [],
                })
            },
        },
        "references": [{"id": index_ref, "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern"}],
    }

def dashboard(title, panel_refs, refs_flat):
    panels = []
    x = 0
    y = 0
    for i, pid in enumerate(panel_refs):
        panels.append({
            "type": "visualization", "id": pid,
            "panelIndex": str(i + 1),
            "gridData": {"x": (i % 2) * 24, "y": y, "w": 24, "h": 15},
            "panelRefName": f"panel_{i}",
        })
        if i % 2 == 1:
            y += 15
    return {
        "id": _id(),
        "type": "dashboard",
        "namespaces": ["default"],
        "attributes": {
            "title": title,
            "description": "Events, detections and severities across the case (fo-case-* indices).",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs_flat,
    }

dv_all = data_view("fo-case-*", "Citadel — all events")
dv_det = data_view("fo-case-*-detection,fo-case-*-hayabusa,fo-case-*-finding", "Citadel — detections & findings")

v1 = agg_vis("Events over time", dv_all["id"], [("events", "timestamp", True)])
v2 = agg_vis("Detections by level (pie)", dv_det["id"], [("level", "level.keyword", False)])
v3 = agg_vis("Top artifact types", dv_all["id"], [("artifact_type", "artifact_type", False)])

dash = dashboard(
    "Citadel — Case Overview",
    [v1["id"], v2["id"], v3["id"]],
    [
        {"id": v1["id"], "name": "panel_0", "type": "visualization"},
        {"id": v2["id"], "name": "panel_1", "type": "visualization"},
        {"id": v3["id"], "name": "panel_2", "type": "visualization"},
    ],
)

with open("citadel-kibana.ndjson", "w") as fh:
    for obj in (dv_all, dv_det, v1, v2, v3, dash):
        fh.write(json.dumps(obj) + "\n")
print("wrote citadel-kibana.ndjson")
