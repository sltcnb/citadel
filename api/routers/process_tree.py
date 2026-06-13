"""
Process tree reconstruction.

Sources:
  - Windows : EVTX 4688 (Process Creation) + Sysmon-for-Windows event ID 1
  - Linux   : auditd SYSCALL records where syscall ∈ (execve, execveat),
              + Sysmon-for-Linux event ID 1 (same shape as Windows Sysmon)

All three feed the same shared `process.pid` / `process.ppid` fields, so the
graph builder treats them identically.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from auth.dependencies import get_current_user, require_case_access
from fastapi import APIRouter, Depends, HTTPException, Query
from services.elasticsearch import build_bool_query
from services.elasticsearch import es_request as es_req

logger = logging.getLogger(__name__)
router = APIRouter(tags=["process-tree"])

# OS-agnostic "this is a process creation event" predicate.
# Windows : evtx.event_id ∈ (4688, 1) — Sysmon Windows reuses ID 1.
# Linux   : audit_event with audit.syscall ∈ (execve, execveat).
PROCESS_CREATION_FILTER = {
    "bool": {
        "should": [
            {"term": {"evtx.event_id": 4688}},
            {"term": {"evtx.event_id": 1}},  # Sysmon (Windows + Linux port)
            {
                "bool": {
                    "must": [
                        {"term": {"artifact_type": "audit_event"}},
                        {"terms": {"audit.syscall": ["execve", "execveat"]}},
                    ]
                }
            },
        ],
        "minimum_should_match": 1,
    }
}


@router.get("/cases/{case_id}/process-tree")
def process_tree(
    case_id: str,
    _: dict = Depends(get_current_user),
    _case: dict = Depends(require_case_access),
    host: str | None = Query(default=None, description="Restrict to a single hostname"),
    size: int = Query(2000, ge=10, le=10000),
):
    """Return the process tree(s) reconstructed from EVTX 4688 / Sysmon 1 / auditd execve.

    Output:
      {
        "hosts": ["L1234", …],
        "selected_host": "L1234",
        "nodes":  [{pid, ppid, name, path, cmdline, user, ts, fo_id, source, children: [pid…]}, …],
        "roots":  [pid, …]
      }
    """
    host_agg = {
        "size": 0,
        "query": PROCESS_CREATION_FILTER,
        "aggs": {"hosts": {"terms": {"field": "host.hostname.keyword", "size": 100}}},
    }
    try:
        ha = es_req("POST", f"/fo-case-{case_id}-*/_search", host_agg)
    except Exception:
        ha = {}
    hosts = [b["key"] for b in ha.get("aggregations", {}).get("hosts", {}).get("buckets", [])]
    selected_host = host or (hosts[0] if hosts else None)

    if not selected_host:
        return {"hosts": [], "selected_host": None, "nodes": [], "roots": []}

    must = [
        {"term": {"host.hostname.keyword": selected_host}},
        PROCESS_CREATION_FILTER,
    ]
    body = {
        "size": size,
        "query": build_bool_query(must=must),
        "sort": [{"timestamp": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}}],
        "_source": [
            "fo_id",
            "timestamp",
            "host",
            "user",
            "process",
            "evtx.event_id",
            "artifact_type",
            "audit.syscall",
        ],
    }
    try:
        res = es_req("POST", f"/fo-case-{case_id}-*/_search", body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Process tree query failed: {exc}")

    nodes_by_pid: dict[int, dict] = {}
    children: dict[int, list[int]] = defaultdict(list)
    pids_with_parents: set[int] = set()

    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        proc = src.get("process") or {}
        pid = proc.get("pid")
        ppid = proc.get("ppid") or proc.get("parent_pid")
        if pid is None:
            continue
        try:
            pid_i = int(pid)
            ppid_i = int(ppid) if ppid is not None and str(ppid).isdigit() else None
        except (TypeError, ValueError):
            continue
        # Keep the FIRST occurrence (process creation), skip later updates
        if pid_i in nodes_by_pid:
            continue
        artifact = src.get("artifact_type") or ""
        evtx_eid = (src.get("evtx") or {}).get("event_id")
        if evtx_eid == 4688:
            source = "evtx-4688"
        elif evtx_eid == 1:
            source = "sysmon"
        elif artifact == "audit_event":
            source = "auditd"
        else:
            source = artifact or "unknown"

        nodes_by_pid[pid_i] = {
            "pid": pid_i,
            "ppid": ppid_i,
            "name": proc.get("executable_name") or proc.get("name") or "",
            "path": proc.get("path") or proc.get("exe") or "",
            "cmdline": proc.get("command_line") or "",
            "user": (src.get("user") or {}).get("name", "") or proc.get("user", ""),
            "integrity_level": proc.get("integrity_level", ""),
            "hash_sha256": proc.get("hash_sha256", ""),
            "parent_name": proc.get("parent_executable") or proc.get("parent_name", ""),
            "ts": src.get("timestamp", ""),
            "fo_id": src.get("fo_id"),
            "event_id": evtx_eid,
            "source": source,
        }
        if ppid_i is not None:
            children[ppid_i].append(pid_i)
            pids_with_parents.add(pid_i)

    # Attach children to each node
    for pid_i, node in nodes_by_pid.items():
        node["children"] = sorted(children.get(pid_i, []), key=lambda p: nodes_by_pid[p]["ts"])

    # Roots: nodes whose parent is not present in our set
    roots = sorted(
        [pid for pid in nodes_by_pid.keys() if nodes_by_pid[pid]["ppid"] not in nodes_by_pid],
        key=lambda p: nodes_by_pid[p]["ts"],
    )

    return {
        "hosts": hosts,
        "selected_host": selected_host,
        "nodes": list(nodes_by_pid.values()),
        "roots": roots,
    }
