"""
Entity graph router — lateral-movement view.

Endpoints (all case-scoped, behind require_case_access):

  GET /cases/{case_id}/graph?focus=&limit=
      → {nodes, edges} host↔user↔ip co-occurrence graph.

  GET /cases/{case_id}/graph/entities?limit=
      → {hosts, users} top entities for a focus picker.

Follows the conventions in routers/anomaly.py.
"""

from __future__ import annotations

import logging

from auth.dependencies import require_case_access
from fastapi import APIRouter, Depends, Query

from services.entity_graph import build_graph, list_entities

logger = logging.getLogger(__name__)
router = APIRouter(tags=["entity_graph"])


@router.get("/cases/{case_id}/graph")
def get_entity_graph(
    case_id: str,
    _acl: dict = Depends(require_case_access),
    focus: str | None = Query(None, description="Scope to a hostname or username"),
    limit: int = Query(50, ge=1, le=200),
):
    """Return the host↔user↔ip entity graph for a case.

    ``focus`` optionally scopes the graph to one entity's neighbourhood.
    """
    return build_graph(case_id, focus=focus, limit=limit)


@router.get("/cases/{case_id}/graph/entities")
def get_graph_entities(
    case_id: str,
    _acl: dict = Depends(require_case_access),
    limit: int = Query(50, ge=1, le=500),
):
    """Return the top hosts and users in a case (for the focus picker)."""
    return list_entities(case_id, limit=limit)
