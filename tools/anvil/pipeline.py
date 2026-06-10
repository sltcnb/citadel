"""Anvil — analyzer DAG pipeline.

Chains :class:`~base.BaseModule` analyzers into a directed acyclic graph: a node
runs after all its dependencies, and each node sees the upstream :class:`Result`
objects (so a downstream analyzer can act on what an upstream one produced —
e.g. unpack → analyze, or strings → grep). Execution is single-process and
topologically ordered; a cycle is rejected up front.

Standalone::

    from pipeline import Pipeline, Node
    pipe = Pipeline([
        Node("strings", StringsModule()),
        Node("grep", GrepSearchModule(), depends_on=["strings"]),
    ])
    results = pipe.run(ctx)          # {node_id: Result}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from base import BaseModule, Result, RunContext


@dataclass
class Node:
    """One analyzer in the DAG."""

    id: str
    module: BaseModule
    depends_on: list[str] = field(default_factory=list)


class Pipeline:
    """A DAG of analyzer nodes executed in dependency order."""

    def __init__(self, nodes: list[Node]) -> None:
        self.nodes = {n.id: n for n in nodes}
        if len(self.nodes) != len(nodes):
            raise ValueError("duplicate node id in pipeline")
        for n in nodes:
            for dep in n.depends_on:
                if dep not in self.nodes:
                    raise ValueError(f"node {n.id!r} depends on unknown node {dep!r}")
        self._order = self._toposort()

    def _toposort(self) -> list[str]:
        """Kahn's algorithm; raises on a cycle."""
        indeg = {nid: 0 for nid in self.nodes}
        for n in self.nodes.values():
            for _dep in n.depends_on:
                indeg[n.id] += 1
        ready = [nid for nid, d in indeg.items() if d == 0]
        order: list[str] = []
        while ready:
            nid = ready.pop(0)
            order.append(nid)
            for other in self.nodes.values():
                if nid in other.depends_on:
                    indeg[other.id] -= 1
                    if indeg[other.id] == 0:
                        ready.append(other.id)
        if len(order) != len(self.nodes):
            raise ValueError("pipeline has a cycle")
        return order

    @property
    def order(self) -> list[str]:
        return list(self._order)

    def run(self, ctx: RunContext) -> dict[str, Result]:
        """Run every node in topological order.

        Each node's :class:`RunContext` carries the upstream results under
        ``params['upstream']`` (``{dep_id: Result}``) so a downstream analyzer
        can consume what its dependencies produced.
        """
        results: dict[str, Result] = {}
        for nid in self._order:
            node = self.nodes[nid]
            upstream = {dep: results[dep] for dep in node.depends_on}
            node_ctx = RunContext(
                run_id=ctx.run_id,
                case_id=ctx.case_id,
                source_files=ctx.source_files,
                params={**ctx.params, "upstream": upstream},
                minio_client=ctx.minio_client,
                redis_client=ctx.redis_client,
                tmp_dir=ctx.tmp_dir,
            )
            results[nid] = node.module.run(node_ctx)
        return results

    def to_dict(self, results: dict[str, Result]) -> dict[str, Any]:
        """Serialise a run for the processor/Timeline (per-node + merged hits)."""
        merged: list[dict[str, Any]] = []
        for nid in self._order:
            merged.extend(results[nid].to_dict()["hits"])
        return {
            "pipeline": self._order,
            "nodes": {nid: results[nid].to_dict() for nid in self._order},
            "hits": merged,
        }
