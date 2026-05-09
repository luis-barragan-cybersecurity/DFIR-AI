"""Diamond Model of Intrusion Analysis helpers.

Wraps state['diamond_graph'] (a NetworkX DiGraph) with vertex/edge primitives
for the four Diamond roles (adversary, capability, infrastructure, victim) and
pivot helpers per Plans/IR_FRAMEWORKS_REFERENCE.md §8.
"""
from __future__ import annotations

from typing import Literal

from .state import IncidentState

Role = Literal["adversary", "capability", "infrastructure", "victim"]


def add_vertex(state: IncidentState, *, role: Role, value: str, **attrs: object) -> None:
    """Add a vertex to the Diamond graph with its role and optional extra attributes."""
    state["diamond_graph"].add_node(value, role=role, **attrs)


def add_relation(state: IncidentState, *, src: str, dst: str, relation: str) -> None:
    """Add a bidirectional edge labeled with the relation between two existing vertices."""
    g = state["diamond_graph"]
    g.add_edge(src, dst, relation=relation)
    g.add_edge(dst, src, relation=relation)


def pivot_candidates(state: IncidentState, vertex: str) -> list[str]:
    """Return list of vertices that share an edge with `vertex` (pivot expansion)."""
    g = state["diamond_graph"]
    if vertex not in g:
        return []
    return list(g.successors(vertex))
