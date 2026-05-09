"""LangGraph StateGraph for MemoryHound.

Skeleton topology:  session_init -> claude_dispatch -> session_finalize -> END
Sub-Plan 03 will fan this out per IR_FRAMEWORKS_REFERENCE.md §11.2.
"""
from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .nodes import NODES
from .state import IncidentState

DEFAULT_RECURSION_LIMIT = 25


def build_graph(recursion_limit: int = DEFAULT_RECURSION_LIMIT) -> Any:
    """Compile the skeleton graph. Recursion limit is bound at invoke-time
    via .with_config; this caps node iterations as required by the hackathon
    multi-agent submission rules."""
    g: StateGraph = StateGraph(IncidentState)
    g.add_node("session_init", NODES["session_init"])
    g.add_node("claude_dispatch", NODES["claude_dispatch"])
    g.add_node("session_finalize", NODES["session_finalize"])
    g.set_entry_point("session_init")
    g.add_edge("session_init", "claude_dispatch")
    g.add_edge("claude_dispatch", "session_finalize")
    g.add_edge("session_finalize", END)
    compiled = g.compile()
    return compiled.with_config({"recursion_limit": recursion_limit})
