"""LangGraph StateGraph for MemoryHound.

Skeleton topology:  session_init -> claude_dispatch -> session_finalize -> END
Sub-Plan 03 will fan this out per IR_FRAMEWORKS_REFERENCE.md §11.2.

The `route_after_*` functions in this module are pure conditional-edge
selectors per IR_FRAMEWORKS_REFERENCE.md §11.3 — each maps an IncidentState
to the next-node key. They are added in Task 11; the LangGraph wiring lands
in Task 12.
"""
from __future__ import annotations

import os
from typing import Any

from langgraph.graph import END, StateGraph

from . import blast_radius
from .nodes import NODES
from .state import IncidentState

DEFAULT_RECURSION_LIMIT = 25

# Severity values that indicate "no real incident" when no findings surfaced.
# Triage emits a `_findings` list; an empty list combined with low/informational
# severity is the false-positive path → suppress.
_SUPPRESS_SEVERITIES = {"informational", "low"}

# RCA loop cap (§11.3 row 2). After 3 analyze iterations we force progress to
# attack_tag even if `_rca_complete` is still False — analyze itself is
# responsible for emitting an audit warning when the cap is hit.
_ANALYZE_ITER_CAP = 3


def route_after_triage(state: IncidentState) -> str:
    """Severity gate per §11.3 row 1 (RS.MA-03).

    Returns:
        "suppress"          — false-positive path (low/informational severity
                              AND no findings surfaced).
        "declare_incident"  — otherwise (default fail-open: declare on
                              missing/unknown severity to avoid silent drops).
    """
    severity = state.get("severity")
    findings = state.get("_findings", [])
    if severity in _SUPPRESS_SEVERITIES and not findings:
        return "suppress"
    return "declare_incident"


def route_after_analyze(state: IncidentState) -> str:
    """RCA loop cap per §11.3 row 2 (RS.AN-03).

    Returns:
        "attack_tag" — RCA complete OR iteration cap reached (force progress).
        "analyze"    — RCA incomplete and below cap → loop again.
    """
    if state.get("_rca_complete") is True:
        return "attack_tag"
    if state.get("_analyze_iter", 0) >= _ANALYZE_ITER_CAP:
        return "attack_tag"
    return "analyze"


def route_after_contain(state: IncidentState) -> str:
    """Blast-radius escalation gate per §11.3 row 3 (IR-7, reversibility).

    Threshold sourced from `MH_BLAST_RADIUS_THRESHOLD` env var, falling back
    to `blast_radius.DEFAULT_THRESHOLD`. Strict greater-than: score ==
    threshold does NOT escalate (matches `BlastRadius.exceeds_threshold`).

    Returns:
        "human_in_loop" — `_max_blast_score` strictly exceeds threshold.
        "eradicate"     — otherwise.
    """
    threshold = int(
        os.environ.get(
            "MH_BLAST_RADIUS_THRESHOLD", str(blast_radius.DEFAULT_THRESHOLD),
        ),
    )
    if state.get("_max_blast_score", 0) > threshold:
        return "human_in_loop"
    return "eradicate"


def route_after_eradicate(state: IncidentState) -> str:
    """Re-infection retry per §11.3 row 4 (PICERL phase 4 retry).

    Returns:
        "contain" — re-infection detected → loop back to containment.
        "recover" — clean → proceed.
    """
    if state.get("_reinfection_detected", False) is True:
        return "contain"
    return "recover"


def route_after_recover(state: IncidentState) -> str:
    """Post-restore alarm loop per §11.3 row 5 (RC.RP-01).

    Returns:
        "contain"          — post-restore alarms fired → re-contain.
        "lessons_learned"  — clean restore → proceed.
    """
    if state.get("_post_restore_alarms", False) is True:
        return "contain"
    return "lessons_learned"


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
