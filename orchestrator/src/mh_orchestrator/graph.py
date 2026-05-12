"""LangGraph StateGraph for MemoryHound.

Full §11.2 14-IR-node topology plus chain-of-custody anchor and cross-finding
correlator, with six conditional edges (the original five §11.3 gates plus
the verifier dissent edge):
  manifest_ingest → session_init → detect → triage
  triage --[route_after_triage]--> {suppress | declare_incident}
  declare_incident → analyze
  analyze --[route_after_analyze]--> {analyze | attack_tag}
  attack_tag → kill_chain → d3fend_recommend → contain
  contain --[route_after_contain]--> {human_in_loop | eradicate}
  human_in_loop → eradicate
  eradicate --[route_after_eradicate]--> {contain | recover}
  recover --[route_after_recover]--> {contain | lessons_learned}
  lessons_learned → remediation → verifier_pass
  verifier_pass --[route_after_verifier_pass]--> {analyze | correlate}
  correlate → session_finalize
  suppress → session_finalize → END

verifier_pass placement: locked Sub-Plan 03 decision is "single global
Verifier pass after analyze loop terminates" — meaning AFTER all phases
complete, between remediation and session_finalize. This supersedes any
contrary §11.2 prose. The dissent-driven re-route to analyze is capped at
one revision pass via `_verifier_revision_count` (verifier_pass owns the
cap); without the cap LangGraph would otherwise loop on stubborn dissent.

The `route_after_*` functions are pure conditional-edge selectors per §11.3.
"""
from __future__ import annotations

import os
from typing import Any

from langgraph.graph import END, StateGraph

from . import blast_radius
from .nodes import NODES
from .state import IncidentState

# Default recursion limit: 50 leaves headroom above the 15-node happy path
# so bounded loop-back retries (eradicate→contain, recover→contain) don't
# trip LangGraph's safety guard on first iteration. Override per-invocation
# via build_graph(recursion_limit=N) or env MH_LG_RECURSION_LIMIT.
DEFAULT_RECURSION_LIMIT = 50

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


def route_after_verifier_pass(state: IncidentState) -> str:
    """Dissent-driven self-correction edge.

    The Verifier sets `_verifier_complete=True` only when it agreed with
    every finding (or a previous revision pass already exhausted the cap).
    If `_verifier_complete` is False, dissent is unresolved and one
    revision pass is allowed by routing back through analyze. The cap on
    `_verifier_revision_count` (set inside verifier_pass) prevents loops.

    Returns:
        "correlate"        — verifier_complete (no dissent or cap reached).
                              correlate runs the cross-finding contradiction +
                              gap detector before the reporter renders.
        "analyze"          — dissent + revision available → re-run analyze.
    """
    if state.get("_verifier_complete", False) is True:
        return "correlate"
    return "analyze"


def _resolve_recursion_limit(arg: int | None) -> int:
    """Resolve recursion limit: explicit arg > MH_LG_RECURSION_LIMIT > default.

    Env var lets ops bump the cap without code changes if a particularly
    pathological case keeps hitting bounded retries.
    """
    if arg is not None:
        return arg
    env = os.environ.get("MH_LG_RECURSION_LIMIT")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    return DEFAULT_RECURSION_LIMIT


def build_graph(recursion_limit: int | None = None) -> Any:
    """Compile the full §11.2 graph and bind recursion_limit at invoke-time
    via .with_config.

    The recursion_limit caps total node iterations as required by the
    hackathon multi-agent submission rules. With bounded loop-back retries
    (eradicate→contain, recover→contain) and the analyze RCA loop, default
    50 gives ~3x headroom over the 15-node happy path.
    """
    limit = _resolve_recursion_limit(recursion_limit)
    g: StateGraph = StateGraph(IncidentState)

    for name, fn in NODES.items():
        g.add_node(name, fn)

    g.set_entry_point("manifest_ingest")

    # manifest_ingest is the chain-of-custody anchor — it walks the input
    # tree once at the very start, writes output/manifest.json with sha256
    # per artifact, and records a manifest_complete audit event. From there
    # the rest of the §11.2 pipeline runs unchanged.
    g.add_edge("manifest_ingest", "session_init")

    # Linear edges (deterministic single successor per §11.2)
    g.add_edge("session_init", "detect")
    g.add_edge("detect", "triage")
    # scope sits between triage's non-suppress branch and declare_incident.
    # Pure-Python extractor — populates affected_hosts / users / services /
    # data so the contain/eradicate stack has structured targets to act on.
    g.add_edge("scope", "declare_incident")
    g.add_edge("declare_incident", "analyze")
    g.add_edge("attack_tag", "kill_chain")
    g.add_edge("kill_chain", "d3fend_recommend")
    g.add_edge("d3fend_recommend", "contain")
    g.add_edge("human_in_loop", "eradicate")
    g.add_edge("lessons_learned", "remediation")
    g.add_edge("remediation", "verifier_pass")
    # correlate sits between verifier_pass's "session_finalize" branch and
    # session_finalize itself — cross-finding contradiction + gap detector.
    g.add_edge("correlate", "session_finalize")
    g.add_edge("suppress", "session_finalize")
    g.add_edge("session_finalize", END)

    # §11.3 conditional edges — five gates that govern branch + loop control.
    g.add_conditional_edges(
        "triage", route_after_triage,
        # The "declare_incident" branch routes through scope first; suppress
        # remains a direct exit since false positives don't need scoping.
        {"suppress": "suppress", "declare_incident": "scope"},
    )
    g.add_conditional_edges(
        "analyze", route_after_analyze,
        {"analyze": "analyze", "attack_tag": "attack_tag"},
    )
    g.add_conditional_edges(
        "contain", route_after_contain,
        {"human_in_loop": "human_in_loop", "eradicate": "eradicate"},
    )
    g.add_conditional_edges(
        "eradicate", route_after_eradicate,
        {"contain": "contain", "recover": "recover"},
    )
    g.add_conditional_edges(
        "recover", route_after_recover,
        {"contain": "contain", "lessons_learned": "lessons_learned"},
    )
    # Verifier dissent → route back through analyze (capped at one revision
    # by `_verifier_revision_count`; verifier_pass owns the cap logic).
    # When verifier passes, we go through correlate first to surface
    # cross-finding contradictions/gaps before the reporter renders.
    g.add_conditional_edges(
        "verifier_pass", route_after_verifier_pass,
        {"analyze": "analyze", "correlate": "correlate"},
    )

    compiled = g.compile()
    return compiled.with_config({"recursion_limit": limit})
