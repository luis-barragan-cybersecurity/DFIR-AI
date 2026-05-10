"""Graph smoke test — full §11.2 14-IR-node topology.

Walks the complete graph under MH_NO_CLAUDE=1 and asserts the canonical
non-loop happy-path order plus §11.4 output artifacts.
"""
from __future__ import annotations

import json

import pytest

# Canonical non-loop happy path under MH_NO_CLAUDE=1:
# - triage emits severity='medium' → declare_incident (not suppress)
# - analyze stub sets _rca_complete=True after one pass → attack_tag
# - contain emits max blast 50 (≤ default threshold 50) → eradicate
# - eradicate sets _reinfection_detected=False → recover
# - recover sets _post_restore_alarms=False → lessons_learned
EXPECTED_ORDER = [
    "session_init",
    "detect",
    "triage",
    "declare_incident",
    "analyze",
    "attack_tag",
    "kill_chain",
    "d3fend_recommend",
    "contain",
    "eradicate",
    "recover",
    "lessons_learned",
    "remediation",
    "verifier_pass",
    "session_finalize",
]


def test_graph_walks_full_ir_topology(tmp_path, monkeypatch):
    """Compile the full §11.2 graph, invoke under MH_NO_CLAUDE=1, and verify
    the canonical happy-path traversal hits every IR node exactly once."""
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    from mh_orchestrator.graph import build_graph
    from mh_orchestrator.state import new_state

    s = new_state("case-001")
    s["_output_dir"] = str(tmp_path)
    graph = build_graph(recursion_limit=50)
    final = graph.invoke(s)

    assert final["_node_history"] == EXPECTED_ORDER
    # phase: session_finalize sets it to "lessons" last
    assert final["phase"] == "lessons"
    # global verifier pass ran
    assert final["_verifier_complete"] is True

    # §11.4 outputs that this graph walk should produce
    state_json_path = tmp_path / "state.json"
    history_path = tmp_path / "state.history.jsonl"
    audit_path = tmp_path / "audit.jsonl"
    messages_path = tmp_path / "agent_messages.jsonl"
    contain_path = tmp_path / "containment_actions.jsonl"
    recovery_path = tmp_path / "recovery_verification.json"
    lessons_path = tmp_path / "lessons_learned.md"
    remediation_path = tmp_path / "remediation_plan.json"

    for p in (
        state_json_path, history_path, audit_path, messages_path,
        contain_path, recovery_path, lessons_path, remediation_path,
    ):
        assert p.exists(), f"missing §11.4 output: {p.name}"

    # state.json content sanity
    state_json = json.loads(state_json_path.read_text())
    assert state_json["incident_id"] == "case-001"
    assert state_json["_verifier_complete"] is True
    assert state_json["_node_history"] == EXPECTED_ORDER

    # audit.jsonl carries lifecycle events from each phase
    audit_lines = audit_path.read_text().strip().splitlines()
    audit_events = {json.loads(line)["event"] for line in audit_lines}
    expected_events = {
        "session_started",
        "detect_complete",
        "triage_complete_stub",
        "incident_declared",
        "analyze_complete",
        "attack_tag_complete",
        "kill_chain_complete",
        "d3fend_recommend_complete",
        "contain_complete",
        "eradicate_complete",
        "recover_complete",
        "lessons_learned_complete",
        "remediation_complete",
        "verifier_pass_summary",
        "session_complete",
    }
    missing = expected_events - audit_events
    assert not missing, f"missing audit events: {missing}"


def test_graph_suppresses_low_severity_no_findings(tmp_path, monkeypatch):
    """Severity gate (§11.3 row 1): when triage yields low+no findings, the
    graph short-circuits to suppress → session_finalize and skips the rest of
    the IR pipeline. This validates the route_after_triage conditional edge
    is wired into the compiled graph (not just unit-tested as a pure func).
    """
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    # Make triage stub emit "low" + force _findings=[] post-triage.
    # Simplest deterministic path: monkeypatch triage.run to set severity=low.
    from mh_orchestrator.nodes import triage as triage_mod

    original_run = triage_mod.run

    def low_severity_run(state):
        s = original_run(state)
        s["severity"] = "low"
        s["_findings"] = []
        return s

    monkeypatch.setattr(triage_mod, "run", low_severity_run)
    # Re-bind NODES entry too — registry holds a direct reference.
    from mh_orchestrator.nodes import NODES
    monkeypatch.setitem(NODES, "triage", low_severity_run)

    from mh_orchestrator.graph import build_graph
    from mh_orchestrator.state import new_state

    s = new_state("case-suppress")
    s["_output_dir"] = str(tmp_path)
    graph = build_graph(recursion_limit=50)
    final = graph.invoke(s)

    assert final["_node_history"] == [
        "session_init", "detect", "triage", "suppress", "session_finalize",
    ]
    # suppress + session_finalize both leave phase='lessons'
    assert final["phase"] == "lessons"
    # No verifier ran on the suppressed branch
    assert final["_verifier_complete"] is False


def test_recursion_limit_fires(tmp_path, monkeypatch):
    """A self-loop node compiled with recursion_limit=2 must raise GraphRecursionError."""
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    from langgraph.errors import GraphRecursionError
    from langgraph.graph import StateGraph

    from mh_orchestrator.state import IncidentState, new_state

    def loop_node(state):
        state["_node_history"].append("loop")
        return state

    g = StateGraph(IncidentState)
    g.add_node("loop", loop_node)
    g.set_entry_point("loop")
    g.add_edge("loop", "loop")  # infinite
    compiled = g.compile()

    s = new_state("case-x")
    s["_output_dir"] = str(tmp_path)
    with pytest.raises(GraphRecursionError):
        compiled.invoke(s, config={"recursion_limit": 2})


def test_build_graph_default_recursion_limit_is_50(monkeypatch):
    """Default recursion limit bumped 25→50 for full §11.2 walk plus
    bounded loop-back retries (§11.3 rows 4–5)."""
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    from mh_orchestrator.graph import DEFAULT_RECURSION_LIMIT
    assert DEFAULT_RECURSION_LIMIT >= 50
