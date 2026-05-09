"""Graph smoke test — compiles, executes 3 nodes, mutates state, persists logs."""
from __future__ import annotations

import json

import pytest


def test_graph_compiles_and_runs_three_nodes(tmp_path, monkeypatch):
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    from mh_orchestrator.graph import build_graph
    from mh_orchestrator.state import new_state

    s = new_state("case-001")
    s["_output_dir"] = str(tmp_path)
    graph = build_graph(recursion_limit=10)
    final = graph.invoke(s)

    assert final["_node_history"] == ["session_init", "claude_dispatch", "session_finalize"]
    assert final["phase"] == "lessons"

    state_json = json.loads((tmp_path / "state.json").read_text())
    assert state_json["incident_id"] == "case-001"

    msgs = (tmp_path / "agent_messages.jsonl").read_text().strip().splitlines()
    assert len(msgs) >= 4   # init + dispatch + response + finalize
    parsed = [json.loads(m) for m in msgs]
    assert any(p["from_agent"] == "orchestrator" and p["to_agent"] == "WindowsAgent"
               for p in parsed)

    audit_lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert any("session_started" in line for line in audit_lines)
    assert any("session_complete" in line for line in audit_lines)


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
