"""Diamond Model helpers tests."""
from __future__ import annotations

from mh_orchestrator import diamond
from mh_orchestrator.state import new_state


def test_add_vertex_records_role_attribute() -> None:
    s = new_state("c")
    diamond.add_vertex(s, role="adversary", value="GTG-1002")
    assert "GTG-1002" in s["diamond_graph"]
    assert s["diamond_graph"].nodes["GTG-1002"]["role"] == "adversary"


def test_add_relation_creates_bidirectional_edge() -> None:
    s = new_state("c")
    diamond.add_vertex(s, role="adversary", value="GTG-1002")
    diamond.add_vertex(s, role="infrastructure", value="8.8.8.8")
    diamond.add_relation(s, src="GTG-1002", dst="8.8.8.8", relation="uses")
    assert s["diamond_graph"].has_edge("GTG-1002", "8.8.8.8")
    assert s["diamond_graph"].has_edge("8.8.8.8", "GTG-1002")
    assert s["diamond_graph"]["GTG-1002"]["8.8.8.8"]["relation"] == "uses"


def test_pivot_candidates_returns_neighbours() -> None:
    s = new_state("c")
    diamond.add_vertex(s, role="adversary", value="A")
    diamond.add_vertex(s, role="capability", value="C1")
    diamond.add_vertex(s, role="capability", value="C2")
    diamond.add_vertex(s, role="infrastructure", value="I1")
    diamond.add_relation(s, src="A", dst="C1", relation="uses")
    diamond.add_relation(s, src="A", dst="I1", relation="operates")
    candidates = diamond.pivot_candidates(s, "A")
    assert set(candidates) == {"C1", "I1"}
