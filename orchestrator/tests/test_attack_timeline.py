"""Tests for the deterministic Mermaid attack-timeline renderer."""
from __future__ import annotations

from mh_orchestrator import attack_timeline as at


def test_tactic_for_known_technique() -> None:
    assert at.tactic_for("T1059.001") == "Execution"
    assert at.tactic_for("T1547.001") == "Persistence"
    assert at.tactic_for("T1071.001") == "Command & Control"
    assert at.tactic_for("T1486") == "Impact"


def test_tactic_for_falls_back_to_parent() -> None:
    """Unknown sub-technique should resolve via its parent T-id."""
    # T1059.999 doesn't exist but T1059 (Execution parent) does
    assert at.tactic_for("T1059.999") == "Execution"


def test_tactic_for_unknown_returns_none() -> None:
    assert at.tactic_for("T9999.999") is None


def test_order_techniques_follows_kill_chain() -> None:
    """Mixed techniques should be reordered by Lockheed kill-chain phase."""
    out = at.order_techniques([
        "T1071.001",   # C&C — should come 4th
        "T1547.001",   # Persistence — should come 3rd
        "T1059.001",   # Execution — should come 2nd
        "T1078",       # Initial Access — should come 1st
    ])
    tactics = [e["tactic"] for e in out]
    assert tactics == [
        "Initial Access", "Execution", "Persistence", "Command & Control",
    ]


def test_order_techniques_unknown_lands_in_unmapped() -> None:
    out = at.order_techniques(["T1059.001", "T9999.999"])
    assert out[-1]["tactic"] == "Unmapped"
    assert out[-1]["technique_id"] == "T9999.999"


def test_render_mermaid_empty_list() -> None:
    out = at.render_mermaid([])
    assert "```mermaid" in out
    assert "No ATT&amp;CK techniques observed" in out
    assert out.endswith("```\n")


def test_render_mermaid_includes_flowchart_header() -> None:
    out = at.render_mermaid(["T1078", "T1059.001"])
    assert out.startswith("```mermaid\n")
    assert "flowchart LR" in out
    assert out.rstrip().endswith("```")


def test_render_mermaid_node_count_matches_techniques() -> None:
    out = at.render_mermaid(["T1078", "T1059.001", "T1547.001"])
    # Expect exactly 3 N-prefixed node declarations
    node_lines = [
        line for line in out.splitlines()
        if line.strip().startswith("N") and '["' in line
    ]
    assert len(node_lines) == 3


def test_render_mermaid_emits_arrows_between_nodes() -> None:
    out = at.render_mermaid(["T1078", "T1059.001", "T1547.001"])
    arrows = [line for line in out.splitlines() if "-->" in line]
    assert len(arrows) == 2  # 3 nodes → 2 arrows


def test_render_mermaid_preserves_kill_chain_order() -> None:
    """Even if input is unordered, output should be in tactic order."""
    out = at.render_mermaid([
        "T1486",       # Impact
        "T1078",       # Initial Access
        "T1071.001",   # C&C
    ])
    # First node label should be Initial Access, last should be Impact.
    lines = out.splitlines()
    initial_idx = next(i for i, l in enumerate(lines) if "Initial Access" in l)
    impact_idx = next(i for i, l in enumerate(lines) if "Impact<br/>" in l)
    assert initial_idx < impact_idx
