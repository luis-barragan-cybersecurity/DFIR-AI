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


def test_extract_time_anchors_pulls_iso_stamps_from_claims() -> None:
    findings = [
        {
            "finding_id": "F-005",
            "claim": (
                "msedge.exe burst at 2020-11-14T04:12:49Z by parent PID 22700, "
                "30 children all exiting at 2020-11-14T04:59:17Z."
            ),
        },
        {
            "finding_id": "F-007",
            "claim": "interactive marker fires at 2020-11-14T03:42:50Z (= 22:42 EST)",
        },
    ]
    anchors = at.extract_time_anchors(findings)
    timestamps = [a[0] for a in anchors]
    # Sorted ascending
    assert timestamps == sorted(timestamps)
    # All three stamps captured
    assert "2020-11-14T03:42:50Z" in timestamps
    assert "2020-11-14T04:12:49Z" in timestamps
    assert "2020-11-14T04:59:17Z" in timestamps


def test_extract_time_anchors_handles_no_stamps() -> None:
    anchors = at.extract_time_anchors([
        {"finding_id": "F-X", "claim": "no timestamps in this claim"},
    ])
    assert anchors == []


def test_render_gantt_includes_required_headers() -> None:
    anchors = [
        ("2020-11-14T03:42:50Z", "interactive session", "F-007"),
        ("2020-11-14T04:12:49Z", "msedge burst", "F-005"),
    ]
    out = at.render_gantt(anchors, title="Test Timeline")
    assert "```mermaid" in out
    assert "gantt" in out
    assert "title Test Timeline" in out
    assert "dateFormat YYYY-MM-DDTHH:mm:ssZ" in out
    assert "section Events" in out
    # Both anchors rendered
    assert "F-007" in out
    assert "F-005" in out
    assert "2020-11-14T03:42:50Z" in out
    assert "2020-11-14T04:12:49Z" in out


def test_render_gantt_empty_anchors_renders_placeholder() -> None:
    out = at.render_gantt([], title="Empty")
    assert "```mermaid" in out
    assert "No timestamped events found" in out


def test_render_gantt_escapes_colons_in_labels() -> None:
    """Mermaid uses `:` as a syntax separator; colons in labels must be
    rewritten or the gantt parser breaks.
    """
    anchors = [("2020-11-14T03:42:50Z", "src:port 192.168.1.5:3389", "F-X")]
    out = at.render_gantt(anchors)
    # The label colons should not appear before the section's task syntax.
    label_line = next(l for l in out.splitlines() if "F-X" in l)
    # First `:` in the line is the gantt task separator; before that there
    # should be no raw colon from the label.
    pre_sep = label_line.split(":", 1)[0]
    assert ":" not in pre_sep


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
