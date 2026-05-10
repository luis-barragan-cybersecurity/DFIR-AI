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
            "finding_id": "F-005-browser-burst-msedge",
            "claim": (
                "msedge.exe burst at 2020-11-14T04:12:49Z by parent PID 22700, "
                "30 children all exiting at 2020-11-14T04:59:17Z."
            ),
        },
        {
            "finding_id": "F-007-interactive-logon-marker",
            "claim": "interactive marker fires at 2020-11-14T03:42:50Z (= 22:42 EST)",
        },
    ]
    anchors = at.extract_time_anchors(findings)
    starts = [a[0] for a in anchors]
    # Sorted ascending
    assert starts == sorted(starts)
    # F-005 should carry both start AND end (it had two stamps in claim)
    f5 = next(a for a in anchors if "F-005" in a[2])
    assert f5[0] == "2020-11-14T04:12:49Z"
    assert f5[1] == "2020-11-14T04:59:17Z"
    # F-007 should carry only start (single stamp)
    f7 = next(a for a in anchors if "F-007" in a[2])
    assert f7[0] == "2020-11-14T03:42:50Z"
    assert f7[1] == ""
    # Both anchors carry a section
    assert all(a[3] for a in anchors)


def test_extract_time_anchors_handles_no_stamps() -> None:
    anchors = at.extract_time_anchors([
        {"finding_id": "F-X-no-time", "claim": "no timestamps in this claim"},
    ])
    assert anchors == []


def test_humanize_finding_id() -> None:
    assert at.humanize_finding_id("F-007-interactive-logon-marker") == "Interactive logon marker"
    # Known acronyms preserved in uppercase
    assert at.humanize_finding_id("F-016-rdp-listener-since-boot") == "RDP listener since boot"
    assert at.humanize_finding_id("F-005-browser-burst-msedge") == "Browser burst msedge"
    assert at.humanize_finding_id("F-013-mrc-ir-tool-from-d-drive") == "MRC IR tool from d drive"
    assert at.humanize_finding_id("F-012-device-picker-2358-est") == "Device picker 2358 EST"
    # Non-conforming IDs return as-is
    assert at.humanize_finding_id("legacy") == "legacy"
    assert at.humanize_finding_id("") == "(unnamed)"


def test_section_for_finding_buckets() -> None:
    assert at.section_for_finding("F-016-rdp-listener-since-boot") == "RDP exposure"
    assert at.section_for_finding("F-007-interactive-logon-marker") == "Intrusion"
    assert at.section_for_finding("F-005-browser-burst-msedge") == "Intrusion"
    assert at.section_for_finding("F-008-srl-projects-via-onedrive") == "Exfiltration surface"
    assert at.section_for_finding("F-002-capture-time") == "Acquisition"
    assert at.section_for_finding("F-014-gap-no-registry-plugins") == "Gaps"
    assert at.section_for_finding("F-999-unknown-thing") == "Other"


def test_render_gantt_includes_required_headers() -> None:
    anchors = [
        ("2020-11-14T03:42:50Z", "", "F-007-interactive-logon-marker", "Intrusion"),
        ("2020-11-14T04:12:49Z", "", "F-005-browser-burst-msedge", "Intrusion"),
    ]
    out = at.render_gantt(anchors, title="Test Timeline")
    assert "```mermaid" in out
    assert "gantt" in out
    assert "title Test Timeline" in out
    assert "dateFormat YYYY-MM-DDTHH:mm:ssZ" in out
    assert "section Intrusion" in out
    # Humanized labels rendered, not surrounding-text fragments
    assert "Interactive logon marker" in out
    assert "Browser burst msedge" in out


def test_render_gantt_uses_end_when_present() -> None:
    """A finding with start AND end timestamps should render as a duration
    bar (start, end), not a 1-minute task."""
    anchors = [
        ("2020-11-14T04:12:49Z", "2020-11-14T04:59:17Z",
         "F-005-browser-burst-msedge", "Intrusion"),
    ]
    out = at.render_gantt(anchors)
    line = next(l for l in out.splitlines() if "F-005" in l)
    assert "2020-11-14T04:12:49Z" in line
    assert "2020-11-14T04:59:17Z" in line
    assert "1m" not in line  # not the 1-minute fallback


def test_render_gantt_empty_anchors_renders_placeholder() -> None:
    out = at.render_gantt([], title="Empty")
    assert "```mermaid" in out
    assert "No timestamped events found" in out


def test_render_gantt_groups_by_section() -> None:
    """Anchors from different sections should appear under their own
    `section <Name>` header, in stable phase order."""
    anchors = [
        ("2020-11-14T04:00:00Z", "", "F-005-browser-burst-msedge", "Intrusion"),
        ("2020-11-11T08:00:00Z", "", "F-016-rdp-listener-since-boot", "RDP exposure"),
        ("2020-11-16T02:36:00Z", "", "F-002-capture-time", "Acquisition"),
    ]
    out = at.render_gantt(anchors)
    rdp_idx = out.index("section RDP exposure")
    intr_idx = out.index("section Intrusion")
    acq_idx = out.index("section Acquisition")
    # Phase order is Pre-incident → RDP exposure → Intrusion → Exfil → Acquisition
    assert rdp_idx < intr_idx < acq_idx


def test_render_gantt_escapes_colons_in_labels() -> None:
    """Mermaid uses `:` as a syntax separator; colons in labels must be
    rewritten or the gantt parser breaks. With humanized finding IDs we
    won't naturally see colons, but defend in depth.
    """
    # Force a finding_id whose humanized form contains a colon.
    anchors = [
        ("2020-11-14T03:42:50Z", "", "F-100-time:warp", "Other"),
    ]
    out = at.render_gantt(anchors)
    label_line = next(l for l in out.splitlines() if "F-100" in l)
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
