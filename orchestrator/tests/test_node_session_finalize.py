"""session_finalize node tests — §11.4 deliverables (T15).

Verifies that session_finalize emits the two final §11.4 deliverables:
- compliance_map.json (CSF 2.0 subcategories + ISO 27035 + PICERL phase)
- incident_summary.md (investigator-readable narrative)

Pre-existing wrap-up duties (state.json, history, audit, agent_messages) are
covered transitively by tests/test_graph_smoke.py — this file focuses on the
two new deliverables and their contents.
"""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import session_finalize
from mh_orchestrator.state import new_state


def test_finalize_writes_compliance_map(tmp_path: Path) -> None:
    s = new_state("case-FIN-001")
    s["_output_dir"] = str(tmp_path)
    s["csf_subcategories_satisfied"] = {"DE.AE-02", "RS.MA-01"}
    s["iso27035_phase"] = "learn_lessons"
    s["attack_techniques"] = ["T1059"]
    s["kill_chain_stage"] = 5

    session_finalize.run(s)

    cm_path = tmp_path / "compliance_map.json"
    assert cm_path.exists(), "compliance_map.json should be emitted"
    cm = json.loads(cm_path.read_text())

    # Top-level keys per §11.4 / sub-plan brief
    expected_keys = {
        "case_id",
        "csf_subcategories_satisfied",
        "iso27035_phase",
        "phase",
        "picerl_phase",
        "attack_techniques",
        "kill_chain_stage",
        "frameworks",
    }
    assert expected_keys <= set(cm.keys()), f"missing keys: {expected_keys - set(cm.keys())}"

    # case_id mirrors incident_id
    assert cm["case_id"] == "case-FIN-001"

    # csf list is sorted
    assert cm["csf_subcategories_satisfied"] == ["DE.AE-02", "RS.MA-01"]

    # attack_techniques is a sorted list
    assert cm["attack_techniques"] == ["T1059"]

    # kill_chain_stage propagated
    assert cm["kill_chain_stage"] == 5

    # iso27035_phase propagated
    assert cm["iso27035_phase"] == "learn_lessons"

    # frameworks block has expected version pins
    fw = cm["frameworks"]
    assert fw["nist_csf_version"] == "2.0"
    assert fw["nist_sp_800_61"].startswith("Rev. 3")
    assert fw["iso_27035"] == "27035-1:2023"
    assert fw["mitre_attck"] == "v18"
    assert "stub" in fw["mitre_d3fend"].lower()
    assert fw["lockheed_kill_chain"] == "7-stage"
    assert fw["sans_picerl"] == "6-phase"


def test_finalize_compliance_map_picerl_phase_for_finalize(tmp_path: Path) -> None:
    """session_finalize maps to PICERL 'lessons_learned' (per picerl.NODE_TO_PICERL)."""
    s = new_state("case-FIN-002")
    s["_output_dir"] = str(tmp_path)
    # session_finalize.run sets phase='lessons' before recording picerl_phase
    session_finalize.run(s)

    cm = json.loads((tmp_path / "compliance_map.json").read_text())
    assert cm["picerl_phase"] == "lessons_learned"
    assert cm["phase"] == "lessons"


def test_finalize_compliance_map_sorted_lists(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    # Intentionally unsorted
    s["csf_subcategories_satisfied"] = {"RS.MA-01", "DE.AE-02", "GV.OV-01"}
    s["attack_techniques"] = ["T1486", "T1059", "T1003"]

    session_finalize.run(s)
    cm = json.loads((tmp_path / "compliance_map.json").read_text())

    assert cm["csf_subcategories_satisfied"] == sorted(cm["csf_subcategories_satisfied"])
    assert cm["attack_techniques"] == sorted(cm["attack_techniques"])


def test_finalize_writes_incident_summary(tmp_path: Path) -> None:
    s = new_state("case-FIN-003")
    s["_output_dir"] = str(tmp_path)
    s["severity"] = "high"
    s["_detected_os"] = "linux"
    s["attack_techniques"] = ["T1059"]
    s["kill_chain_stage"] = 4
    s["csf_subcategories_satisfied"] = {"DE.AE-02", "RS.MA-01"}
    s["iso27035_phase"] = "learn_lessons"

    session_finalize.run(s)

    md_path = tmp_path / "incident_summary.md"
    assert md_path.exists(), "incident_summary.md should be emitted"
    md = md_path.read_text()

    # case_id appears in the heading
    assert "case-FIN-003" in md
    # ATT&CK header and technique are reflected
    assert "ATT&CK Techniques" in md
    assert "T1059" in md
    # Severity + OS surfaced
    assert "high" in md
    assert "linux" in md
    # CSF subcategories surfaced
    assert "DE.AE-02" in md
    assert "RS.MA-01" in md
    # §11.4 deliverables section heading present
    assert "Deliverables Emitted Per §11.4" in md
    # Advisory disclaimer present
    assert "advisory" in md.lower()


def test_finalize_summary_handles_empty_collections(tmp_path: Path) -> None:
    """Default new_state has no findings/techniques — summary must still render."""
    s = new_state("case-FIN-004")
    s["_output_dir"] = str(tmp_path)

    session_finalize.run(s)
    md = (tmp_path / "incident_summary.md").read_text()

    # case_id heading
    assert "case-FIN-004" in md
    # Empty technique list rendered as "(none)"
    assert "(none)" in md
    # Verifier-not-run fallback
    assert "False" in md  # _verifier_complete defaults False


def test_finalize_summary_reflects_verifier_decisions(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "F-1"},
        {"finding_id": "F-2"},
        {"finding_id": "F-3"},
    ]
    s["_verifier_decisions"] = [
        {"finding_id": "F-1", "decision": "agree", "rationale": "", "verifier_iter": 1},
        {"finding_id": "F-2", "decision": "dissent", "rationale": "", "verifier_iter": 2},
        {"finding_id": "F-3", "decision": "revise", "rationale": "", "verifier_iter": 3},
    ]

    session_finalize.run(s)
    md = (tmp_path / "incident_summary.md").read_text()

    # 3 findings, 1 agree / 1 dissent / 1 revise — all should appear in the
    # Findings line.
    findings_line = next(line for line in md.splitlines() if "Findings" in line)
    assert "3" in findings_line
    assert "1 verifier-agreed" in findings_line or "verifier-agreed" in findings_line
    assert "dissent" in findings_line
    assert "revise" in findings_line


def test_finalize_summary_lists_recommendation_counts(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["containment_actions"] = [{"id": 1}, {"id": 2}]
    s["eradication_actions"] = [{"id": 1}]
    s["recovery_actions"] = [{"id": 1}, {"id": 2}, {"id": 3}]
    s["remediation_plan"] = [{"control_id": "AC-2"}]

    session_finalize.run(s)
    md = (tmp_path / "incident_summary.md").read_text()

    # Counts surface
    assert "Containment actions: 2" in md
    assert "Eradication actions: 1" in md
    assert "Recovery actions: 3" in md
    assert "Remediation controls: 1" in md


def test_finalize_audit_records_new_writes(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)

    session_finalize.run(s)

    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    events = {json.loads(line)["event"] for line in audit_path.read_text().splitlines()}
    assert "compliance_map_written" in events
    assert "incident_summary_written" in events
    # Pre-existing event still emitted
    assert "session_complete" in events


def test_finalize_still_writes_state_and_history(tmp_path: Path) -> None:
    """Pre-existing wrap-up duties remain intact alongside new deliverables."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)

    session_finalize.run(s)

    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
    assert (tmp_path / "audit.jsonl").exists()
    assert (tmp_path / "agent_messages.jsonl").exists()
    assert (tmp_path / "compliance_map.json").exists()
    assert (tmp_path / "incident_summary.md").exists()


def test_incident_summary_discloses_analyze_timeout(tmp_path):
    """A run where analyze hit a liveness timeout must disclose it in the
    Acknowledged Gaps section of incident_summary.md."""
    from mh_orchestrator.nodes import session_finalize
    from mh_orchestrator.state import new_state

    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_analyze_timed_out"] = True
    session_finalize.run(s)

    summary = (tmp_path / "incident_summary.md").read_text()
    assert "## Acknowledged Gaps" in summary
    assert "timeout" in summary.lower()
    assert "analyze" in summary.lower()
