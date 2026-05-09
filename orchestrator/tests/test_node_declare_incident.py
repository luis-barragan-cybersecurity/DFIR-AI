"""declare_incident node tests."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import declare_incident
from mh_orchestrator.state import new_state


def test_declare_incident_sets_iso_phase_and_csf(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["severity"] = "high"
    s = declare_incident.run(s)
    assert s["iso27035_phase"] == "assessment_and_decision"
    assert "RS.MA-01" in s["csf_subcategories_satisfied"]
    assert "declare_incident" in s["_node_history"]
