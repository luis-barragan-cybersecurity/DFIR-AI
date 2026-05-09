"""IncidentState schema tests — mirrors IR_FRAMEWORKS_REFERENCE §11.1."""
from __future__ import annotations

import json

from mh_orchestrator.state import (
    deserialize_state,
    new_state,
    serialize_state,
)


def test_new_state_has_all_required_keys() -> None:
    s = new_state("case-001")
    required = {
        "incident_id", "severity", "phase", "kill_chain_stage",
        "attack_techniques", "diamond_graph", "iocs", "forensic_artifacts",
        "csf_subcategories_satisfied", "iso27035_phase",
        "d3fend_recommendations", "remediation_plan", "evidence_chain",
    }
    assert required.issubset(set(s.keys()))


def test_new_state_defaults() -> None:
    s = new_state("case-001")
    assert s["incident_id"] == "case-001"
    assert s["severity"] == "low"
    assert s["phase"] == "detect"
    assert s["kill_chain_stage"] == 0
    assert s["attack_techniques"] == []
    assert s["iocs"] == []
    assert s["csf_subcategories_satisfied"] == set()


def test_state_roundtrip_serializes_diamond_graph() -> None:
    s = new_state("case-001")
    s["attack_techniques"].append("T1003.001")
    s["csf_subcategories_satisfied"].add("RS.MA-03")
    s["diamond_graph"].add_node("attacker", role="adversary")
    s["diamond_graph"].add_node("8.8.8.8", role="infrastructure")
    s["diamond_graph"].add_edge("attacker", "8.8.8.8", relation="uses")
    blob = serialize_state(s)
    json.dumps(blob)  # must be JSON-serializable
    s2 = deserialize_state(blob)
    assert s2["attack_techniques"] == ["T1003.001"]
    assert s2["csf_subcategories_satisfied"] == {"RS.MA-03"}
    assert s2["diamond_graph"].has_edge("attacker", "8.8.8.8")


def test_write_checkpoint_creates_state_json_and_history(tmp_path):
    from mh_orchestrator.persistence import append_history, write_checkpoint
    s = new_state("case-001")
    s["_output_dir"] = str(tmp_path)
    s["phase"] = "triage"
    write_checkpoint(s, tmp_path)
    append_history(s, tmp_path, node="session_init")
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
    line = (tmp_path / "state.history.jsonl").read_text().strip()
    assert '"node":"session_init"' in line.replace(" ", "")
    assert '"phase":"triage"' in line.replace(" ", "")
