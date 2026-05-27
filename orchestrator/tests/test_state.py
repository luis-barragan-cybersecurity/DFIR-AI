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
        "attack_techniques", "forensic_artifacts",
        "csf_subcategories_satisfied", "iso27035_phase",
        "d3fend_recommendations", "remediation_plan",
    }
    assert required.issubset(set(s.keys()))


def test_new_state_defaults() -> None:
    s = new_state("case-001")
    assert s["incident_id"] == "case-001"
    assert s["severity"] == "low"
    assert s["phase"] == "detect"
    assert s["kill_chain_stage"] == 0
    assert s["attack_techniques"] == []
    assert s["csf_subcategories_satisfied"] == set()


def test_state_roundtrip_serializes_techniques_and_csf() -> None:
    s = new_state("case-001")
    s["attack_techniques"].append("T1003.001")
    s["csf_subcategories_satisfied"].add("RS.MA-03")
    blob = serialize_state(s)
    json.dumps(blob)  # must be JSON-serializable
    s2 = deserialize_state(blob)
    assert s2["attack_techniques"] == ["T1003.001"]
    assert s2["csf_subcategories_satisfied"] == {"RS.MA-03"}


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


def test_new_state_has_internal_control_flags() -> None:
    s = new_state("case-001")
    assert s["_detected_os"] == "unknown"
    assert s["_analyze_iter"] == 0
    assert s["_rca_complete"] is False
    assert s["_reinfection_detected"] is False
    assert s["_post_restore_alarms"] is False
    assert s["_verifier_complete"] is False
    assert s["_verifier_decisions"] == []
    assert s["_findings"] == []
    assert s["_max_blast_score"] == 0
    assert s["human_approval_required"] is False
    assert s["containment_actions"] == []
    assert s["eradication_actions"] == []
    assert s["recovery_actions"] == []
    assert s["remediation_plan"] == []


def test_state_roundtrip_preserves_internal_flags() -> None:
    s = new_state("case-001")
    s["_detected_os"] = "windows"
    s["_analyze_iter"] = 2
    s["_rca_complete"] = True
    s["_reinfection_detected"] = True
    s["_post_restore_alarms"] = True
    s["_verifier_complete"] = True
    s["_verifier_decisions"].append({
        "finding_id": "F-001", "decision": "agree",
        "rationale": "test", "verifier_iter": 1,
    })
    s["_findings"].append({"finding_id": "F-001", "claim": "test"})
    s["_max_blast_score"] = 42
    s["human_approval_required"] = True
    s["containment_actions"].append({"id": "CONTAIN-1", "advisory_only": True})
    s["eradication_actions"].append({"id": "ERADICATE-1", "advisory_only": True})
    s["recovery_actions"].append({"id": "RECOVER-1", "advisory_only": True})
    s["remediation_plan"].append({"control_id": "IR-4", "advisory_only": True})

    blob = serialize_state(s)
    import json
    json.dumps(blob)  # JSON-serializable
    s2 = deserialize_state(blob)

    assert s2["_detected_os"] == "windows"
    assert s2["_analyze_iter"] == 2
    assert s2["_rca_complete"] is True
    assert s2["_reinfection_detected"] is True
    assert s2["_post_restore_alarms"] is True
    assert s2["_verifier_complete"] is True
    assert s2["_verifier_decisions"] == [{
        "finding_id": "F-001", "decision": "agree",
        "rationale": "test", "verifier_iter": 1,
    }]
    assert s2["_findings"] == [{"finding_id": "F-001", "claim": "test"}]
    assert s2["_max_blast_score"] == 42
    assert s2["human_approval_required"] is True
    assert s2["containment_actions"] == [{"id": "CONTAIN-1", "advisory_only": True}]
    assert s2["eradication_actions"] == [{"id": "ERADICATE-1", "advisory_only": True}]
    assert s2["recovery_actions"] == [{"id": "RECOVER-1", "advisory_only": True}]
    assert s2["remediation_plan"] == [{"control_id": "IR-4", "advisory_only": True}]


def test_new_state_has_analyze_timed_out_false():
    from mh_orchestrator.state import deserialize_state, new_state, serialize_state
    s = new_state("c")
    assert s["_analyze_timed_out"] is False
    # round-trips through serialize/deserialize
    assert deserialize_state(serialize_state(s))["_analyze_timed_out"] is False
