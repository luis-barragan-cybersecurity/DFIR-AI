"""remediation node tests — NIST SP 800-53 IR-family controls."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import remediation
from mh_orchestrator.state import new_state


def test_remediation_emits_at_least_six_controls(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = remediation.run(s)
    assert len(s["remediation_plan"]) >= 6
    assert s["phase"] == "remediation"


def test_remediation_majority_ir_family(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    remediation.run(s)
    ir_count = sum(1 for c in s["remediation_plan"] if c["family"] == "IR")
    assert ir_count >= 4


def test_remediation_each_control_has_priority_and_id(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    remediation.run(s)
    for control in s["remediation_plan"]:
        assert control["control_id"]
        assert control["priority"] in {"high", "medium", "low"}
        assert control["family"] in {"IR", "SI", "SC"}
        assert control["advisory_only"] is True
        assert isinstance(control["action"], str) and control["action"]


def test_remediation_writes_plan_json(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["incident_id"] = "case-rem-001"
    remediation.run(s)
    plan_path = tmp_path / "remediation_plan.json"
    assert plan_path.exists()
    payload = json.loads(plan_path.read_text())
    assert payload["case_id"] == "case-rem-001"
    assert payload["advisory_only"] is True
    assert len(payload["controls"]) >= 6


def test_remediation_includes_attack_techniques_in_action(tmp_path: Path) -> None:
    """IR-5 (Incident Monitoring) action should reference observed techniques."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1059", "T1486"]
    remediation.run(s)
    ir5 = next(c for c in s["remediation_plan"] if c["control_id"] == "IR-5")
    assert "T1059" in ir5["action"] or "T1486" in ir5["action"]


def test_remediation_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    remediation.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
