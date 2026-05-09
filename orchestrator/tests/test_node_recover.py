"""recover node tests — Restore-tactic recommendations + verification stub."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import recover
from mh_orchestrator.state import new_state


def test_recover_emits_three_recommendations(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = recover.run(s)
    assert len(s["recovery_actions"]) == 3
    assert s["phase"] == "recover"
    assert "RC.RP-01" in s["csf_subcategories_satisfied"]
    assert "RC.CO-03" in s["csf_subcategories_satisfied"]
    assert "recover" in s["_node_history"]


def test_recover_recommendations_are_advisory_only(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    recover.run(s)
    for rec in s["recovery_actions"]:
        assert rec["advisory_only"] is True
        assert rec["tactic"] == "restore"
        assert rec["id"].startswith("RECOVER-")
        assert isinstance(rec["action"], str) and rec["action"]


def test_recover_writes_verification_json(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["incident_id"] = "case-recover-001"
    recover.run(s)
    verify_path = tmp_path / "recovery_verification.json"
    assert verify_path.exists()
    payload = json.loads(verify_path.read_text())
    assert payload["case_id"] == "case-recover-001"
    assert payload["advisory_only"] is True
    assert len(payload["verification_steps"]) == 3
    for step in payload["verification_steps"]:
        assert step["status"] == "pending"
        assert step["id"].startswith("VERIFY-")
        assert isinstance(step["check"], str) and step["check"]


def test_recover_sets_post_restore_alarms_false(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = recover.run(s)
    assert s["_post_restore_alarms"] is False


def test_recover_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    recover.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
