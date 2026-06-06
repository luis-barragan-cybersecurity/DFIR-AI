"""verifier_pass node tests — global Verifier pass after analyze loop.

Iterates state['_findings'], dispatches each to the Verifier subagent (stub
under MH_NO_CLAUDE=1), and records decisions on state['_verifier_decisions'].
Marks RS.AN-03 (Categorization: requires verification) per §11.4.
"""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import verifier_pass
from mh_orchestrator.state import new_state


def test_verifier_pass_with_empty_findings(tmp_path: Path) -> None:
    """Empty findings: synthetic 'no findings' audit, _verifier_complete=True, no decisions."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = verifier_pass.run(s)
    assert s["_verifier_complete"] is True
    assert s["_verifier_decisions"] == []
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    audit_lines = [json.loads(line) for line in audit_path.read_text().strip().splitlines()]
    has_no_findings = any(
        e["event"] == "verifier_pass_no_findings" for e in audit_lines
    )
    assert has_no_findings


def test_verifier_pass_with_two_stub_findings(tmp_path: Path) -> None:
    """Two stub findings → 2 decisions appended, both 'agree' under MH_NO_CLAUDE stub."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "F-001", "claim": "process X spawned by Y", "pins": []},
        {"finding_id": "F-002", "claim": "registry key Z was modified", "pins": []},
    ]
    s = verifier_pass.run(s)
    assert len(s["_verifier_decisions"]) == 2
    fids = {d["finding_id"] for d in s["_verifier_decisions"]}
    assert fids == {"F-001", "F-002"}
    for d in s["_verifier_decisions"]:
        assert d["decision"] == "agree"
        assert "MH_NO_CLAUDE" in d["rationale"] or "stub" in d["rationale"].lower()
        assert isinstance(d["verifier_iter"], int)


def test_verifier_pass_emits_message_per_finding_with_metadata(tmp_path: Path) -> None:
    """For each finding, emit_message from Verifier with metadata.verifier_decision."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "F-001", "claim": "test claim", "pins": []},
    ]
    verifier_pass.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    assert msgs_path.exists()
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    verifier_msgs = [
        p for p in parsed
        if p.get("from_agent") == "Verifier"
        and p.get("metadata", {}).get("verifier_decision") == "agree"
        and p.get("metadata", {}).get("finding_id") == "F-001"
    ]
    assert len(verifier_msgs) == 1


def test_verifier_pass_sets_verifier_complete_true(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "F-001", "claim": "x", "pins": []},
    ]
    s = verifier_pass.run(s)
    assert s["_verifier_complete"] is True


def test_verifier_pass_marks_rs_an_03(tmp_path: Path) -> None:
    """Verifier pass is the categorization gate per §11.4 → RS.AN-03."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = verifier_pass.run(s)
    assert "RS.AN-03" in s["csf_subcategories_satisfied"]


def test_verifier_pass_does_not_overwrite_phase(tmp_path: Path) -> None:
    """Verifier must NOT write state['phase']. Pre-fix it unconditionally
    set phase='analyze' even when not re-routing for dissent, which
    rolled the lifecycle backward from 'remediation' to 'analyze' in
    every clean run. The routing layer (route_after_verifier_pass) and
    the next node (analyze on re-route / session_finalize on clean)
    own the phase value now."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["phase"] = "remediation"  # what the prior node (remediation) set
    s = verifier_pass.run(s)
    assert s["phase"] == "remediation", (
        "verifier_pass regressed phase; routing layer should own it"
    )


def test_verifier_pass_writes_checkpoint_and_history(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    verifier_pass.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()


def test_verifier_pass_appends_to_node_history(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = verifier_pass.run(s)
    assert "verifier_pass" in s["_node_history"]
