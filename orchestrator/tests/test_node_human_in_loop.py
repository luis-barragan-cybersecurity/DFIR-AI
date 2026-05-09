"""human_in_loop node tests — reversibility-gate human approval pause.

Fires only when blast radius exceeds threshold. Writes
human_approval_required.json listing actions awaiting approval. Marks
RS.MI-01 (Incidents are contained) — advisory-only.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mh_orchestrator.nodes import human_in_loop
from mh_orchestrator.state import new_state


def test_human_in_loop_no_over_threshold_actions(tmp_path: Path) -> None:
    """Default threshold=50, no containment_actions → empty list, status=pending."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = human_in_loop.run(s)
    approval_path = tmp_path / "human_approval_required.json"
    assert approval_path.exists()
    payload = json.loads(approval_path.read_text())
    assert payload["actions_requiring_approval"] == []
    assert payload["approval_status"] == "pending"
    assert payload["advisory_only"] is True
    assert payload["threshold"] == 50  # blast_radius.DEFAULT_THRESHOLD


def test_human_in_loop_env_override_threshold_filters_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MH_BLAST_RADIUS_THRESHOLD=1 → action with score=5 listed for approval."""
    monkeypatch.setenv("MH_BLAST_RADIUS_THRESHOLD", "1")
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["containment_actions"] = [
        {
            "id": "CONTAIN-X",
            "tactic": "short_term",
            "action": "Isolate host",
            "blast_radius": {"hosts": 1, "users": 0, "services": 0, "score": 5},
            "advisory_only": True,
        },
        {
            "id": "CONTAIN-LOW",
            "tactic": "long_term",
            "action": "Tiny",
            "blast_radius": {"hosts": 0, "users": 0, "services": 0, "score": 0},
            "advisory_only": True,
        },
    ]
    s = human_in_loop.run(s)
    approval_path = tmp_path / "human_approval_required.json"
    payload = json.loads(approval_path.read_text())
    assert payload["threshold"] == 1
    listed_ids = [a["id"] for a in payload["actions_requiring_approval"]]
    assert "CONTAIN-X" in listed_ids
    assert "CONTAIN-LOW" not in listed_ids


def test_human_in_loop_sets_human_approval_required_true(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = human_in_loop.run(s)
    assert s["human_approval_required"] is True


def test_human_in_loop_emits_awaiting_approval_audit_event(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    human_in_loop.run(s)
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    audit_lines = [json.loads(line) for line in audit_path.read_text().strip().splitlines()]
    has_awaiting = any(e["event"] == "awaiting_approval" for e in audit_lines)
    assert has_awaiting


def test_human_in_loop_marks_rs_mi_01(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = human_in_loop.run(s)
    assert "RS.MI-01" in s["csf_subcategories_satisfied"]


def test_human_in_loop_sets_phase_contain(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = human_in_loop.run(s)
    assert s["phase"] == "contain"


def test_human_in_loop_writes_checkpoint_and_history(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    human_in_loop.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()


def test_human_in_loop_appends_to_node_history(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = human_in_loop.run(s)
    assert "human_in_loop" in s["_node_history"]


def test_human_in_loop_payload_includes_max_blast_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Payload contains max_blast_score from state for downstream review."""
    monkeypatch.setenv("MH_BLAST_RADIUS_THRESHOLD", "1")
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_max_blast_score"] = 11
    s["containment_actions"] = [
        {
            "id": "CONTAIN-A",
            "blast_radius": {"hosts": 2, "users": 0, "services": 0, "score": 10},
            "advisory_only": True,
        },
    ]
    human_in_loop.run(s)
    payload = json.loads((tmp_path / "human_approval_required.json").read_text())
    assert payload["max_blast_score"] == 11
    assert payload["case_id"] == "c"
