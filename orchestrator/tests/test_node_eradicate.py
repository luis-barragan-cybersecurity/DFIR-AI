"""eradicate node tests — Evict-tactic recommendations (advisory only)."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import eradicate
from mh_orchestrator.state import new_state


def test_eradicate_emits_three_recommendations(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = eradicate.run(s)
    assert len(s["eradication_actions"]) == 3
    assert s["phase"] == "eradicate"
    assert "RS.MI-02" in s["csf_subcategories_satisfied"]
    assert "eradicate" in s["_node_history"]


def test_eradicate_recommendations_are_advisory_only(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    eradicate.run(s)
    for rec in s["eradication_actions"]:
        assert rec["advisory_only"] is True
        assert rec["tactic"] == "evict"
        assert rec["id"].startswith("ERADICATE-")
        assert isinstance(rec["action"], str) and rec["action"]


def test_eradicate_sets_reinfection_flag_false(tmp_path: Path) -> None:
    """Skeleton: no detection signal → False."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = eradicate.run(s)
    assert s["_reinfection_detected"] is False


def test_eradicate_extends_actions_list(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    eradicate.run(s)
    eradicate.run(s)
    assert len(s["eradication_actions"]) == 6


def test_eradicate_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    eradicate.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
