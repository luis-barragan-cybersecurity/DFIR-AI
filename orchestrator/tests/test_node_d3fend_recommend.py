"""d3fend_recommend node tests — D3FEND countermeasure recommendation (crosswalk-backed)."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import d3fend_recommend
from mh_orchestrator.state import new_state


def test_d3fend_recommend_populates_from_known_technique(tmp_path: Path) -> None:
    """Known ATT&CK ID produces >=1 D3FEND countermeasure."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1003.001"]
    s = d3fend_recommend.run(s)
    assert len(s["d3fend_recommendations"]) >= 1
    rec = s["d3fend_recommendations"][0]
    assert rec.d3fend_id.startswith("D3-")
    assert rec.attack_id_satisfied == "T1003.001"
    assert s["phase"] == "analyze"
    assert "d3fend_recommend" in s["_node_history"]


def test_d3fend_recommend_empty_input(tmp_path: Path) -> None:
    """Empty attack_techniques -> empty recs, no crosswalk-miss audit event."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = []
    s = d3fend_recommend.run(s)
    assert s["d3fend_recommendations"] == []
    audit_path = tmp_path / "audit.jsonl"
    if audit_path.exists():
        assert "d3fend_crosswalk_miss" not in audit_path.read_text()


def test_d3fend_recommend_unknown_logs_miss(tmp_path: Path) -> None:
    """Unknown ATT&CK ID writes d3fend_crosswalk_miss audit event."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T9999.999"]
    s = d3fend_recommend.run(s)
    assert s["d3fend_recommendations"] == []
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    assert "d3fend_crosswalk_miss" in audit_path.read_text()


def test_d3fend_recommend_initializes_field_if_missing(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    # Remove the recommendations field to test initialization
    del s["d3fend_recommendations"]
    s["attack_techniques"] = ["T9999.999"]  # unknown -> empty recs but field initialized
    s = d3fend_recommend.run(s)
    assert s["d3fend_recommendations"] == []


def test_d3fend_recommend_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1003.001"]
    d3fend_recommend.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
