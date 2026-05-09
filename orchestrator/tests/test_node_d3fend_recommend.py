"""d3fend_recommend node tests — D3FEND countermeasure recommendation (stub-backed)."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import d3fend_recommend
from mh_orchestrator.state import new_state


def test_d3fend_recommend_stub_returns_empty(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1059", "T1486"]
    s = d3fend_recommend.run(s)
    # Stub returns empty list — recommendations stay empty
    assert s["d3fend_recommendations"] == []
    assert s["phase"] == "analyze"
    assert "d3fend_recommend" in s["_node_history"]


def test_d3fend_recommend_emits_stub_warning(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1059"]
    d3fend_recommend.run(s)
    audit_log = tmp_path / "audit.jsonl"
    assert audit_log.exists()
    lines = audit_log.read_text().strip().splitlines()
    parsed = [json.loads(line) for line in lines]
    has_stub_warning = any(e["event"] == "d3fend_stub_used" for e in parsed)
    assert has_stub_warning


def test_d3fend_recommend_empty_techniques_no_crash(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = []
    s = d3fend_recommend.run(s)
    assert s["d3fend_recommendations"] == []


def test_d3fend_recommend_initializes_field_if_missing(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    # Remove the recommendations field to test initialization
    del s["d3fend_recommendations"]
    s["attack_techniques"] = ["T1059"]
    s = d3fend_recommend.run(s)
    assert s["d3fend_recommendations"] == []


def test_d3fend_recommend_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1059"]
    d3fend_recommend.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
