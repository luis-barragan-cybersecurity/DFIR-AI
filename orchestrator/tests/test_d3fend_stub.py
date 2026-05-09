"""d3fend_stub placeholder tests."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator import d3fend_stub
from mh_orchestrator.state import new_state


def test_recommend_empty_input_returns_empty(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    result = d3fend_stub.recommend(s, [])
    assert result == []


def test_recommend_emits_audit_warning(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    result = d3fend_stub.recommend(s, ["T1003.001", "T1486"])
    assert result == []
    audit_log = tmp_path / "audit.jsonl"
    assert audit_log.exists()
    lines = audit_log.read_text().strip().splitlines()
    parsed = [json.loads(line) for line in lines]
    warnings = [e for e in parsed if e["event"] == "d3fend_stub_used"]
    assert len(warnings) == 1
    assert warnings[0]["data"]["attack_techniques"] == ["T1003.001", "T1486"]
    assert warnings[0]["data"]["sub_plan_04"] == "pending"
