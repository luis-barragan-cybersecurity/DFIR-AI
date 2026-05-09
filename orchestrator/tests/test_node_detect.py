"""detect node tests."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import detect
from mh_orchestrator.state import new_state


def test_detect_sets_detected_os_and_phase(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = detect.run(s)
    assert s["_detected_os"] in {"windows", "macos", "linux", "unknown"}
    assert s["phase"] == "triage"
    assert "DE.AE-02" in s["csf_subcategories_satisfied"]
    assert "detect" in s["_node_history"]


def test_detect_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    detect.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
