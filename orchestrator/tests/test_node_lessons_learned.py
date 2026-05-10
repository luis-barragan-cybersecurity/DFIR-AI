"""lessons_learned node tests — markdown writeup + GV.OV-01."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import lessons_learned
from mh_orchestrator.state import new_state


def test_lessons_writes_markdown(tmp_path: Path) -> None:
    s = new_state("case-LL-001")
    s["_output_dir"] = str(tmp_path)
    s["severity"] = "high"
    s["attack_techniques"] = ["T1059", "T1486"]
    s["kill_chain_stage"] = 5
    s = lessons_learned.run(s)
    md_path = tmp_path / "lessons_learned.md"
    assert md_path.exists()
    content = md_path.read_text()
    assert "case-LL-001" in content
    assert "high" in content
    assert "T1059" in content


def test_lessons_sets_iso27035_phase(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = lessons_learned.run(s)
    assert s["iso27035_phase"] == "learn_lessons"
    assert s["phase"] == "lessons"


def test_lessons_marks_gv_ov_01(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = lessons_learned.run(s)
    assert "GV.OV-01" in s["csf_subcategories_satisfied"]
    assert "lessons_learned" in s["_node_history"]


def test_lessons_summary_includes_finding_counts(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1"}, {"finding_id": "F-2"}]
    lessons_learned.run(s)
    md = (tmp_path / "lessons_learned.md").read_text()
    # Should reflect 2 findings
    assert "2" in md


def test_lessons_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    lessons_learned.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
