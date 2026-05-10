"""attack_tag node tests — MITRE ATT&CK technique extraction."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import attack_tag
from mh_orchestrator.state import new_state


def test_attack_tag_extracts_technique_id_from_claim(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "f1", "claim": "Process injection observed (T1059)", "confidence": "high"},
    ]
    s = attack_tag.run(s)
    assert "T1059" in s["attack_techniques"]
    assert "RS.AN-03" in s["csf_subcategories_satisfied"]
    assert s["phase"] == "analyze"


def test_attack_tag_extracts_subtechnique(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "f1", "claim": "PowerShell abuse: T1059.001 detected", "confidence": "high"},
    ]
    s = attack_tag.run(s)
    assert "T1059.001" in s["attack_techniques"]


def test_attack_tag_dedupes_and_sorts(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "f1", "claim": "First T1486 then T1059"},
        {"finding_id": "f2", "claim": "T1059 again here"},
        {"finding_id": "f3", "claim": "T1486 repeated"},
    ]
    s = attack_tag.run(s)
    assert s["attack_techniques"] == ["T1059", "T1486"]


def test_attack_tag_reads_mitre_attck_field(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "f1", "claim": "no id in text", "mitre_attck": ["T1190", "T1133"]},
    ]
    s = attack_tag.run(s)
    assert "T1190" in s["attack_techniques"]
    assert "T1133" in s["attack_techniques"]


def test_attack_tag_no_findings_no_crash(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = []
    s = attack_tag.run(s)
    assert s["attack_techniques"] == []
    assert "RS.AN-03" in s["csf_subcategories_satisfied"]


def test_attack_tag_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "f1", "claim": "T1486"}]
    attack_tag.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
