"""kill_chain node tests — Lockheed Martin Cyber Kill Chain stage classification."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import kill_chain
from mh_orchestrator.state import new_state


def test_kill_chain_delivery_stage(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1566"]
    s = kill_chain.run(s)
    assert s["kill_chain_stage"] == 3
    assert s["phase"] == "analyze"


def test_kill_chain_actions_on_objectives_stage(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1486"]
    s = kill_chain.run(s)
    assert s["kill_chain_stage"] == 7


def test_kill_chain_max_wins(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1566", "T1486"]
    s = kill_chain.run(s)
    assert s["kill_chain_stage"] == 7


def test_kill_chain_unknown_technique_keeps_default(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T9999"]
    s = kill_chain.run(s)
    assert s["kill_chain_stage"] == 0


def test_kill_chain_subtechnique_strip(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1059.001"]
    s = kill_chain.run(s)
    assert s["kill_chain_stage"] == 4


def test_kill_chain_empty_techniques(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = []
    s = kill_chain.run(s)
    assert s["kill_chain_stage"] == 0


def test_kill_chain_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["attack_techniques"] = ["T1059"]
    kill_chain.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
