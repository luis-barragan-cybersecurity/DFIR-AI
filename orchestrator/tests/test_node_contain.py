"""contain node tests — NIST SP 800-61 §5.1 containment recommendations.

Advisory-only: emit recommendations + score blast radius. Never executes
any host change. Mirrors test pattern from test_node_analyze.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import contain
from mh_orchestrator.state import new_state


def test_contain_emits_three_recommendations(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = contain.run(s)
    assert len(s["containment_actions"]) == 3
    assert s["phase"] == "contain"
    assert "RS.MI-01" in s["csf_subcategories_satisfied"]
    assert "contain" in s["_node_history"]


def test_contain_recommendations_are_advisory_only(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = contain.run(s)
    assert all(rec["advisory_only"] is True for rec in s["containment_actions"])
    # Each rec carries id + tactic + action
    for rec in s["containment_actions"]:
        assert rec["id"].startswith("CONTAIN-")
        assert rec["tactic"] in {"short_term", "system_backup", "long_term"}
        assert isinstance(rec["action"], str) and rec["action"]


def test_contain_writes_actions_jsonl(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    contain.run(s)
    actions_path = tmp_path / "containment_actions.jsonl"
    assert actions_path.exists()
    lines = actions_path.read_text().strip().splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    for rec in parsed:
        assert rec["advisory_only"] is True
        assert "blast_radius" in rec
        assert isinstance(rec["blast_radius"]["score"], int)


def test_contain_sets_max_blast_score(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = contain.run(s)
    assert "_max_blast_score" in s
    assert isinstance(s["_max_blast_score"], int)
    # short_term has hosts=1+services=2 → 5+6=11 (highest of the three)
    assert s["_max_blast_score"] >= 1


def test_contain_extends_actions_list_idempotently(tmp_path: Path) -> None:
    """Calling contain.run twice should append (extend) — not overwrite."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    contain.run(s)
    contain.run(s)
    assert len(s["containment_actions"]) == 6


def test_contain_user_count_from_findings(tmp_path: Path) -> None:
    """Long-term rec should reflect distinct users from finding pins."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": "F-001", "pins": [{"user": "alice"}, {"user": "bob"}]},
        {"finding_id": "F-002", "pins": [{"user": "alice"}]},  # dup alice
    ]
    contain.run(s)
    long_term = next(
        r for r in s["containment_actions"] if r["tactic"] == "long_term"
    )
    # Two distinct users (alice + bob)
    assert long_term["blast_radius"]["users"] == 2


def test_contain_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    contain.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
