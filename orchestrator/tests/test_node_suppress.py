"""suppress node tests."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import suppress
from mh_orchestrator.state import new_state


def test_suppress_terminal_state(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["severity"] = "low"
    s = suppress.run(s)
    assert s["phase"] == "lessons"
    assert "suppress" in s["_node_history"]
    audit = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    parsed = [json.loads(line) for line in audit]
    assert any(e["event"] == "false_positive_suppressed" for e in parsed)
