"""triage node tests."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import triage
from mh_orchestrator.state import new_state


def test_triage_sets_severity_under_no_claude(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = triage.run(s)
    assert s["severity"] in {"low", "medium", "high", "critical"}
    assert "RS.MA-03" in s["csf_subcategories_satisfied"]
    assert "triage" in s["_node_history"]


def test_triage_writes_dispatch_response_messages(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    triage.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    assert msgs_path.exists()
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    has_dispatch = any(p["from_agent"] == "orchestrator" and p["to_agent"] == "WindowsAgent" for p in parsed)
    has_response = any(p["from_agent"] == "WindowsAgent" and p["to_agent"] == "orchestrator" for p in parsed)
    assert has_dispatch and has_response


def test_memory_dump_routes_to_windows_agent(tmp_path: Path) -> None:
    """Regression: rocba-memory case shipped a Windows memory image (Rocba-Memory.raw).
    Previously memory_dump fell through to WindowsAgent via the fallback default —
    but that path was load-bearing on undocumented behaviour. Make the route
    explicit so it can't regress silently into routing to (e.g.) MemoryAgent
    in some refactor and skipping windows.* Volatility plugins."""
    assert triage.OS_TO_SUBAGENT["memory_dump"] == "WindowsAgent"
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "memory_dump"
    triage.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    assert any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "WindowsAgent"
        for p in parsed
    ), "memory_dump did not dispatch to WindowsAgent"
