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


def test_triage_allowed_tools_include_memory_probe() -> None:
    """Triage MUST be allowed to call magic_check + memory_volatility so
    it can do a real evidence probe before classifying severity. Without
    these, triage on a raw memory image has zero signal and reflexively
    answers 'low', causing route_after_triage to short-circuit through
    suppress on every real case. Locks in the Option B contract."""
    assert "mcp__protocol_sift__magic_check" in triage.ALLOWED_TOOLS
    assert "mcp__protocol_sift__memory_volatility" in triage.ALLOWED_TOOLS


def test_triage_keeps_baseline_tools() -> None:
    """Defense: the expanded allowlist must not lose the baseline tools
    (hash, os_detect, finding_record). All three are load-bearing for
    other phases triage informs."""
    for t in ("mcp__protocol_sift__hash",
              "mcp__protocol_sift__os_detect",
              "mcp__protocol_sift__finding_record"):
        assert t in triage.ALLOWED_TOOLS


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
