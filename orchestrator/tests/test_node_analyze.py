"""analyze node tests — per-OS dispatch + bounded RCA loop."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import analyze
from mh_orchestrator.state import new_state


def test_analyze_under_no_claude_marks_rca_complete(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = analyze.run(s)
    # Under MH_NO_CLAUDE=1 (autouse), one shot through, no findings → rca_complete
    assert s["_rca_complete"] is True
    assert s["_analyze_iter"] >= 1
    assert s["phase"] == "analyze"
    assert "RS.AN-01" in s["csf_subcategories_satisfied"]
    assert "analyze" in s["_node_history"]


def test_analyze_per_os_dispatch_macos(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "macos"
    analyze.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    assert msgs_path.exists()
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    # Verify MacOSAgent was the dispatch target
    has_macos_dispatch = any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "MacOSAgent"
        for p in parsed
    )
    assert has_macos_dispatch


def test_analyze_per_os_dispatch_linux(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "linux"
    analyze.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    has_linux_dispatch = any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "LinuxAgent"
        for p in parsed
    )
    assert has_linux_dispatch


def test_analyze_unknown_os_fallback(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    # Force unknown by clearing the field
    s["_detected_os"] = "unknown"
    # Should not crash, should emit audit warning + fallback to WindowsAgent
    s = analyze.run(s)
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    audit_lines = [json.loads(line) for line in audit_path.read_text().strip().splitlines()]
    has_warning = any(e["event"] == "analyze_unknown_os_fallback" for e in audit_lines)
    assert has_warning
    msgs_path = tmp_path / "agent_messages.jsonl"
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    has_windows_fallback = any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "WindowsAgent"
        for p in parsed
    )
    assert has_windows_fallback


def test_analyze_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    analyze.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()
