"""triage node tests."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mh_orchestrator.nodes import triage
from mh_orchestrator.state import new_state


def _install_fake_claude(tmp_path, monkeypatch, reply: str) -> None:
    """Put a fake `claude` on PATH that returns `reply` as its success result,
    and run triage in real (non-stub) mode wired to a project root."""
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text(
        "#!/usr/bin/env bash\ncat >/dev/null\n"
        f"echo '{{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"{reply}\"}}'\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("MH_NO_CLAUDE", "0")  # override conftest autouse stub
    (tmp_path / "bin").mkdir(exist_ok=True)
    monkeypatch.setenv("MH_HOME", str(tmp_path))


def test_triage_sets_severity_under_no_claude(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = triage.run(s)
    assert s["severity"] in {"low", "medium", "high", "critical"}
    assert "RS.MA-03" in s["csf_subcategories_satisfied"]
    assert "triage" in s["_node_history"]


def test_triage_stub_does_not_flag_false_positive(tmp_path: Path) -> None:
    """Stub (happy path) must NOT mark a false positive — it flows to the full
    pipeline, never suppress."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = triage.run(s)
    assert s["_triage_false_positive"] is False


def test_triage_explicit_false_positive_sets_flag(tmp_path, monkeypatch) -> None:
    """A specialist that explicitly returns a false-positive verdict sets the
    flag so route_after_triage can suppress."""
    _install_fake_claude(tmp_path, monkeypatch, "false_positive")
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = triage.run(s)
    assert s["_triage_false_positive"] is True


def test_triage_severity_reply_is_not_false_positive(tmp_path, monkeypatch) -> None:
    """A normal severity verdict (even 'low') must NOT flag a false positive."""
    _install_fake_claude(tmp_path, monkeypatch, "low")
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = triage.run(s)
    assert s["severity"] == "low"
    assert s["_triage_false_positive"] is False


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


def test_triage_timeout_fails_open_to_unknown(tmp_path, monkeypatch) -> None:
    """A timed-out triage call must fail OPEN (severity unknown, NOT a false
    positive) so the investigation still proceeds, and must not raise."""
    from mh_orchestrator.claude_node import SubagentResult
    from mh_orchestrator.nodes import triage as triage_mod
    monkeypatch.setenv("MH_NO_CLAUDE", "0")

    def fake_invoke(**kwargs):
        return SubagentResult(exit_code=-15, stdout="", stderr="",
                              timed_out=True, timeout_reason="idle")

    monkeypatch.setattr(triage_mod, "invoke_subagent", fake_invoke)

    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = triage_mod.run(s)

    assert s["severity"] == "unknown"
    assert s["_triage_false_positive"] is False


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
