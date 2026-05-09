"""claude_node tests — uses a fake `claude` binary on PATH."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text(
        "#!/usr/bin/env bash\n"
        "echo '{\"type\":\"system\",\"subtype\":\"init\"}'\n"
        "echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"WindowsAgent online.\"}]}}'\n"
        "echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"WindowsAgent online.\"}'\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    return fake


def test_invoke_subagent_parses_stream_json(fake_claude, tmp_path):
    from mh_orchestrator.claude_node import invoke_subagent
    result = invoke_subagent(
        subagent_name="WindowsAgent",
        prompt="probe",
        case_dir=tmp_path,
        allowed_tools=["mcp__protocol_sift__hash"],
        mcp_config_path=None,
        headless=True,
    )
    assert result.exit_code == 0
    assert result.final_text == "WindowsAgent online."
    assert any(m["type"] == "result" for m in result.parsed_messages)


def test_invoke_subagent_surfaces_nonzero_exit(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("#!/usr/bin/env bash\nexit 7\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    from mh_orchestrator.claude_node import invoke_subagent
    result = invoke_subagent(
        subagent_name="WindowsAgent",
        prompt="probe",
        case_dir=tmp_path,
        allowed_tools=[],
        mcp_config_path=None,
        headless=True,
    )
    assert result.exit_code == 7
