"""claude_node tests — uses a fake `claude` binary on PATH."""
from __future__ import annotations

import json
import os
import stat

import pytest


@pytest.fixture
def capturing_claude(tmp_path, monkeypatch):
    """Fake `claude` that records argv, cwd, CLAUDE_PROJECT_DIR, the stdin
    prompt, and the content of any --mcp-config file — so tests can assert how
    invoke_subagent wired the subprocess without launching real Claude."""
    capture = tmp_path / "capture.txt"
    mcp_dump = tmp_path / "capture.mcp.json"
    stdin_dump = tmp_path / "capture.stdin.txt"
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text(
        "#!/usr/bin/env bash\n"
        f'cat > "{stdin_dump}"\n'
        f'{{ echo "CWD=$(pwd)"; echo "CLAUDE_PROJECT_DIR=${{CLAUDE_PROJECT_DIR:-}}"; '
        f'echo "ARGV=$*"; }} > "{capture}"\n'
        'prev=""\n'
        'for a in "$@"; do\n'
        f'  if [ "$prev" = "--mcp-config" ]; then cp "$a" "{mcp_dump}"; fi\n'
        '  prev="$a"\n'
        'done\n'
        "echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}'\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    return capture, mcp_dump, stdin_dump


def test_invoke_subagent_wires_mcp_and_project_context(capturing_claude, tmp_path, monkeypatch):
    """The headless subprocess must receive a protocol_sift --mcp-config built
    from the orchestrator env, with CLAUDE_PROJECT_DIR exported and cwd set to
    the project root — otherwise the spawned agent has no forensic tools (the
    root-cause bug: nodes passed mcp_config_path=None)."""
    capture, mcp_dump, _ = capturing_claude
    project = tmp_path / "proj"
    (project / "bin").mkdir(parents=True)
    monkeypatch.setenv("MH_HOME", str(project))
    monkeypatch.setenv("EVIDENCE_PATH", str(tmp_path / "ev"))
    monkeypatch.setenv("OUTPUT_PATH", str(tmp_path / "out"))
    monkeypatch.setenv("CASE_ID", "case-xyz")

    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(
        subagent_name="WindowsAgent", prompt="go",
        allowed_tools=["mcp__protocol_sift__hash", "Read"], headless=True,
    )

    text = capture.read_text()
    assert "--mcp-config" in text, "no --mcp-config passed → agent has no MCP tools"
    assert f"CLAUDE_PROJECT_DIR={project}" in text
    assert f"CWD={project}" in text, "cwd must be project root so .claude/ + mh-mcp-server resolve"

    cfg = json.loads(mcp_dump.read_text())
    server = cfg["mcpServers"]["protocol_sift"]
    assert server["command"].endswith("bin/mh-mcp-server")
    assert server["env"]["EVIDENCE_PATH"] == str(tmp_path / "ev")
    assert server["env"]["OUTPUT_PATH"] == str(tmp_path / "out")
    assert server["env"]["CASE_ID"] == "case-xyz"
    assert server["env"]["MH_HOME"] == str(project)


def test_invoke_subagent_fails_loud_without_mh_home(tmp_path, monkeypatch):
    """No silent fallback (trust contract): if MH_HOME is unset the wiring
    cannot be built, so invoke_subagent must raise rather than spawn a blind
    agent with no MCP config."""
    monkeypatch.delenv("MH_HOME", raising=False)
    from mh_orchestrator.claude_node import invoke_subagent
    with pytest.raises(RuntimeError, match="MH_HOME"):
        invoke_subagent(
            subagent_name="WindowsAgent", prompt="go",
            allowed_tools=["Read"], headless=True,
        )


def test_invoke_subagent_defaults_to_whole_server_allowlist(capturing_claude, tmp_path, monkeypatch):
    """Decision: agent frontmatter is the source of truth for capability, so
    we stop maintaining narrow per-node allowlists. Operationally this is also
    REQUIRED: in headless -p mode a tool call outside --allowedTools hangs
    indefinitely, so the default must grant the whole protocol_sift server."""
    capture, _, _ = capturing_claude
    project = tmp_path / "proj"
    (project / "bin").mkdir(parents=True)
    monkeypatch.setenv("MH_HOME", str(project))

    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(subagent_name="WindowsAgent", prompt="go", headless=True)  # no allowed_tools

    argv = capture.read_text()
    assert "--allowedTools" in argv
    assert "mcp__protocol_sift" in argv, "default allowlist must grant the whole protocol_sift server"


def test_invoke_subagent_loads_named_agent_persona(capturing_claude, tmp_path, monkeypatch):
    """The OS-specialist playbook must actually load: pass --agent <name> so
    the .claude/agents/<name>.md persona runs, and drop the dead
    'Use the X subagent.' text prefix (a default-agent session with no Task
    tool ignored it, so the FOR500/FOR518 playbook was never applied)."""
    capture, _, stdin_dump = capturing_claude
    project = tmp_path / "proj"
    (project / "bin").mkdir(parents=True)
    monkeypatch.setenv("MH_HOME", str(project))

    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(
        subagent_name="LinuxAgent", prompt="analyze the evidence",
        allowed_tools=["Read"], headless=True,
    )

    argv = capture.read_text()
    assert "--agent LinuxAgent" in argv, "persona not loaded via --agent"

    prompt_sent = stdin_dump.read_text()
    assert "analyze the evidence" in prompt_sent
    assert "Use the LinuxAgent subagent" not in prompt_sent, "dead text-prefix must be gone"


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text(
        "#!/usr/bin/env bash\n"
        "echo '{\"type\":\"system\",\"subtype\":\"init\"}'\n"
        "echo '{\"type\":\"assistant\",\"message\":{\"content\":"
        "[{\"type\":\"text\",\"text\":\"WindowsAgent online.\"}]}}'\n"
        "echo '{\"type\":\"result\",\"subtype\":\"success\","
        "\"result\":\"WindowsAgent online.\"}'\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    return fake


def test_invoke_subagent_parses_stream_json(fake_claude, tmp_path, monkeypatch):
    monkeypatch.setenv("MH_HOME", str(tmp_path))
    from mh_orchestrator.claude_node import invoke_subagent
    result = invoke_subagent(
        subagent_name="WindowsAgent",
        prompt="probe",
        allowed_tools=["mcp__protocol_sift__hash"],
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
    monkeypatch.setenv("MH_HOME", str(tmp_path))
    from mh_orchestrator.claude_node import invoke_subagent
    result = invoke_subagent(
        subagent_name="WindowsAgent",
        prompt="probe",
        allowed_tools=[],
        headless=True,
    )
    assert result.exit_code == 7


def test_subagent_result_defaults_not_timed_out():
    from mh_orchestrator.claude_node import SubagentResult
    r = SubagentResult(exit_code=0, stdout="", stderr="")
    assert r.timed_out is False
    assert r.timeout_reason == ""


import textwrap


def _write_fake_claude(tmp_path, body: str):
    """Write an executable fake `claude` whose bash body is `body`."""
    import stat as _stat
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(body))
    fake.chmod(fake.stat().st_mode | _stat.S_IXUSR | _stat.S_IXGRP)
    return fake


def test_monitor_kills_idle_silent_process(tmp_path):
    from mh_orchestrator.claude_node import _run_with_liveness_monitor
    fake = _write_fake_claude(tmp_path, "cat >/dev/null\nsleep 30\n")
    rc, out, err, timed_out, reason = _run_with_liveness_monitor(
        [str(fake)], prompt="go", cwd=str(tmp_path), env=dict(__import__("os").environ),
        idle_timeout=1.0, max_sec=30.0, poll_sec=0.25,
    )
    assert timed_out is True
    assert reason == "idle"


def test_monitor_keeps_cpu_busy_process_alive(tmp_path):
    # Silent (no stdout) but CPU-busy for ~2s, longer than idle_timeout, then exits.
    from mh_orchestrator.claude_node import _run_with_liveness_monitor
    fake = _write_fake_claude(
        tmp_path,
        "cat >/dev/null\n"
        "python3 -c 'import time; t=time.time()\\nwhile time.time()-t<2: pass'\n"
        "echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}'\n",
    )
    rc, out, err, timed_out, reason = _run_with_liveness_monitor(
        [str(fake)], prompt="go", cwd=str(tmp_path), env=dict(__import__("os").environ),
        idle_timeout=1.0, max_sec=30.0, poll_sec=0.25,
    )
    assert timed_out is False
    assert "ok" in out


def test_monitor_keeps_stdout_active_process_alive(tmp_path):
    # Near-zero CPU (sleeps) but prints a line every 0.3s for ~1.8s, > idle_timeout.
    from mh_orchestrator.claude_node import _run_with_liveness_monitor
    fake = _write_fake_claude(
        tmp_path,
        "cat >/dev/null\n"
        "for i in $(seq 1 6); do echo \"line $i\"; sleep 0.3; done\n"
        "echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"done\"}'\n",
    )
    rc, out, err, timed_out, reason = _run_with_liveness_monitor(
        [str(fake)], prompt="go", cwd=str(tmp_path), env=dict(__import__("os").environ),
        idle_timeout=1.0, max_sec=30.0, poll_sec=0.25,
    )
    assert timed_out is False


def test_monitor_enforces_absolute_ceiling(tmp_path):
    # Always active (prints forever) but exceeds the ceiling.
    from mh_orchestrator.claude_node import _run_with_liveness_monitor
    fake = _write_fake_claude(
        tmp_path, "cat >/dev/null\nwhile true; do echo x; sleep 0.2; done\n",
    )
    rc, out, err, timed_out, reason = _run_with_liveness_monitor(
        [str(fake)], prompt="go", cwd=str(tmp_path), env=dict(__import__("os").environ),
        idle_timeout=30.0, max_sec=1.0, poll_sec=0.25,
    )
    assert timed_out is True
    assert reason == "ceiling"


def test_monitor_fast_clean_exit_not_timed_out(tmp_path):
    from mh_orchestrator.claude_node import _run_with_liveness_monitor
    fake = _write_fake_claude(
        tmp_path, "cat >/dev/null\necho '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}'\n",
    )
    rc, out, err, timed_out, reason = _run_with_liveness_monitor(
        [str(fake)], prompt="go", cwd=str(tmp_path), env=dict(__import__("os").environ),
        idle_timeout=5.0, max_sec=30.0, poll_sec=0.25,
    )
    assert timed_out is False
    assert rc == 0
    assert "ok" in out


def test_monitor_idle_fallback_when_proc_unavailable(tmp_path, monkeypatch):
    # Force the /proc-absent path; idle detection must still work via stdout silence.
    from mh_orchestrator import proc_activity
    monkeypatch.setattr(proc_activity, "proc_available", lambda: False)
    from mh_orchestrator.claude_node import _run_with_liveness_monitor
    fake = _write_fake_claude(tmp_path, "cat >/dev/null\nsleep 30\n")
    rc, out, err, timed_out, reason = _run_with_liveness_monitor(
        [str(fake)], prompt="go", cwd=str(tmp_path), env=dict(__import__("os").environ),
        idle_timeout=1.0, max_sec=30.0, poll_sec=0.25,
    )
    assert timed_out is True
    assert reason == "idle"
