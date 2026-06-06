"""claude_node tests — uses a fake `claude` binary on PATH."""
from __future__ import annotations

import json
import os
import stat
import textwrap

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
    """No silent fallback (trust contract): if MH_HOME is unset AND the
    defensive auto-derive can't find a project root (no .claude/settings.json
    + bin/mh-mcp-server markers in any parent), invoke_subagent must raise
    rather than spawn a blind agent with no MCP config.

    The auto-derive layer was added so `mh-orchestrate run` (which historically
    didn't export MH_HOME) works without the bash wrapper. The trust contract
    still holds — when both env AND auto-derive fail, raise loudly.
    """
    monkeypatch.delenv("MH_HOME", raising=False)
    # Redirect the auto-derive walk to a tmp dir that lacks the project markers
    # so the resolver falls all the way through to the raise. The resolver now
    # lives in providers/anthropic_cli.py after the multi-provider refactor;
    # patching the legacy claude_node.__file__ would no-op.
    monkeypatch.setattr(
        "mh_orchestrator.providers.anthropic_cli.__file__",
        str(tmp_path / "fake.py"),
    )
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


def test_invoke_subagent_disallows_bash(capturing_claude, tmp_path, monkeypatch):
    """Forensic specialists are read-only and reach evidence only through the
    sandboxed protocol_sift MCP tools (+ Read/Glob/Grep). The headless `claude -p`
    --allowedTools flag is ADDITIVE — it does NOT remove Bash from the spawned
    default toolset (confirmed against the system/init event) — so the only way to
    actually withhold Bash is the SUBTRACTIVE --disallowedTools flag. Without it a
    specialist holds Bash, which (a) lets it escape the evidence sandbox
    (chain-of-custody breach) and (b) is the error-prone tool that triggers the
    harness parallel-tool-call cancellation cascade. (Edit/Write/WebSearch
    hardening is a deliberate follow-up — Write is intentionally on the allowlist.)"""
    capture, _, _ = capturing_claude
    project = tmp_path / "proj"
    (project / "bin").mkdir(parents=True)
    monkeypatch.setenv("MH_HOME", str(project))

    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(subagent_name="WindowsAgent", prompt="go", headless=True)

    argv = capture.read_text()
    assert "--disallowedTools" in argv, (
        "spawn must SUBTRACT Bash — --allowedTools is additive, not restrictive"
    )
    disallowed_token = argv.split("--disallowedTools", 1)[1].split()[0]
    denied = set(disallowed_token.split(","))
    assert "Bash" in denied, (
        f"read-only specialist must deny Bash (cascade trigger + sandbox-escape vector); got {denied}"
    )


def test_invoke_subagent_passes_strict_mcp_config(capturing_claude, tmp_path, monkeypatch):
    """--mcp-config is ADDITIVE: without --strict-mcp-config the spawn inherits
    every user-scope MCP server (e.g. claude.ai Drive/Calendar/Notion connectors)
    on top of the injected protocol_sift config — confirmed against the
    system/init event of real subagent traces. That leak is (a) a latent hang:
    in headless -p mode a call to a connector tool outside --allowedTools hangs
    until the idle-timeout kill, (b) a chain-of-custody wart: a forensic
    specialist holding live Drive/Notion/Calendar connections, and (c) context
    noise (connector server instructions + eagerly-loaded auth tools).
    --strict-mcp-config restricts the spawn to exactly the servers in
    --mcp-config."""
    capture, _, _ = capturing_claude
    project = tmp_path / "proj"
    (project / "bin").mkdir(parents=True)
    monkeypatch.setenv("MH_HOME", str(project))

    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(subagent_name="WindowsAgent", prompt="go", headless=True)

    argv = capture.read_text()
    assert "--strict-mcp-config" in argv, (
        "spawn must pass --strict-mcp-config — --mcp-config alone is additive, "
        "so user-scope MCP servers (claude.ai connectors) leak into the "
        "forensic subagent session"
    )


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
        "python3 -c 'import time; time.sleep(0.1); t=time.time()\\nwhile time.time()-t<2: pass'\n"
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


def test_invoke_subagent_returns_timed_out_on_idle(tmp_path, monkeypatch):
    """A silent, idle subagent makes invoke_subagent return timed_out=True
    (NOT raise), honoring the env-tuned idle timeout."""
    _write_fake_claude(tmp_path, "cat >/dev/null\nsleep 30\n")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("MH_HOME", str(tmp_path))
    monkeypatch.setenv("MH_SUBAGENT_IDLE_TIMEOUT_SEC", "1")
    monkeypatch.setenv("MH_SUBAGENT_POLL_SEC", "0.25")
    from mh_orchestrator.claude_node import invoke_subagent
    result = invoke_subagent(subagent_name="WindowsAgent", prompt="go", headless=True)
    assert result.timed_out is True
    assert result.timeout_reason == "idle"


# ─── Trace capture (subagent forensic trail) ───────────────────────────────
#
# The agent's narrative reply is unreliable: in the earlier run it claimed
# 'DONE 5 findings recorded' while findings.json was []. The only trustworthy
# signal is the raw stream-json from `claude -p --output-format stream-json`,
# which shows every tool_use block. invoke_subagent receives that text but
# never persists it — leaving operators (and future debugging) blind.

def test_invoke_subagent_writes_stdout_trace_when_output_path_set(
    capturing_claude, tmp_path, monkeypatch,
):
    """When OUTPUT_PATH is set, invoke_subagent persists stdout to
    <OUTPUT_PATH>/_trace/<subagent_lower>_*.stdout.jsonl so the actual
    stream-json (tool_use blocks, MCP failures) is recoverable post-hoc."""
    monkeypatch.setenv("MH_HOME", str(tmp_path))
    output_dir = tmp_path / "case-out"
    output_dir.mkdir()
    monkeypatch.setenv("OUTPUT_PATH", str(output_dir))
    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(subagent_name="WindowsAgent", prompt="ping", headless=True)

    trace_dir = output_dir / "_trace"
    assert trace_dir.exists(), "expected _trace/ directory created under OUTPUT_PATH"
    stdout_files = list(trace_dir.glob("windowsagent_*.stdout.jsonl"))
    assert stdout_files, f"no stdout trace file written; contents: {list(trace_dir.iterdir())}"
    # The fake claude prints one stream-json result line — confirm it landed.
    body = stdout_files[0].read_text()
    assert '"type":"result"' in body or '"type": "result"' in body


def test_invoke_subagent_writes_stderr_trace(capturing_claude, tmp_path, monkeypatch):
    """stderr also captured — that's where MCP-server connection failures
    and authentication errors surface."""
    monkeypatch.setenv("MH_HOME", str(tmp_path))
    output_dir = tmp_path / "case-out"
    output_dir.mkdir()
    monkeypatch.setenv("OUTPUT_PATH", str(output_dir))
    # Extend fake to emit a stderr line so we can assert capture.
    fake = tmp_path / "bin" / "claude"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        "cat >/dev/null\n"
        "echo 'sample-stderr-line' >&2\n"
        "echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}'\n"
    )
    import stat as _stat
    fake.chmod(fake.stat().st_mode | _stat.S_IXUSR | _stat.S_IXGRP)

    from mh_orchestrator.claude_node import invoke_subagent
    invoke_subagent(subagent_name="WindowsAgent", prompt="ping", headless=True)

    trace_dir = output_dir / "_trace"
    stderr_files = list(trace_dir.glob("windowsagent_*.stderr.log"))
    assert stderr_files, "no stderr trace file written"
    assert "sample-stderr-line" in stderr_files[0].read_text()


def test_invoke_subagent_no_trace_when_output_path_absent(
    capturing_claude, tmp_path, monkeypatch,
):
    """When OUTPUT_PATH is not set (e.g., unit-test path), capture is a
    no-op. The pipeline must not fail just because no trace dir is configured."""
    monkeypatch.setenv("MH_HOME", str(tmp_path))
    monkeypatch.delenv("OUTPUT_PATH", raising=False)
    from mh_orchestrator.claude_node import invoke_subagent
    # Should not raise.
    result = invoke_subagent(subagent_name="WindowsAgent", prompt="ping", headless=True)
    assert result.exit_code == 0
