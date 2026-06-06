"""Subprocess wrapper for invoking a Claude Code subagent.

Mirrors `bin/mh:claude_run` — same MCP config layout, same allowedTools wiring,
same auth inheritance — but designed for non-interactive (headless) calls
from inside a LangGraph node.

The wiring here is load-bearing: a LangGraph node that shells out to `claude`
WITHOUT a resolved `--mcp-config`, `CLAUDE_PROJECT_DIR`, and a project-root cwd
spawns a blind agent — the `mcp__protocol_sift__*` forensic tools don't exist in
its session, so it can't run os_detect / finding_record and the whole pipeline
produces empty deliverables. We build the same runtime-resolved config that the
interactive `bin/mh run --interactive` path uses, and load the OS-specialist
persona (`.claude/agents/<name>.md`) via `--agent` so the FOR500/FOR518 playbook
actually applies.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import proc_activity


def should_stub(node_name: str) -> bool:
    """Decide whether an LLM-invoking node should use its stub branch.

    Rules (in precedence order):
    1. If MH_NO_CLAUDE is not set or != "1" → return False (always real).
    2. If MH_REAL_CLAUDE_NODES is set and node_name is in the
       comma-separated list → return False (override: real Claude even
       though MH_NO_CLAUDE=1).
    3. Otherwise → return True (stub).

    Args:
        node_name: One of "triage", "analyze", "verifier_pass".

    Returns:
        True if the node should take its stub branch.
    """
    if os.environ.get("MH_NO_CLAUDE") != "1":
        return False
    real_nodes = os.environ.get("MH_REAL_CLAUDE_NODES", "")
    requested = {n.strip() for n in real_nodes.split(",") if n.strip()}
    return node_name not in requested


# Default tool allowlist for every subagent call.
#
# `mcp__protocol_sift` (bare server name) is the canonical Claude Code form for
# "allow EVERY tool from this MCP server" — drift-proof as the server grows.
# This is both a design choice (the `--agent` frontmatter, not a per-node list,
# is the source of truth for what each specialist actually uses) and a
# CORRECTNESS requirement: in headless `-p` mode a tool call that isn't on the
# allowlist hangs the subprocess indefinitely (no auto-deny), so we must grant
# the whole forensic surface up front. Bash is intentionally omitted — the
# specialists are read-only and reach evidence only through sandboxed MCP tools.
DEFAULT_ALLOWED_TOOLS: list[str] = [
    "mcp__protocol_sift",
    "Read", "Glob", "Grep", "Write", "TodoWrite", "Skill",
]


@dataclass
class SubagentResult:
    exit_code: int
    stdout: str
    stderr: str
    parsed_messages: list[dict[str, Any]] = field(default_factory=list)
    final_text: str = ""
    timed_out: bool = False
    timeout_reason: str = ""


def _resolve_project_dir() -> Path:
    """Return the project root (MH_HOME) or raise — no silent fallback.

    `bin/mh run` exports MH_HOME / EVIDENCE_PATH / OUTPUT_PATH / CASE_ID before
    invoking the orchestrator. If MH_HOME is missing we cannot build the
    protocol_sift MCP config or resolve `.claude/agents/`, so refuse loudly
    rather than spawn a tool-less agent that silently produces nothing.
    """
    mh_home = os.environ.get("MH_HOME")
    if not mh_home:
        raise RuntimeError(
            "MH_HOME not set — invoke_subagent must run under `bin/mh run`, "
            "which exports MH_HOME/EVIDENCE_PATH/OUTPUT_PATH/CASE_ID. Refusing "
            "to spawn a subagent with no protocol_sift MCP config.",
        )
    return Path(mh_home)


def _write_mcp_config(project_dir: Path, dest_dir: Path) -> Path:
    """Write a runtime-resolved protocol_sift mcp-config (mirrors claude_run).

    `claude` does NOT substitute ${VARS} inside --mcp-config files, so we
    resolve the command path + env here and write a concrete JSON file.
    """
    cfg = {
        "mcpServers": {
            "protocol_sift": {
                "command": str(project_dir / "bin" / "mh-mcp-server"),
                "args": [],
                "env": {
                    "EVIDENCE_PATH": os.environ.get("EVIDENCE_PATH", ""),
                    "OUTPUT_PATH": os.environ.get("OUTPUT_PATH", ""),
                    "CASE_ID": os.environ.get("CASE_ID", ""),
                    "MH_HOME": str(project_dir),
                },
            },
        },
    }
    path = dest_dir / "mcp-config.json"
    path.write_text(json.dumps(cfg))
    return path


def _read_stream(stream: Any, buf: list[str], last_ts: list[float]) -> None:
    """Drain a text stream line-by-line into buf, stamping last_ts on each line.
    Runs in a daemon thread so a long subagent can't deadlock on a full pipe."""
    try:
        for line in stream:
            buf.append(line)
            last_ts[0] = time.monotonic()
    except (ValueError, OSError):
        pass  # stream closed under us on kill


def _write_stdin(stream: Any, data: str) -> None:
    """Feed the prompt to the child's stdin in a daemon thread so a prompt
    larger than the OS pipe buffer can't block the monitor before the stdout/
    stderr readers start draining."""
    try:
        stream.write(data)
        stream.close()
    except (BrokenPipeError, OSError, ValueError):
        pass


def _kill_group(proc: "subprocess.Popen[str]") -> None:
    """SIGTERM the whole process group, grace, then SIGKILL. Kills the agent
    plus its mh-mcp-server and any tool subprocesses (start_new_session put
    them in one group)."""
    try:
        pgid = os.getpgid(proc.pid)
    except (OSError, ProcessLookupError):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def _run_with_liveness_monitor(
    argv: list[str], *, prompt: str, cwd: str, env: dict[str, str],
    idle_timeout: float, max_sec: float, poll_sec: float,
) -> tuple[int, str, str, bool, str]:
    """Run argv under a liveness monitor. Returns
    (returncode, stdout, stderr, timed_out, timeout_reason).

    Idle = no stdout/stderr line AND no process-group CPU advance for
    idle_timeout seconds. A kill (idle or ceiling) terminates the whole group
    and returns timed_out=True rather than raising.

    Callers should pass poll_sec < idle_timeout: idle is only checked once per
    poll, so a poll larger than the idle window delays detection.
    """
    proc = subprocess.Popen(  # noqa: S603
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, cwd=cwd, env=env,
        start_new_session=True,
    )

    out_buf: list[str] = []
    err_buf: list[str] = []
    last_output = [time.monotonic()]
    threads = [
        threading.Thread(target=_read_stream, args=(proc.stdout, out_buf, last_output), daemon=True),
        threading.Thread(target=_read_stream, args=(proc.stderr, err_buf, last_output), daemon=True),
    ]
    if proc.stdin is not None:
        threads.append(threading.Thread(target=_write_stdin, args=(proc.stdin, prompt), daemon=True))
    for t in threads:
        t.start()

    use_cpu = proc_activity.proc_available()
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = proc.pid
    prev_cpu = proc_activity.read_pgroup_cpu(pgid) if use_cpu else {}

    start = time.monotonic()
    last_active = start
    timed_out = False
    reason = ""
    while True:
        try:
            proc.wait(timeout=poll_sec)
            break  # process exited on its own
        except subprocess.TimeoutExpired:
            pass
        now = time.monotonic()
        active = last_output[0] > last_active
        if use_cpu:
            curr_cpu = proc_activity.read_pgroup_cpu(pgid)
            if proc_activity.cpu_advanced(prev_cpu, curr_cpu):
                active = True
            prev_cpu = curr_cpu
        if active:
            last_active = now
        elif now - last_active >= idle_timeout:
            timed_out, reason = True, "idle"
            break
        if now - start >= max_sec:
            timed_out, reason = True, "ceiling"
            break

    if timed_out:
        _kill_group(proc)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
    for t in threads:
        t.join(timeout=2)
    rc = proc.returncode if proc.returncode is not None else -1
    return rc, "".join(out_buf), "".join(err_buf), timed_out, reason


def _write_subagent_trace(
    subagent_name: str, stdout: str, stderr: str,
) -> None:
    """Persist subagent subprocess stdout/stderr to <OUTPUT_PATH>/_trace/.

    No-op when OUTPUT_PATH is unset (e.g., direct unit-test invocations
    that don't go through `bin/mh run`). Failures here are swallowed —
    the pipeline must not break because trace capture couldn't write.

    Rationale: the agent's natural-language reply is unreliable (in the
    earlier run it claimed "DONE 5 findings recorded" while
    findings.json was []). The stream-json stdout contains every actual
    tool_use block, and stderr surfaces MCP-server connection / auth
    failures — both invisible without persisting.
    """
    output_path = os.environ.get("OUTPUT_PATH")
    if not output_path:
        return
    try:
        trace_dir = Path(output_path) / "_trace"
        trace_dir.mkdir(parents=True, exist_ok=True)
        # Lowercase + non-alphanumerics-to-underscore for a stable filename.
        slug = re.sub(r"[^a-z0-9]+", "_", subagent_name.lower()).strip("_") or "subagent"
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        (trace_dir / f"{slug}_{ts}.stdout.jsonl").write_text(stdout)
        (trace_dir / f"{slug}_{ts}.stderr.log").write_text(stderr)
    except OSError:
        # Disk full, permission denied, anything — debugging trace is
        # best-effort and must never break the pipeline.
        return

def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _parse_stream_json(stdout: str) -> tuple[list[dict[str, Any]], str]:
    parsed: list[dict[str, Any]] = []
    final_text = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed.append(msg)
        if msg.get("type") == "result" and msg.get("subtype") == "success":
            final_text = msg.get("result", "") or ""
    return parsed, final_text


def invoke_subagent(
    *,
    subagent_name: str,
    prompt: str,
    allowed_tools: list[str] | None = None,
    headless: bool = True,
) -> SubagentResult:
    """Invoke a named Claude Code subagent headlessly under a liveness monitor.

    Wires --agent / --mcp-config / CLAUDE_PROJECT_DIR / project-root cwd exactly
    as the working interactive path, then runs under _run_with_liveness_monitor:
    a call is killed only when genuinely idle (no CPU and no output) for
    MH_SUBAGENT_IDLE_TIMEOUT_SEC, or after the MH_SUBAGENT_MAX_SEC ceiling. A
    timeout returns timed_out=True (never raises) so the caller can degrade.
    """
    project_dir = _resolve_project_dir()
    tools = allowed_tools if allowed_tools is not None else DEFAULT_ALLOWED_TOOLS
    idle_timeout = _env_float("MH_SUBAGENT_IDLE_TIMEOUT_SEC", 600.0)
    max_sec = _env_float("MH_SUBAGENT_MAX_SEC", 7200.0)
    poll_sec = _env_float("MH_SUBAGENT_POLL_SEC", 15.0)

    with tempfile.TemporaryDirectory(prefix="mh-mcp-") as td:
        mcp_cfg = _write_mcp_config(project_dir, Path(td))
        argv: list[str] = ["claude"]
        if headless:
            argv += ["-p", "--output-format", "stream-json", "--verbose"]
        argv += ["--agent", subagent_name, "--mcp-config", str(mcp_cfg)]
        if tools:
            argv += ["--allowedTools", ",".join(tools)]
        env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project_dir)}
        rc, stdout, stderr, timed_out, reason = _run_with_liveness_monitor(
            argv, prompt=prompt, cwd=str(project_dir), env=env,
            idle_timeout=idle_timeout, max_sec=max_sec, poll_sec=poll_sec,
        )

    parsed, final_text = _parse_stream_json(stdout) if headless else ([], "")
    _write_subagent_trace(subagent_name, stdout, stderr)
    return SubagentResult(
        exit_code=rc, stdout=stdout, stderr=stderr,
        parsed_messages=parsed, final_text=final_text,
        timed_out=timed_out, timeout_reason=reason,
    )
