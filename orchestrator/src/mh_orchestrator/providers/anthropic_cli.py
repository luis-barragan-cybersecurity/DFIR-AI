"""Anthropic Claude Code CLI provider.

Wraps the existing ``claude -p`` subprocess pattern that's been MemoryHound's
only AI engine since day one. Behaviour MUST stay bit-identical to the
pre-refactor ``claude_node.invoke_subagent`` — same MCP config layout, same
``--agent`` wiring, same liveness monitor, same stream-json parsing, same
``HeadlessBillingError`` heuristic. The refactor just relocates the code; it
does not change what runs.

If you change something here, also update the parity test
(``test_anthropic_cli_parity.py``) — it pins this provider against the
captured pre-refactor behaviour.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import proc_activity
from .base import HeadlessBillingError, Provider, SubagentResult

# Liberal regex — matches the most common billing-error substrings. False
# positives are fine; a false positive just means the orchestrator raises
# HeadlessBillingError and the user gets a "re-run with --interactive" hint,
# which is the same advice any other -p failure mode gets.
_BILLING_RE = re.compile(
    r"(credit balance|out of credits|api credits|insufficient credits"
    r"|payment required|\b402\b|requires.*credits|requires.*api.*key"
    r"|headless.*not.*available|need.*top.*up|billing.*required)",
    re.IGNORECASE,
)


def _looks_like_billing(text: str) -> bool:
    return bool(text) and bool(_BILLING_RE.search(text))


# Default tool allowlist. `mcp__protocol_sift` (bare server name) is the
# canonical Claude Code form for "allow EVERY tool from this MCP server" —
# drift-proof as the server grows. Bash is omitted here — but note that
# `--allowedTools` is ADDITIVE, so omission alone does NOT withhold Bash; see
# DISALLOWED_TOOLS below for the flag that actually does.
DEFAULT_ALLOWED_TOOLS: list[str] = [
    "mcp__protocol_sift",
    "Read", "Glob", "Grep", "Write", "TodoWrite", "Skill",
]

# Tools SUBTRACTED from every subagent at spawn. `--allowedTools` is ADDITIVE —
# listing only MCP/Read/Glob/Grep above does NOT remove Bash from the inherited
# default toolset (confirmed against the system/init event). `--disallowedTools`
# is the one flag that actually withholds a tool. Bash is denied because it is the
# single error-prone tool that triggers the harness parallel-tool-call
# cancellation cascade, AND because it lets a "read-only" specialist escape the
# evidence sandbox (cd out of /input, read non-evidence files) outside the MCP
# audit trail — a chain-of-custody breach. Edit/Write/WebSearch hardening is a
# deliberate follow-up (Write is intentionally on the allowlist above).
DISALLOWED_TOOLS: list[str] = ["Bash"]


def _resolve_project_dir() -> Path:
    """Return the project root.

    Resolution order:
      1. ``MH_HOME`` env var — set by ``bin/mh run`` and by ``cli._cmd_run``.
      2. Walk up from this module's ``__file__`` looking for a marker that
         identifies the project root (``.claude/settings.json`` AND
         ``bin/mh-mcp-server``). Defensive fallback for tests + direct module
         use + the ``mh-orchestrate`` CLI which historically didn't export
         MH_HOME.
      3. Raise — refuse to spawn a tool-less subagent that would silently
         produce nothing.
    """
    mh_home = os.environ.get("MH_HOME")
    if mh_home:
        return Path(mh_home)
    candidate = Path(__file__).resolve()
    for parent in (candidate, *candidate.parents):
        if (parent / ".claude" / "settings.json").exists() and \
                (parent / "bin" / "mh-mcp-server").exists():
            return parent
    raise RuntimeError(
        "MH_HOME not set and could not auto-derive project root — "
        "invoke_subagent must run under `bin/mh run` or `mh-orchestrate run` "
        "(both export MH_HOME). Refusing to spawn a subagent with no "
        "protocol_sift MCP config.",
    )


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
    """SIGTERM the whole process group, grace, then SIGKILL."""
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
            break
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


def _write_subagent_trace(subagent_name: str, stdout: str, stderr: str) -> None:
    """Persist subagent subprocess stdout/stderr to <OUTPUT_PATH>/_trace/.

    No-op when OUTPUT_PATH is unset. Failures are swallowed.
    """
    output_path = os.environ.get("OUTPUT_PATH")
    if not output_path:
        return
    try:
        trace_dir = Path(output_path) / "_trace"
        trace_dir.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "_", subagent_name.lower()).strip("_") or "subagent"
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        (trace_dir / f"{slug}_{ts}.stdout.jsonl").write_text(stdout)
        (trace_dir / f"{slug}_{ts}.stderr.log").write_text(stderr)
    except OSError:
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


def _tui_mirror(tui_mod, subagent_name: str, msg: dict[str, Any]) -> None:
    """Translate one stream-json message into a TUI NOW update."""
    t = msg.get("type")
    if t == "system" and msg.get("subtype") == "init":
        tui_mod.now(f"{subagent_name} · session initialized",
                    "subagent loaded · ready for tool calls")
        return
    if t == "assistant":
        content = (msg.get("message") or {}).get("content") or []
        for block in content:
            btype = block.get("type")
            if btype == "tool_use":
                tool = block.get("name", "?")
                inputs = block.get("input") or {}
                argv_summary = " · ".join(
                    f"{k}={str(v)[:40]}" for k, v in list(inputs.items())[:2]
                )
                tui_mod.now(f"{subagent_name} · calling {tool}", argv_summary or "(no args)")
                return
            if btype == "text":
                snippet = (block.get("text") or "").strip().splitlines()
                if snippet:
                    tui_mod.now(f"{subagent_name} · model speaking", snippet[0][:80])
                    return
    elif t == "user":
        content = (msg.get("message") or {}).get("content") or []
        for block in content:
            if block.get("type") == "tool_result":
                is_error = block.get("is_error", False)
                tui_mod.now(
                    f"{subagent_name} · tool returned" + (" (ERROR)" if is_error else ""),
                    "processing result",
                )
                return
    elif t == "result":
        sub = msg.get("subtype", "")
        tui_mod.now(f"{subagent_name} · result · {sub}", "subagent finished")


class AnthropicCliProvider(Provider):
    """Drive Claude Code via the ``claude -p`` subprocess.

    Preserves the entire pre-refactor invoke_subagent behaviour: project-root
    resolution, MCP config write, --agent persona, --allowedTools wiring,
    liveness monitor, stream-json parse, TUI mirroring, billing-error sniff,
    trace persistence.
    """

    name = "anthropic-cli"

    def invoke(
        self,
        *,
        subagent_name: str,
        prompt: str,
        allowed_tools: list[str] | None = None,
        headless: bool = True,
    ) -> SubagentResult:
        from .. import tui  # local import — TUI module may not be available in CI

        project_dir = _resolve_project_dir()
        tools = allowed_tools if allowed_tools is not None else DEFAULT_ALLOWED_TOOLS
        idle_timeout = _env_float("MH_SUBAGENT_IDLE_TIMEOUT_SEC", 600.0)
        max_sec = _env_float("MH_SUBAGENT_MAX_SEC", 7200.0)
        poll_sec = _env_float("MH_SUBAGENT_POLL_SEC", 15.0)

        try:
            tui.update_state(subagent=subagent_name)
            tui.now(
                f"{subagent_name} · spawning claude -p subprocess",
                f"idle_timeout={idle_timeout:.0f}s · max={max_sec:.0f}s · tools: {len(tools)}",
            )
        except Exception:  # noqa: BLE001
            pass

        with tempfile.TemporaryDirectory(prefix="mh-mcp-") as td:
            mcp_cfg = _write_mcp_config(project_dir, Path(td))
            argv: list[str] = ["claude"]
            if headless:
                argv += ["-p", "--output-format", "stream-json", "--verbose"]
            # --strict-mcp-config: --mcp-config alone is ADDITIVE, so the spawn
            # would also inherit every user-scope MCP server (claude.ai
            # Drive/Calendar/Notion connectors — seen in real trace init events).
            # That leak is a latent hang (a connector tool call outside
            # --allowedTools hangs headless until the idle-timeout kill), a
            # chain-of-custody wart (forensic specialist holding live external
            # connections), and context noise. Restrict to exactly our config.
            argv += [
                "--agent", subagent_name,
                "--mcp-config", str(mcp_cfg),
                "--strict-mcp-config",
            ]
            if tools:
                argv += ["--allowedTools", ",".join(tools)]
            # SUBTRACTIVE deny — the additive --allowedTools above cannot withhold
            # Bash; this is what actually keeps it out of the spawned toolset.
            argv += ["--disallowedTools", ",".join(DISALLOWED_TOOLS)]
            env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project_dir)}
            rc, stdout, stderr, timed_out, reason = _run_with_liveness_monitor(
                argv, prompt=prompt, cwd=str(project_dir), env=env,
                idle_timeout=idle_timeout, max_sec=max_sec, poll_sec=poll_sec,
            )

        parsed, final_text = _parse_stream_json(stdout) if headless else ([], "")
        _write_subagent_trace(subagent_name, stdout, stderr)

        try:
            if timed_out:
                tui.now(
                    f"{subagent_name} · timed out ({reason})",
                    "recorded as dissent · check audit.jsonl for the trace",
                )
            else:
                tui.now(
                    f"{subagent_name} · subagent returned (exit {rc})",
                    f"messages: {len(parsed)} · final_text: {len(final_text)} chars",
                )
            for msg in parsed:
                try:
                    _tui_mirror(tui, subagent_name, msg)
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass

        if rc != 0 and not timed_out:
            combined = (stdout or "") + "\n" + (stderr or "")
            if _looks_like_billing(combined):
                raise HeadlessBillingError(
                    f"claude -p exit={rc} with billing-shaped error. "
                    f"Re-run with --interactive (subscription path) or top up at "
                    f"https://console.anthropic.com/billing. "
                    f"Output excerpt: {combined[:300]!r}"
                )

        return SubagentResult(
            exit_code=rc, stdout=stdout, stderr=stderr,
            parsed_messages=parsed, final_text=final_text,
            timed_out=timed_out, timeout_reason=reason,
        )
