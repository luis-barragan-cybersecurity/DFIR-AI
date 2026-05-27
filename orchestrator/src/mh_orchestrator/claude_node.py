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
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


def invoke_subagent(
    *,
    subagent_name: str,
    prompt: str,
    allowed_tools: list[str] | None = None,
    headless: bool = True,
    timeout_sec: int = 600,
) -> SubagentResult:
    """Invoke a named Claude Code subagent headlessly. Returns parsed messages.

    Wires the subprocess exactly like the working interactive path:
      * `--agent <subagent_name>` loads the `.claude/agents/<name>.md` persona
        (the FOR500/FOR518 playbook) — the agent's own `tools:` frontmatter is
        the source of truth for capability.
      * `--mcp-config <resolved.json>` gives the agent the protocol_sift
        forensic tools (built from the orchestrator env at call time).
      * `CLAUDE_PROJECT_DIR` exported + cwd = project root so `.claude/agents/`
        and the mh-mcp-server command resolve.
    """
    project_dir = _resolve_project_dir()
    tools = allowed_tools if allowed_tools is not None else DEFAULT_ALLOWED_TOOLS

    with tempfile.TemporaryDirectory(prefix="mh-mcp-") as td:
        mcp_cfg = _write_mcp_config(project_dir, Path(td))

        argv: list[str] = ["claude"]
        if headless:
            argv += ["-p", "--output-format", "stream-json", "--verbose"]
        # Persona: load the named agent so its system prompt + tool scope apply.
        argv += ["--agent", subagent_name]
        argv += ["--mcp-config", str(mcp_cfg)]
        if tools:
            argv += ["--allowedTools", ",".join(tools)]

        env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project_dir)}
        proc = subprocess.run(
            argv,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
            cwd=str(project_dir),
            env=env,
            check=False,
        )

    parsed: list[dict[str, Any]] = []
    final_text = ""
    if headless:
        for line in proc.stdout.splitlines():
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
    return SubagentResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        parsed_messages=parsed,
        final_text=final_text,
    )
