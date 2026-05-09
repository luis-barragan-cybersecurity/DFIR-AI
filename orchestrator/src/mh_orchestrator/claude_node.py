"""Subprocess wrapper for invoking a Claude Code subagent.

Mirrors `bin/mh:claude_run` — same MCP config layout, same allowedTools wiring,
same auth inheritance — but designed for non-interactive (headless) calls
from inside a LangGraph node.
"""
from __future__ import annotations

import json
import os
import subprocess
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


@dataclass
class SubagentResult:
    exit_code: int
    stdout: str
    stderr: str
    parsed_messages: list[dict[str, Any]] = field(default_factory=list)
    final_text: str = ""


def invoke_subagent(
    *,
    subagent_name: str,
    prompt: str,
    case_dir: Path,
    allowed_tools: list[str],
    mcp_config_path: Path | None,
    headless: bool = True,
    timeout_sec: int = 600,
) -> SubagentResult:
    """Invoke a named Claude Code subagent. Returns parsed stream-json messages."""
    argv: list[str] = ["claude"]
    if headless:
        argv += ["-p", "--output-format", "stream-json", "--verbose"]
    if mcp_config_path is not None:
        argv += ["--mcp-config", str(mcp_config_path)]
    if allowed_tools:
        argv += ["--allowedTools", ",".join(allowed_tools)]
    full_prompt = f"Use the {subagent_name} subagent. {prompt}"
    proc = subprocess.run(
        argv,
        input=full_prompt,
        text=True,
        capture_output=True,
        timeout=timeout_sec,
        cwd=str(case_dir.parent),
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
