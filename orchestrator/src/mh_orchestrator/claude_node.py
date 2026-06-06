"""Subprocess wrapper for invoking a Claude Code subagent.

Mirrors `bin/mh:claude_run` — same MCP config layout, same allowedTools wiring,
same auth inheritance — but designed for non-interactive (headless) calls
from inside a LangGraph node.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class HeadlessBillingError(RuntimeError):
    """Raised when `claude -p` fails specifically because headless mode
    is gated by billing (separate API credit pool, distinct from the
    subscription / Max bucket). Distinct from generic subagent failure so
    the orchestrator-level catch can surface a clear ``rerun in --interactive``
    hint instead of generic exit-code error.

    Detection is heuristic: the wrapper greps the combined stdout+stderr
    for substrings like "credit balance", "out of credits", "api credits",
    "402 Payment Required", etc. Liberal on purpose — the exact Anthropic
    wording varies across CLI versions.
    """


# Liberal regex — matches the most common billing-error substrings. False
# positives are fine here; a false positive just means the orchestrator
# raises HeadlessBillingError and the user gets a "re-run with --interactive"
# hint, which is the same advice they'd get from any other -p failure mode.
_BILLING_RE = re.compile(
    r"(credit balance|out of credits|api credits|insufficient credits"
    r"|payment required|\b402\b|requires.*credits|requires.*api.*key"
    r"|headless.*not.*available|need.*top.*up|billing.*required)",
    re.IGNORECASE,
)


def _looks_like_billing(text: str) -> bool:
    """Return True if `text` contains a billing-shaped error marker."""
    return bool(text) and bool(_BILLING_RE.search(text))


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
    """Invoke a named Claude Code subagent. Returns parsed stream-json messages.

    Side effect: emits live-action signals to ``tui`` when present (TUI is
    a no-op singleton when MH_QUIET=1, so this is safe in tests/CI)."""
    from . import tui

    argv: list[str] = ["claude"]
    if headless:
        argv += ["-p", "--output-format", "stream-json", "--verbose"]
    if mcp_config_path is not None:
        argv += ["--mcp-config", str(mcp_config_path)]
    if allowed_tools:
        argv += ["--allowedTools", ",".join(allowed_tools)]
    full_prompt = f"Use the {subagent_name} subagent. {prompt}"

    tui.update_state(subagent=subagent_name)
    tui.now(f"{subagent_name} · spawning claude -p subprocess",
            f"timeout {timeout_sec}s · allowed tools: {len(allowed_tools)}")

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
            # Mirror notable events into the TUI's NOW area so the demo
            # video shows tool calls happening in real time. Best-effort
            # only — never break on a malformed message.
            try:
                _tui_mirror(tui, subagent_name, msg)
            except Exception:  # noqa: BLE001
                pass
            if msg.get("type") == "result" and msg.get("subtype") == "success":
                final_text = msg.get("result", "") or ""

    # Defense-in-depth: if the subprocess exited non-zero AND the combined
    # output looks like a billing/credit error, raise HeadlessBillingError so
    # the caller (analyze/triage/verifier_pass nodes) can surface a clean
    # message instead of a generic RuntimeError. The preflight in bin/mh
    # should catch this case before the orchestrator starts, but this
    # protects the mid-run case where the preflight passed but credits
    # ran out partway through.
    if proc.returncode != 0:
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if _looks_like_billing(combined):
            raise HeadlessBillingError(
                f"claude -p exit={proc.returncode} with billing-shaped error. "
                f"Re-run with --interactive (subscription path) or top up at "
                f"https://console.anthropic.com/billing. "
                f"Output excerpt: {combined[:300]!r}"
            )

    return SubagentResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        parsed_messages=parsed,
        final_text=final_text,
    )


def _tui_mirror(tui_mod, subagent_name: str, msg: dict[str, Any]) -> None:
    """Translate one stream-json message into a TUI NOW update.

    stream-json schema (relevant subset):
      {type: "system", subtype: "init"}                 → handshake done
      {type: "assistant", message: {content: [...]}}   → model spoke or
                                                          called a tool
      {type: "user", message: {content: [tool_result]}}→ tool returned
      {type: "result", subtype: "success"|"error"}     → run complete
    """
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
                # First non-trivial value is usually the most informative
                # (path / plugin / query). Truncated for screen width.
                argv_summary = " · ".join(
                    f"{k}={str(v)[:40]}" for k, v in list(inputs.items())[:2]
                )
                tui_mod.now(
                    f"{subagent_name} · calling {tool}",
                    argv_summary or "(no args)",
                )
                return
            if btype == "text":
                snippet = (block.get("text") or "").strip().splitlines()
                if snippet:
                    tui_mod.now(
                        f"{subagent_name} · model speaking",
                        snippet[0][:80],
                    )
                    return
    elif t == "user":
        content = (msg.get("message") or {}).get("content") or []
        for block in content:
            if block.get("type") == "tool_result":
                is_error = block.get("is_error", False)
                tui_mod.now(
                    f"{subagent_name} · tool returned"
                    + (" (ERROR)" if is_error else ""),
                    "processing result",
                )
                return
    elif t == "result":
        sub = msg.get("subtype", "")
        tui_mod.now(f"{subagent_name} · result · {sub}",
                    "subagent finished")
