"""claude_dispatch — invokes a Claude Code subagent (skeleton: WindowsAgent probe).

Sub-Plan 03 will replace this with real per-OS routing. For now it issues a
trivial probe so we can prove the subprocess wrapper, MCP wiring, and message
log all work end-to-end.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..claude_node import invoke_subagent
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

ALLOWED_TOOLS = [
    "mcp__protocol_sift__hash",
    "mcp__protocol_sift__audit_append",
    "mcp__protocol_sift__os_detect",
    "Read", "Glob", "Grep", "TodoWrite",
]


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    case_dir = out.parent
    mcp_cfg_env = os.environ.get("MH_MCP_CONFIG", "")
    mcp_cfg = Path(mcp_cfg_env) if mcp_cfg_env else None

    if os.environ.get("MH_NO_CLAUDE") == "1":
        emit_message(state, from_agent="orchestrator", to_agent="WindowsAgent",
                     role="dispatch",
                     content="[skipped — MH_NO_CLAUDE=1]")
        record_audit(state, event="claude_dispatch_skipped", data={})
        state["_node_history"].append("claude_dispatch")
        write_checkpoint(state, out)
        append_history(state, out, node="claude_dispatch")
        return state

    emit_message(state, from_agent="orchestrator", to_agent="WindowsAgent",
                 role="dispatch", content="probe — confirm subagent online")
    result = invoke_subagent(
        subagent_name="WindowsAgent",
        prompt="Respond with the single word ONLINE and stop.",
        case_dir=case_dir,
        allowed_tools=ALLOWED_TOOLS,
        mcp_config_path=mcp_cfg,
        headless=True,
        timeout_sec=120,
    )
    emit_message(state, from_agent="WindowsAgent", to_agent="orchestrator",
                 role="response", content=result.final_text or "[no result]",
                 metadata={"exit_code": result.exit_code})
    record_audit(state, event="claude_dispatch_completed",
                 data={"subagent": "WindowsAgent", "exit_code": result.exit_code})

    state["_node_history"].append("claude_dispatch")
    write_checkpoint(state, out)
    append_history(state, out, node="claude_dispatch")
    return state
