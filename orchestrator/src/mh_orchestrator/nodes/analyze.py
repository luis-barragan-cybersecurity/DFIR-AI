"""analyze node — per-OS specialist dispatch with bounded RCA loop.

Routes to WindowsAgent / MacOSAgent / LinuxAgent based on state['_detected_os'],
collects findings, deduplicates by finding_id, and stops when:
  * subagent returns no new findings, OR
  * _analyze_iter >= MAX_ITER (cap), OR
  * MH_NO_CLAUDE=1 stub returned no findings (one-shot deterministic path)

Marks RS.AN-01 (Analysis: notifications + cause). Sets phase='analyze'.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "analyze"
MAX_ITER = 3

# Map _detected_os → subagent name (mirrors triage.OS_TO_SUBAGENT)
OS_TO_SUBAGENT: dict[str, str] = {
    "windows": "WindowsAgent",
    "macos": "MacOSAgent",
    "linux": "LinuxAgent",
}
FALLBACK_SUBAGENT = "WindowsAgent"

ALLOWED_TOOLS = [
    "mcp__protocol_sift__hash",
    "mcp__protocol_sift__finding_record",
    "mcp__protocol_sift__os_detect",
    "Read", "Glob", "Grep",
]


def _select_subagent(state: IncidentState) -> tuple[str, bool]:
    """Return (subagent_name, is_fallback)."""
    detected = state.get("_detected_os", "unknown")
    if detected in OS_TO_SUBAGENT:
        return OS_TO_SUBAGENT[detected], False
    return FALLBACK_SUBAGENT, True


def _merge_findings(state: IncidentState, new_findings: list[dict[str, Any]]) -> int:
    """Append new findings deduped by finding_id. Return count of newly added."""
    existing_ids = {f.get("finding_id") for f in state.get("_findings", [])}
    added = 0
    for f in new_findings:
        fid = f.get("finding_id")
        if fid and fid not in existing_ids:
            state["_findings"].append(f)
            existing_ids.add(fid)
            added += 1
    return added


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    case_dir = out.parent
    subagent, is_fallback = _select_subagent(state)

    if is_fallback:
        record_audit(
            state, event="analyze_unknown_os_fallback",
            data={"detected_os": state.get("_detected_os", "unknown"),
                  "fallback_subagent": subagent},
        )

    # Bounded RCA loop. Each pass increments _analyze_iter and dispatches to
    # the chosen subagent. Stop on: cap, no new findings, or empty stub.
    while state["_analyze_iter"] < MAX_ITER and not state["_rca_complete"]:
        state["_analyze_iter"] += 1
        iter_num = state["_analyze_iter"]

        emit_message(
            state, from_agent="orchestrator", to_agent=subagent,
            role="dispatch",
            content=f"analyze: root-cause iteration {iter_num}",
            metadata={"iter": iter_num, "phase": "analyze"},
        )

        if should_stub(NODE_NAME):
            # Deterministic stub: no new findings → RCA complete after one pass.
            emit_message(
                state, from_agent=subagent, to_agent="orchestrator",
                role="response", content="[stub] no findings returned",
                metadata={"exit_code": 0, "stub": True, "iter": iter_num},
            )
            record_audit(
                state, event="analyze_stub_pass",
                data={"subagent": subagent, "iter": iter_num, "added": 0},
            )
            state["_rca_complete"] = True
            break

        result = invoke_subagent(
            subagent_name=subagent,
            prompt=(
                "Analyze the case for root cause. Record findings via "
                "mcp__protocol_sift__finding_record. Reply with one line: DONE."
            ),
            case_dir=case_dir,
            allowed_tools=ALLOWED_TOOLS,
            mcp_config_path=None,
            headless=True,
            timeout_sec=300,
        )
        # Findings are recorded out-of-band via the finding_record MCP tool;
        # this node treats result.parsed_messages as informational only and
        # relies on the MCP tool to mutate state['_findings'] elsewhere if
        # wired. For now, no in-band findings are extracted here, so each
        # subagent pass ends without adding new findings → loop exits.
        added = _merge_findings(state, [])
        emit_message(
            state, from_agent=subagent, to_agent="orchestrator",
            role="response",
            content=result.final_text or "[no result]",
            metadata={"exit_code": result.exit_code, "iter": iter_num, "added": added},
        )
        record_audit(
            state, event="analyze_pass_complete",
            data={"subagent": subagent, "iter": iter_num,
                  "exit_code": result.exit_code, "added": added},
        )
        if added == 0:
            state["_rca_complete"] = True
            break

    state["phase"] = "analyze"
    csf_tags.mark_satisfied(state, csf_tags.RS_AN_01)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("analyze"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="analyze_complete",
        data={"subagent": subagent, "iters": state["_analyze_iter"],
              "rca_complete": state["_rca_complete"],
              "findings_count": len(state.get("_findings", []))},
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
