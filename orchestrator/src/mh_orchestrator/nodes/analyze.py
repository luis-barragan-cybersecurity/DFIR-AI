"""analyze node — per-OS specialist dispatch with bounded RCA loop.

Routes to WindowsAgent / MacOSAgent / LinuxAgent based on state['_detected_os'],
collects findings, deduplicates by finding_id, and stops when:
  * subagent returns no new findings, OR
  * _analyze_iter >= MAX_ITER (cap), OR
  * MH_NO_CLAUDE=1 stub returned no findings (one-shot deterministic path)

Marks RS.AN-01 (Analysis: notifications + cause). Sets phase='analyze'.
"""
from __future__ import annotations

import json
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
    "mcp__protocol_sift__magic_check",
    "mcp__protocol_sift__memory_volatility",
    "mcp__protocol_sift__linux_history_parse",
    "mcp__protocol_sift__win_registry_get",
    "mcp__protocol_sift__win_evtx_query",
    "mcp__protocol_sift__win_prefetch_parse",
    "mcp__protocol_sift__win_lnk_parse",
    "mcp__protocol_sift__mac_plist_get",
    "mcp__protocol_sift__audit_append",
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

        evidence_dir = case_dir / "input"
        evidence_listing = "\n".join(
            f"  - {p.name} ({p.stat().st_size} bytes)"
            for p in sorted(evidence_dir.iterdir()) if p.exists()
        ) if evidence_dir.exists() else "  (no evidence files found)"
        prompt = (
            f"Case: {case_dir.name}\n"
            f"Detected OS: {state.get('_detected_os', 'unknown')}\n"
            f"Severity: {state.get('severity', 'unknown')}\n"
            f"Iteration: {iter_num}\n\n"
            f"Evidence files under {evidence_dir}/:\n{evidence_listing}\n\n"
            "Analyze the evidence for root cause and IOCs. Use the per-OS "
            "MCP forensic tools available to you (e.g., mcp__protocol_sift__"
            "memory_volatility for memory dumps, mcp__protocol_sift__linux_"
            "history_parse for shell history, mcp__protocol_sift__win_* for "
            "Windows artifacts). For memory dumps, run plugins like "
            "linux.pslist / windows.pslist / linux.bash. Record EVERY "
            "finding via mcp__protocol_sift__finding_record with: claim, "
            "confidence, confidence_rationale (one sentence in the form "
            "'X because Y' justifying the chosen confidence), and >=1 pin. "
            "Tag MITRE ATT&CK techniques (T####) in the claim text where "
            "relevant. Reply with one line: DONE."
        )
        result = invoke_subagent(
            subagent_name=subagent,
            prompt=prompt,
            case_dir=case_dir,
            allowed_tools=ALLOWED_TOOLS,
            mcp_config_path=None,
            headless=True,
            timeout_sec=1200,
        )
        if result.exit_code != 0:
            record_audit(
                state, event="analyze_subagent_failed",
                data={"subagent": subagent, "iter": iter_num,
                      "exit_code": result.exit_code,
                      "stderr": (result.final_text or "")[:500]},
            )
            raise RuntimeError(
                f"analyze subagent {subagent!r} failed at iter {iter_num}: "
                f"exit_code={result.exit_code}"
            )
        # Findings are recorded out-of-band by the subagent via the
        # finding_record MCP tool, which writes to <output>/findings.json
        # (mcp-server/tools/finding.py). Re-read that file each iteration
        # to surface any new entries into state["_findings"].
        new_findings: list[dict] = []
        findings_path = Path(state["_output_dir"]) / "findings.json"
        if findings_path.exists():
            try:
                raw = json.loads(findings_path.read_text())
                if isinstance(raw, list):
                    new_findings = raw
                elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
                    new_findings = raw["findings"]
            except (json.JSONDecodeError, OSError):
                new_findings = []
        added = _merge_findings(state, new_findings)
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
