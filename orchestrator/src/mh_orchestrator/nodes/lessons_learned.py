"""lessons_learned node — markdown writeup synthesizing the incident.

Pulls case_id, severity, attack_techniques, kill_chain_stage, and per-phase
recommendation counts from state and renders a human-readable markdown
report at <output>/lessons_learned.md.

Marks GV.OV-01 (Governance Oversight). Sets iso27035_phase='learn_lessons'.
"""
from __future__ import annotations

from pathlib import Path

from .. import csf_tags
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "lessons_learned"


def _phases_completed(state: IncidentState) -> list[str]:
    history = state.get("_node_history", []) or []
    candidates = ["triage", "analyze", "contain", "eradicate", "recover"]
    return [phase for phase in candidates if phase in history]


def _gaps(state: IncidentState) -> list[str]:
    gaps: list[str] = []
    if not state.get("d3fend_recommendations"):
        gaps.append(
            "D3FEND recommendations empty (Sub-Plan 04 deferred — stub backed)"
        )
    if not state.get("attack_techniques"):
        gaps.append("No ATT&CK techniques extracted from findings")
    if not state.get("_findings"):
        gaps.append("No findings recorded by specialist subagents")
    return gaps


def _action_items(state: IncidentState) -> list[str]:
    plan = state.get("remediation_plan", []) or []
    if plan:
        return [f"{c.get('control_id', '?')}: {c.get('action', '')}" for c in plan]
    return ["Populate remediation_plan in next IR cycle"]


def _render(state: IncidentState) -> str:
    case_id = state["incident_id"]
    severity = state.get("severity", "low")
    detected_os = state.get("_detected_os", "unknown")
    findings_n = len(state.get("_findings", []) or [])
    kc_stage = state.get("kill_chain_stage", 0)
    techniques = state.get("attack_techniques", []) or []
    contain_n = len(state.get("containment_actions", []) or [])
    eradicate_n = len(state.get("eradication_actions", []) or [])
    recover_n = len(state.get("recovery_actions", []) or [])

    phases = _phases_completed(state)
    phases_block = "\n".join(f"- {p}" for p in phases) if phases else "- (none)"

    gaps = _gaps(state)
    gaps_block = "\n".join(f"- {g}" for g in gaps) if gaps else "- (none)"

    actions = _action_items(state)
    actions_block = "\n".join(f"- {a}" for a in actions)

    return (
        f"# Lessons Learned — {case_id}\n"
        "\n"
        "## Incident Summary\n"
        f"- Severity: {severity}\n"
        f"- Detected OS: {detected_os}\n"
        f"- Findings: {findings_n}\n"
        f"- Kill-chain stage reached: {kc_stage}\n"
        f"- ATT&CK techniques observed: {techniques}\n"
        f"- Containment recommendations: {contain_n}\n"
        f"- Eradication recommendations: {eradicate_n}\n"
        f"- Recovery recommendations: {recover_n}\n"
        "\n"
        "## What Worked\n"
        f"{phases_block}\n"
        "\n"
        "## What Did Not Work\n"
        f"{gaps_block}\n"
        "\n"
        "## Action Items\n"
        f"{actions_block}\n"
    )


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    out.mkdir(parents=True, exist_ok=True)
    md = _render(state)
    (out / "lessons_learned.md").write_text(md)

    state["phase"] = "lessons"
    csf_tags.mark_satisfied(state, csf_tags.GV_OV_01)
    state["iso27035_phase"] = "learn_lessons"
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="lessons_learned_complete",
        data={"writeup_chars": len(md),
              "techniques": list(state.get("attack_techniques", []) or []),
              "findings_count": len(state.get("_findings", []) or [])},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"lessons_learned: writeup rendered ({len(md)} chars)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
