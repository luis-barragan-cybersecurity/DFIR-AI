"""remediation node — NIST SP 800-53 IR-family controls (advisory).

Emits a hardening + IR-controls plan derived from observed ATT&CK techniques.
Writes <output>/remediation_plan.json. Sets phase='remediation'.

Controls emitted:
  - IR-4 (Incident Handling)
  - IR-5 (Incident Monitoring)
  - IR-6 (Incident Reporting)
  - IR-8 (IR Plan)
  - SI-3 (Malicious Code Protection)
  - SC-7 (Boundary Protection)
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "remediation"


def _format_techniques(state: IncidentState) -> str:
    techs = state.get("attack_techniques", []) or []
    if not techs:
        return "(none observed)"
    return ", ".join(techs)


def _build_plan(state: IncidentState) -> list[dict]:
    techs_str = _format_techniques(state)
    return [
        {
            "control_id": "IR-4",
            "family": "IR",
            "action": "Update IR playbook to include scenarios observed in this case",
            "priority": "high",
            "advisory_only": True,
        },
        {
            "control_id": "IR-5",
            "family": "IR",
            "action": f"Add detections for ATT&CK techniques: {techs_str}",
            "priority": "high",
            "advisory_only": True,
        },
        {
            "control_id": "IR-6",
            "family": "IR",
            "action": "Confirm reporting channels exercised",
            "priority": "medium",
            "advisory_only": True,
        },
        {
            "control_id": "IR-8",
            "family": "IR",
            "action": "Update IR plan with deltas from this incident",
            "priority": "medium",
            "advisory_only": True,
        },
        {
            "control_id": "SI-3",
            "family": "SI",
            "action": "Verify EDR coverage on affected hosts",
            "priority": "high",
            "advisory_only": True,
        },
        {
            "control_id": "SC-7",
            "family": "SC",
            "action": "Review network segmentation",
            "priority": "medium",
            "advisory_only": True,
        },
    ]


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    plan = _build_plan(state)

    if "remediation_plan" not in state:
        state["remediation_plan"] = []
    state["remediation_plan"].extend(plan)

    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "case_id": state["incident_id"],
        "controls": plan,
        "advisory_only": True,
    }
    (out / "remediation_plan.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
    )

    state["phase"] = "remediation"
    # NOTE: must match the key in picerl.NODE_TO_PICERL — the string
    # "remediation_plan" silently fell through to default "identification"
    # and rolled iso27035_phase back to detection_and_reporting.
    picerl.advance_iso27035(state, picerl.picerl_phase_for(NODE_NAME))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="remediation_complete",
        data={"controls": len(plan),
              "ir_controls": sum(1 for c in plan if c["family"] == "IR"),
              "advisory_only": True},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"remediation: {len(plan)} advisory controls (IR-family + hardening)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
