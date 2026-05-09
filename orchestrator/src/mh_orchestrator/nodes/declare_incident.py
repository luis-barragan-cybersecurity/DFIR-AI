"""declare_incident node — promotes detected event to incident."""
from __future__ import annotations

from pathlib import Path

from .. import csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    state["iso27035_phase"] = "assessment_and_decision"
    csf_tags.mark_satisfied(state, csf_tags.RS_MA_01)
    state["_node_history"].append("declare_incident")
    record_audit(state, event="incident_declared",
                 data={"incident_id": state["incident_id"], "severity": state.get("severity", "medium")})
    emit_message(state, from_agent="orchestrator", to_agent="orchestrator",
                 role="lifecycle",
                 content=f"incident declared: {state['incident_id']} severity={state.get('severity', 'medium')}")
    write_checkpoint(state, out)
    append_history(state, out, node="declare_incident")
    return state
