"""suppress node — terminal: false-positive path; routes to END."""
from __future__ import annotations

from pathlib import Path

from .. import picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    state["phase"] = "lessons"
    picerl.advance_iso27035(state, picerl.picerl_phase_for("suppress"))
    state["_node_history"].append("suppress")
    record_audit(state, event="false_positive_suppressed",
                 data={"severity": state.get("severity", "low")})
    emit_message(state, from_agent="orchestrator", to_agent="orchestrator",
                 role="lifecycle",
                 content=f"suppressed: severity={state.get('severity', 'low')}")
    write_checkpoint(state, out)
    append_history(state, out, node="suppress")
    return state
