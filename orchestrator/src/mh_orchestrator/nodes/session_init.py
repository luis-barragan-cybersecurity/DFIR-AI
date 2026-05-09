"""session_init — opens audit + agent_messages logs."""
from __future__ import annotations

from pathlib import Path

from ..persistence import append_history, write_checkpoint
from ..state import IncidentState


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # local import avoids circular

    out = Path(state["_output_dir"])
    out.mkdir(parents=True, exist_ok=True)

    record_audit(state, event="session_started",
                 data={"incident_id": state["incident_id"]})
    emit_message(state, from_agent="orchestrator", to_agent="orchestrator",
                 role="lifecycle",
                 content=f"session_init for {state['incident_id']}")

    state["phase"] = "detect"
    state["_node_history"].append("session_init")
    write_checkpoint(state, out)
    append_history(state, out, node="session_init")
    return state
