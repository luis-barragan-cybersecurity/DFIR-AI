"""session_finalize — final state.json, closing audit + message events."""
from __future__ import annotations

from pathlib import Path

from ..persistence import append_history, write_checkpoint
from ..state import IncidentState


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    state["phase"] = "lessons"
    state["_node_history"].append("session_finalize")
    record_audit(state, event="session_complete",
                 data={"node_history": state["_node_history"]})
    emit_message(state, from_agent="orchestrator", to_agent="orchestrator",
                 role="lifecycle",
                 content=f"session_finalize — {len(state['_node_history'])} nodes ran")
    write_checkpoint(state, out)
    append_history(state, out, node="session_finalize")
    return state
