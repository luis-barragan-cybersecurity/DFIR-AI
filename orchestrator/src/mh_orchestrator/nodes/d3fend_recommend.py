"""d3fend_recommend node — D3FEND countermeasure recommendation.

Resolves ATT&CK technique IDs to D3FEND countermeasures via the static
crosswalk in :mod:`mh_orchestrator.d3fend_crosswalk`. Unknown techniques
emit ``d3fend_crosswalk_miss`` audit events from inside the crosswalk so
coverage gaps surface in the audit log.
"""
from __future__ import annotations

from pathlib import Path

from .. import picerl
from ..d3fend_crosswalk import lookup_all
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "d3fend_recommend"


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    techniques = state.get("attack_techniques", []) or []

    # Initialize recommendations field if missing (defensive)
    if "d3fend_recommendations" not in state:
        state["d3fend_recommendations"] = []

    new_recs = lookup_all(state, techniques)
    state["d3fend_recommendations"].extend(new_recs)

    state["phase"] = "analyze"
    picerl.advance_iso27035(state, picerl.picerl_phase_for("d3fend_recommend"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="d3fend_recommend_complete",
        data={"techniques": list(techniques),
              "added_recommendations": len(new_recs),
              "total_recommendations": len(state["d3fend_recommendations"])},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"d3fend_recommend: +{len(new_recs)} countermeasures (crosswalk)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
