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
    if "_compliance_gaps" not in state:
        state["_compliance_gaps"] = []

    new_recs = lookup_all(state, techniques)
    state["d3fend_recommendations"].extend(new_recs)

    # Honesty fix (#10): the crosswalk emits `d3fend_crosswalk_miss` audit
    # events for techniques it can't map, but those misses never reached the
    # operator-facing narrative or compliance map — the gap was silent. Track
    # them on state so session_finalize can render an explicit
    # "D3FEND coverage gaps" section in incident_summary.md.
    covered_attack_ids = {r.attack_id_satisfied for r in new_recs if r.attack_id_satisfied}
    for t in techniques:
        if t not in covered_attack_ids and not any(
            existing.get("technique_id") == t for existing in state["_compliance_gaps"]
        ):
            state["_compliance_gaps"].append({
                "framework": "MITRE D3FEND",
                "kind": "no_countermeasure_in_crosswalk",
                "technique_id": t,
                "note": "D3FEND crosswalk has no countermeasure mapping for this technique",
            })

    state["phase"] = "analyze"
    picerl.advance_iso27035(state, picerl.picerl_phase_for("d3fend_recommend"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="d3fend_recommend_complete",
        data={"techniques": list(techniques),
              "added_recommendations": len(new_recs),
              "total_recommendations": len(state["d3fend_recommendations"]),
              "compliance_gaps": len(state["_compliance_gaps"])},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"d3fend_recommend: +{len(new_recs)} countermeasures (crosswalk)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
