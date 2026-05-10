"""human_in_loop node — reversibility-gate human approval pause.

Fired only when the blast-radius reversibility gate trips
(IR_FRAMEWORKS_REFERENCE §11.3 route_after_contain). Reads
state['containment_actions'], filters those whose blast-radius score exceeds
MH_BLAST_RADIUS_THRESHOLD (default blast_radius.DEFAULT_THRESHOLD), and
writes human_approval_required.json into the case output directory listing
the actions awaiting human approval.

Marks RS.MI-01 (Incidents are contained). Sets phase='contain' (still in
containment phase per §11.2). Advisory-only — never executes any action.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .. import blast_radius, csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "human_in_loop"


def _resolve_threshold() -> int:
    env = os.environ.get("MH_BLAST_RADIUS_THRESHOLD")
    if env:
        return int(env)
    return blast_radius.DEFAULT_THRESHOLD


def _action_score(action: dict[str, Any]) -> int:
    br = action.get("blast_radius") or {}
    raw = br.get("score", 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    threshold = _resolve_threshold()

    actions = state.get("containment_actions", []) or []
    over_threshold = [a for a in actions if _action_score(a) > threshold]

    payload: dict[str, Any] = {
        "case_id": state.get("incident_id", ""),
        "threshold": threshold,
        "max_blast_score": int(state.get("_max_blast_score", 0) or 0),
        "actions_requiring_approval": over_threshold,
        "advisory_only": True,
        "approval_status": "pending",
    }

    out.mkdir(parents=True, exist_ok=True)
    approval_path = out / "human_approval_required.json"
    approval_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    state["human_approval_required"] = True
    state["phase"] = "contain"
    csf_tags.mark_satisfied(state, csf_tags.RS_MI_01)
    picerl.advance_iso27035(state, picerl.picerl_phase_for(NODE_NAME))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="awaiting_approval",
        data={
            "threshold": threshold,
            "max_blast_score": payload["max_blast_score"],
            "actions_count": len(over_threshold),
            "advisory_only": True,
        },
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="human",
        role="lifecycle",
        content=(
            f"human_in_loop: {len(over_threshold)} action(s) over "
            f"blast threshold {threshold} awaiting approval"
        ),
        metadata={"approval_status": "pending", "threshold": threshold},
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
