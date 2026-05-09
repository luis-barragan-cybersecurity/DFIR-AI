"""eradicate node — NIST SP 800-61 Evict-tactic recommendations.

Advisory-only: emits a fixed set of eradication recommendations and sets
the reinfection-detection flag to False (no detection signal in skeleton).

Marks RS.MI-02 (Incidents are eradicated). Sets phase='eradicate'.
"""
from __future__ import annotations

from pathlib import Path

from .. import csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "eradicate"


def _build_recommendations() -> list[dict]:
    actions = [
        "Remove malicious binaries identified in findings",
        "Disable or delete unauthorized accounts",
        "Patch exploited vulnerabilities (CVE list deferred to remediation_plan)",
    ]
    return [
        {
            "id": f"ERADICATE-{idx}",
            "tactic": "evict",
            "action": action,
            "advisory_only": True,
        }
        for idx, action in enumerate(actions, start=1)
    ]


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    recs = _build_recommendations()

    if "eradication_actions" not in state:
        state["eradication_actions"] = []
    state["eradication_actions"].extend(recs)

    # Skeleton: no detection signal yet — Sub-Plan 04 may flip this.
    state["_reinfection_detected"] = False

    state["phase"] = "eradicate"
    csf_tags.mark_satisfied(state, csf_tags.RS_MI_02)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("eradicate"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="eradicate_complete",
        data={"recommendations": len(recs),
              "reinfection_detected": False,
              "advisory_only": True},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"eradicate: {len(recs)} advisory recommendations (evict)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
