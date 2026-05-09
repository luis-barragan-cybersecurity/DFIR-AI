"""recover node — NIST SP 800-61 Restore-tactic recommendations + verification stub.

Advisory-only: emits a fixed set of recovery recommendations, writes a
verification stub (recovery_verification.json) the human-in-loop reviewer
can ratify, and sets the post-restore-alarms flag to False (no telemetry
hookup in skeleton).

Marks RC.RP-01 (Recovery plan executed) and RC.CO-03 (Recovery comms).
Sets phase='recover'.
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "recover"


def _build_recommendations() -> list[dict]:
    actions = [
        "Restore affected systems from clean backup taken before compromise",
        "Validate restored services with health checks before re-exposing to network",
        "Monitor restored systems for 30 days for re-compromise indicators",
    ]
    return [
        {
            "id": f"RECOVER-{idx}",
            "tactic": "restore",
            "action": action,
            "advisory_only": True,
        }
        for idx, action in enumerate(actions, start=1)
    ]


def _build_verification_steps() -> list[dict]:
    checks = [
        "Service health check",
        "Authentication smoke test",
        "Telemetry baseline comparison",
    ]
    return [
        {"id": f"VERIFY-{idx}", "check": check, "status": "pending"}
        for idx, check in enumerate(checks, start=1)
    ]


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    recs = _build_recommendations()

    if "recovery_actions" not in state:
        state["recovery_actions"] = []
    state["recovery_actions"].extend(recs)

    # Verification stub — file the human-in-loop reviewer must ratify.
    out.mkdir(parents=True, exist_ok=True)
    verify_payload = {
        "case_id": state["incident_id"],
        "verification_steps": _build_verification_steps(),
        "advisory_only": True,
    }
    (out / "recovery_verification.json").write_text(
        json.dumps(verify_payload, indent=2, sort_keys=True),
    )

    # Skeleton: no telemetry hookup → no alarms yet.
    state["_post_restore_alarms"] = False

    state["phase"] = "recover"
    csf_tags.mark_satisfied(state, csf_tags.RC_RP_01, csf_tags.RC_CO_03)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("recover"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="recover_complete",
        data={"recommendations": len(recs),
              "verification_steps": len(verify_payload["verification_steps"]),
              "post_restore_alarms": False,
              "advisory_only": True},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"recover: {len(recs)} advisory recommendations (restore)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
