"""contain node — NIST SP 800-61 §5.1 containment recommendations.

Advisory-only: emits a fixed set of recommendations (short-term isolate,
system-backup before remediation, long-term credential rotation), scores
blast radius per recommendation, and stores the maximum on state for the
reversibility gate (route_after_contain). NEVER executes any host change.

Marks RS.MI-01 (Incidents are contained). Sets phase='contain'.
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import csf_tags, picerl
from ..blast_radius import BlastRadius
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "contain"


def _distinct_user_count(state: IncidentState) -> int:
    """Count distinct users referenced across finding pins; default 1."""
    users: set[str] = set()
    for f in state.get("_findings", []) or []:
        for pin in f.get("pins", []) or []:
            user = pin.get("user")
            if user:
                users.add(user)
    return len(users) or 1


def _build_recommendations(state: IncidentState) -> list[dict]:
    user_n = _distinct_user_count(state)
    recs: list[tuple[str, str, BlastRadius]] = [
        (
            "short_term",
            "Isolate affected host from network",
            BlastRadius(hosts_affected=1, users_affected=0, services_affected=2),
        ),
        (
            "system_backup",
            "Capture full disk + memory image of affected host before remediation",
            BlastRadius(hosts_affected=1, users_affected=0, services_affected=0),
        ),
        (
            "long_term",
            "Rotate credentials for impacted user accounts",
            BlastRadius(hosts_affected=0, users_affected=user_n, services_affected=1),
        ),
    ]
    out: list[dict] = []
    for idx, (tactic, action, br) in enumerate(recs, start=1):
        out.append({
            "id": f"CONTAIN-{idx}",
            "tactic": tactic,
            "action": action,
            "blast_radius": {
                "hosts": br.hosts_affected,
                "users": br.users_affected,
                "services": br.services_affected,
                "score": br.score(),
            },
            "advisory_only": True,
        })
    return out


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    recs = _build_recommendations(state)

    # Defensive init — supports states deserialized from older snapshots.
    if "containment_actions" not in state:
        state["containment_actions"] = []
    state["containment_actions"].extend(recs)

    # Persist newly emitted recs as JSONL (append, one per line).
    actions_path = out / "containment_actions.jsonl"
    out.mkdir(parents=True, exist_ok=True)
    with actions_path.open("a") as f:
        for rec in recs:
            f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")

    max_score = max(rec["blast_radius"]["score"] for rec in recs)
    # Track running max across multiple invocations.
    current_max = state.get("_max_blast_score", 0) or 0
    state["_max_blast_score"] = max(current_max, max_score)

    state["phase"] = "contain"
    csf_tags.mark_satisfied(state, csf_tags.RS_MI_01)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("contain"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="contain_complete",
        data={"recommendations": len(recs),
              "max_blast_score": state["_max_blast_score"],
              "advisory_only": True},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"contain: {len(recs)} advisory recommendations (max blast={max_score})",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
