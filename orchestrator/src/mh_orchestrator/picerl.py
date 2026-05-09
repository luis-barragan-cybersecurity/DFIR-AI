"""PICERL phase tracker + ISO 27035 mapper.

Maps LangGraph node names to SANS PICERL 6-phase model (Plans/IR_FRAMEWORKS_REFERENCE.md §5).
Maps PICERL phases to ISO/IEC 27035 5-phase governance overlay (§10.1).
"""
from __future__ import annotations

from .state import IncidentState

# §5.1 — SANS PICERL 6 phases
NODE_TO_PICERL: dict[str, str] = {
    "session_init": "preparation",
    "detect": "identification",
    "triage": "identification",
    "declare_incident": "identification",
    "suppress": "identification",
    "analyze": "identification",
    "attack_tag": "identification",
    "kill_chain_classify": "identification",
    "d3fend_recommend": "containment",
    "contain": "containment",
    "eradicate": "eradication",
    "recover": "recovery",
    "lessons_learned": "lessons_learned",
    "remediation_plan": "lessons_learned",
    "verifier_pass": "identification",
    "human_in_loop": "containment",
    "session_finalize": "lessons_learned",
}

# §10.1 — ISO/IEC 27035-1:2023 5 phases
PICERL_TO_ISO27035: dict[str, str] = {
    "preparation": "plan_and_prepare",
    "identification": "detection_and_reporting",
    "containment": "responses",
    "eradication": "responses",
    "recovery": "responses",
    "lessons_learned": "learn_lessons",
}


def picerl_phase_for(node_name: str) -> str:
    """Return SANS PICERL phase for a LangGraph node. Unknown nodes → 'identification'."""
    return NODE_TO_PICERL.get(node_name, "identification")


def advance_iso27035(state: IncidentState, picerl_phase: str) -> None:
    """Set state['iso27035_phase'] for the given PICERL phase. Unknown phases → no-op."""
    iso = PICERL_TO_ISO27035.get(picerl_phase)
    if iso is not None:
        state["iso27035_phase"] = iso
