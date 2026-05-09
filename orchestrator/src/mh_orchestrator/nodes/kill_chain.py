"""kill_chain node — Lockheed Martin Cyber Kill Chain stage classification.

Maps MITRE ATT&CK technique IDs in state['attack_techniques'] to one of the
seven Cyber Kill Chain stages and sets state['kill_chain_stage'] to the MAX
stage observed (highest progression in the chain wins).

Stages:
  1 Reconnaissance  2 Weaponization  3 Delivery  4 Exploitation
  5 Installation    6 Command & Control          7 Actions on Objectives
"""
from __future__ import annotations

from pathlib import Path

from .. import picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "kill_chain"

# Static mapping per the Lockheed Martin Cyber Kill Chain. Subtechnique
# suffixes (e.g. T1059.001) are stripped before lookup.
TECHNIQUE_TO_STAGE: dict[str, int] = {
    # 1: Reconnaissance
    "T1592": 1, "T1589": 1, "T1590": 1,
    # 2: Weaponization
    "T1587": 2, "T1588": 2,
    # 3: Delivery
    "T1566": 3, "T1190": 3, "T1133": 3,
    # 4: Exploitation
    "T1203": 4, "T1059": 4, "T1068": 4,
    # 5: Installation
    "T1547": 5, "T1543": 5, "T1546": 5,
    # 6: Command & Control
    "T1071": 6, "T1095": 6, "T1573": 6,
    # 7: Actions on Objectives
    "T1486": 7, "T1485": 7, "T1567": 7, "T1041": 7,
}


def _base_technique(tid: str) -> str:
    """Strip subtechnique suffix: 'T1059.001' → 'T1059'."""
    return tid.split(".", 1)[0]


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    techniques = state.get("attack_techniques", []) or []

    current_stage = state.get("kill_chain_stage", 0) or 0
    max_stage = current_stage
    matched: list[tuple[str, int]] = []
    for tid in techniques:
        base = _base_technique(tid)
        stage = TECHNIQUE_TO_STAGE.get(base)
        if stage is not None:
            matched.append((tid, stage))
            if stage > max_stage:
                max_stage = stage

    state["kill_chain_stage"] = max_stage
    state["phase"] = "analyze"
    # Pass the registered picerl key (kill_chain_classify) for accurate phase mapping.
    picerl.advance_iso27035(state, picerl.picerl_phase_for("kill_chain_classify"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="kill_chain_complete",
        data={"techniques_evaluated": list(techniques),
              "matched": [{"technique": t, "stage": s} for t, s in matched],
              "kill_chain_stage": max_stage},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"kill_chain: stage={max_stage} (from {len(matched)} matched techniques)",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
