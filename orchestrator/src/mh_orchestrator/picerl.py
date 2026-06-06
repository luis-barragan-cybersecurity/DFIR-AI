"""PICERL phase tracker + ISO 27035 mapper.

Maps LangGraph node names to SANS PICERL 6-phase model (Plans/IR_FRAMEWORKS_REFERENCE.md §5).
Maps PICERL phases to ISO/IEC 27035 5-phase governance overlay (§10.1).

Invariant: `advance_iso27035` is **monotonic** — it never regresses the
ISO phase. The PICERL → ISO map is lossy by construction (PICERL collapses
detection + assessment into a single "identification" phase), so a literal
implementation would let `analyze`'s mapping write `detection_and_reporting`
*after* `declare_incident` had already advanced to `assessment_and_decision`.
We block that regression at the function level so individual node bugs (or
PICERL/ISO model mismatches) can't roll the lifecycle backwards.
"""
from __future__ import annotations

from .state import IncidentState

# §5.1 — SANS PICERL 6 phases
NODE_TO_PICERL: dict[str, str] = {
    "session_init": "preparation",
    "manifest_ingest": "preparation",
    "detect": "identification",
    "triage": "identification",
    # declare_incident is the gate that promotes a *detection* into an
    # *assessed incident*. It maps to PICERL identification (still) but
    # the ISO governance overlay treats it as the start of assessment.
    # declare_incident.py writes ISO directly; this mapping is included
    # for completeness only.
    "declare_incident": "identification",
    "suppress": "identification",
    "scope": "identification",
    "analyze": "identification",
    "attack_tag": "identification",
    "kill_chain": "identification",
    "d3fend_recommend": "containment",
    "contain": "containment",
    "eradicate": "eradication",
    "recover": "recovery",
    "lessons_learned": "lessons_learned",
    # Remediation = post-incident hardening per NIST SP 800-61 §3.5; lives
    # in PICERL's lessons_learned phase, not its own.
    "remediation": "lessons_learned",
    "verifier_pass": "lessons_learned",
    "correlate": "lessons_learned",
    "human_in_loop": "containment",
    "session_finalize": "lessons_learned",
}

# §10.1 — ISO/IEC 27035-1:2023 5 phases, in canonical order.
# IMPORTANT: keep this list in temporal order. `advance_iso27035`'s
# monotonicity check uses index comparison.
ISO27035_PHASE_ORDER: tuple[str, ...] = (
    "plan_and_prepare",
    "detection_and_reporting",
    "assessment_and_decision",
    "responses",
    "learn_lessons",
)

# PICERL → ISO mapping. Lossy — see module docstring. The "identification"
# PICERL phase covers ISO's detection_and_reporting (the default surface);
# nodes that genuinely belong in the assessment phase (declare_incident)
# write ISO directly and rely on monotonicity to keep them there.
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
    """Set state['iso27035_phase'] for the given PICERL phase — but only
    if doing so would advance (or hold) the lifecycle, never regress it.

    Rationale: the PICERL → ISO map is lossy (PICERL identification covers
    two ISO phases). Without this monotonicity guard, any node mapped to
    "identification" (analyze, attack_tag, etc.) would silently roll the
    ISO phase back to detection_and_reporting after declare_incident had
    correctly advanced to assessment_and_decision. The regression then
    appears in state.history.jsonl and breaks the multi-framework
    alignment story the compliance_map.json deliverable promises.

    Unknown PICERL phase → no-op. Unknown current ISO phase (legacy
    state with corrupted field) → unconditional set so we get back to a
    known value.
    """
    target = PICERL_TO_ISO27035.get(picerl_phase)
    if target is None:
        return

    current = state.get("iso27035_phase")
    if current is None or current not in ISO27035_PHASE_ORDER:
        state["iso27035_phase"] = target
        return

    target_idx = ISO27035_PHASE_ORDER.index(target)
    current_idx = ISO27035_PHASE_ORDER.index(current)
    if target_idx >= current_idx:
        state["iso27035_phase"] = target
    # else: would regress — silently keep the current (more-advanced) phase
