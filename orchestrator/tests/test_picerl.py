"""picerl phase tracker + ISO 27035 mapper tests."""
from __future__ import annotations

from mh_orchestrator import picerl
from mh_orchestrator.state import new_state


def test_picerl_phase_for_known_nodes() -> None:
    # Per IR_FRAMEWORKS_REFERENCE §5.2 mapping
    assert picerl.picerl_phase_for("detect") == "identification"
    assert picerl.picerl_phase_for("triage") == "identification"
    assert picerl.picerl_phase_for("contain") == "containment"
    assert picerl.picerl_phase_for("eradicate") == "eradication"
    assert picerl.picerl_phase_for("recover") == "recovery"
    assert picerl.picerl_phase_for("lessons_learned") == "lessons_learned"


def test_advance_iso27035_sets_state_phase() -> None:
    s = new_state("c")
    picerl.advance_iso27035(s, "containment")
    assert s["iso27035_phase"] == "responses"
    picerl.advance_iso27035(s, "lessons_learned")
    assert s["iso27035_phase"] == "learn_lessons"
