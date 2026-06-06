"""Conditional-edge routing function tests for graph.py.

Mirrors IR_FRAMEWORKS_REFERENCE.md §11.3. Each function under test is a pure
(state) -> str returning the next-node key. These tests are deliberately
small/atomic — one branch per test — so a failing assertion points to a
single rule violation.
"""
from __future__ import annotations

from typing import Any

from mh_orchestrator.graph import (
    route_after_analyze,
    route_after_contain,
    route_after_eradicate,
    route_after_recover,
    route_after_triage,
)
from mh_orchestrator.state import IncidentState, new_state


def make_state(**overrides: Any) -> IncidentState:
    s = new_state("test-incident")
    for k, v in overrides.items():
        s[k] = v  # type: ignore[literal-required]
    return s


# --- route_after_triage ---------------------------------------------------
#
# Contract (revised): suppress ONLY on an EXPLICIT false-positive verdict from
# triage (_triage_false_positive=True). A bare low/informational severity must
# NOT suppress — the full investigation runs and the findings speak. This fixes
# the cascade where one weak one-word "low" killed the whole pipeline before
# analyze ran (the `not findings` clause was always true at triage time).

def test_route_after_triage_explicit_false_positive_suppresses() -> None:
    s = make_state(severity="low", _triage_false_positive=True)
    assert route_after_triage(s) == "suppress"


def test_route_after_triage_low_without_false_positive_declares() -> None:
    s = make_state(severity="low", _triage_false_positive=False, _findings=[])
    assert route_after_triage(s) == "declare_incident"


def test_route_after_triage_informational_without_false_positive_declares() -> None:
    s = make_state(severity="informational", _triage_false_positive=False, _findings=[])
    assert route_after_triage(s) == "declare_incident"


def test_route_after_triage_high_declares() -> None:
    s = make_state(severity="high")
    assert route_after_triage(s) == "declare_incident"


def test_route_after_triage_default_state_declares() -> None:
    """A fresh state has no explicit false-positive flag → declare (fail-open:
    investigate rather than silently drop)."""
    s = new_state("test-incident")
    assert route_after_triage(s) == "declare_incident"


# --- route_after_analyze --------------------------------------------------

def test_route_after_analyze_complete_proceeds() -> None:
    s = make_state(_rca_complete=True, _analyze_iter=1)
    assert route_after_analyze(s) == "attack_tag"


def test_route_after_analyze_iter_cap_proceeds() -> None:
    s = make_state(_rca_complete=False, _analyze_iter=3)
    assert route_after_analyze(s) == "attack_tag"


def test_route_after_analyze_loops_when_incomplete_below_cap() -> None:
    s = make_state(_rca_complete=False, _analyze_iter=1)
    assert route_after_analyze(s) == "analyze"


# --- route_after_contain --------------------------------------------------

def test_route_after_contain_below_default_threshold_eradicates() -> None:
    s = make_state(_max_blast_score=10)
    assert route_after_contain(s) == "eradicate"


def test_route_after_contain_above_default_threshold_escalates() -> None:
    s = make_state(_max_blast_score=51)
    assert route_after_contain(s) == "human_in_loop"


def test_route_after_contain_at_default_threshold_eradicates() -> None:
    # Strict greater-than: score == threshold should NOT escalate.
    s = make_state(_max_blast_score=50)
    assert route_after_contain(s) == "eradicate"


def test_route_after_contain_env_override_escalates(monkeypatch) -> None:
    monkeypatch.setenv("MH_BLAST_RADIUS_THRESHOLD", "10")
    s = make_state(_max_blast_score=15)
    assert route_after_contain(s) == "human_in_loop"


def test_route_after_contain_missing_score_eradicates() -> None:
    s = new_state("test-incident")
    s.pop("_max_blast_score", None)  # type: ignore[misc]
    assert route_after_contain(s) == "eradicate"


# --- route_after_eradicate ------------------------------------------------

def test_route_after_eradicate_reinfection_loops_to_contain() -> None:
    s = make_state(_reinfection_detected=True)
    assert route_after_eradicate(s) == "contain"


def test_route_after_eradicate_clean_proceeds_to_recover() -> None:
    s = make_state(_reinfection_detected=False)
    assert route_after_eradicate(s) == "recover"


# --- route_after_recover --------------------------------------------------

def test_route_after_recover_alarms_loop_to_contain() -> None:
    s = make_state(_post_restore_alarms=True)
    assert route_after_recover(s) == "contain"


def test_route_after_recover_clean_proceeds_to_lessons() -> None:
    s = make_state(_post_restore_alarms=False)
    assert route_after_recover(s) == "lessons_learned"
