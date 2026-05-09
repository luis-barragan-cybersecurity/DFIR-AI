"""BlastRadius scoring + threshold-gate tests."""
from __future__ import annotations

import os

from mh_orchestrator.blast_radius import BlastRadius


def test_score_formula() -> None:
    # hosts*5 + users*1 + services*3
    br = BlastRadius(hosts_affected=10, users_affected=20, services_affected=4)
    assert br.score() == 10 * 5 + 20 * 1 + 4 * 3  # 50 + 20 + 12 = 82


def test_exceeds_threshold_explicit() -> None:
    br = BlastRadius(hosts_affected=10, users_affected=0, services_affected=0)
    assert br.score() == 50
    assert br.exceeds_threshold(49) is True
    assert br.exceeds_threshold(50) is False
    assert br.exceeds_threshold(100) is False


def test_exceeds_threshold_uses_env_var(monkeypatch) -> None:
    br = BlastRadius(hosts_affected=2, users_affected=0, services_affected=0)
    assert br.score() == 10
    monkeypatch.setenv("MH_BLAST_RADIUS_THRESHOLD", "5")
    assert br.exceeds_threshold() is True   # 10 > 5
    monkeypatch.setenv("MH_BLAST_RADIUS_THRESHOLD", "100")
    assert br.exceeds_threshold() is False  # 10 < 100
    # Unset → default 50
    monkeypatch.delenv("MH_BLAST_RADIUS_THRESHOLD", raising=False)
    assert br.exceeds_threshold() is False  # 10 < 50
