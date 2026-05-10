"""MH_REAL_CLAUDE_NODES env gate tests."""
from __future__ import annotations

import pytest

from mh_orchestrator.claude_node import should_stub


def test_no_claude_unset_always_real(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MH_NO_CLAUDE", raising=False)
    monkeypatch.delenv("MH_REAL_CLAUDE_NODES", raising=False)
    assert should_stub("triage") is False
    assert should_stub("analyze") is False
    assert should_stub("verifier_pass") is False


def test_no_claude_set_no_override_all_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    monkeypatch.delenv("MH_REAL_CLAUDE_NODES", raising=False)
    assert should_stub("triage") is True
    assert should_stub("analyze") is True
    assert should_stub("verifier_pass") is True


def test_real_claude_nodes_override_triage_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    monkeypatch.setenv("MH_REAL_CLAUDE_NODES", "triage")
    assert should_stub("triage") is False
    assert should_stub("analyze") is True
    assert should_stub("verifier_pass") is True


def test_real_claude_nodes_multi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    monkeypatch.setenv("MH_REAL_CLAUDE_NODES", "triage,analyze")
    assert should_stub("triage") is False
    assert should_stub("analyze") is False
    assert should_stub("verifier_pass") is True


def test_whitespace_in_node_list_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    monkeypatch.setenv("MH_REAL_CLAUDE_NODES", " triage , verifier_pass ")
    assert should_stub("triage") is False
    assert should_stub("verifier_pass") is False
    assert should_stub("analyze") is True


def test_unknown_node_name_falls_back_to_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    monkeypatch.setenv("MH_REAL_CLAUDE_NODES", "triage")
    # Unknown node name not in override list → stub (still under MH_NO_CLAUDE=1).
    assert should_stub("unknown_node") is True
