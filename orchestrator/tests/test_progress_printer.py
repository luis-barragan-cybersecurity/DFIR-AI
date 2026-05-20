"""Tests for the per-node live progress printer (mh_orchestrator/nodes/__init__.py).

`mh run` (LangGraph mode) used to go silent for hours during long triage runs.
The progress printer wraps each registered node with a stderr emitter so the
operator sees what's happening live.
"""
from __future__ import annotations

from io import StringIO
from pathlib import Path

from mh_orchestrator.state import new_state


def _make_state(tmp_path: Path) -> dict:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    return s


def test_progress_printer_emits_enter_and_exit_to_stderr(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("MH_QUIET", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")  # strip ANSI so substring asserts are stable

    import importlib
    from mh_orchestrator import nodes as nodes_pkg
    importlib.reload(nodes_pkg)

    triage_fn = nodes_pkg.NODES["triage"]
    triage_fn(_make_state(tmp_path))

    err = capsys.readouterr().err
    assert "▶ triage" in err, f"expected enter line, got: {err!r}"
    assert "✓ triage" in err, f"expected exit line, got: {err!r}"
    assert "done in" in err, "exit line should include duration"


def test_mh_quiet_suppresses_progress_lines(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MH_QUIET", "1")
    monkeypatch.setenv("NO_COLOR", "1")

    import importlib
    from mh_orchestrator import nodes as nodes_pkg
    importlib.reload(nodes_pkg)

    triage_fn = nodes_pkg.NODES["triage"]
    triage_fn(_make_state(tmp_path))

    err = capsys.readouterr().err
    assert "▶ triage" not in err
    assert "✓ triage" not in err


def test_progress_printer_emits_failure_line_on_exception(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("MH_QUIET", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")

    import importlib
    from mh_orchestrator import nodes as nodes_pkg
    importlib.reload(nodes_pkg)

    def boom(_state):
        raise RuntimeError("synthetic node failure")

    wrapped = nodes_pkg._wrap_with_progress("boom_node", boom)

    import pytest
    with pytest.raises(RuntimeError, match="synthetic node failure"):
        wrapped(_make_state(tmp_path))

    err = capsys.readouterr().err
    assert "✗ boom_node FAILED" in err
    assert "RuntimeError" in err


def test_all_registered_nodes_are_wrapped(monkeypatch):
    """Every entry in the public NODES registry must be the wrapped version,
    not the raw node function — otherwise some nodes silently bypass the
    progress printer."""
    monkeypatch.setenv("NO_COLOR", "1")

    import importlib
    from mh_orchestrator import nodes as nodes_pkg
    importlib.reload(nodes_pkg)

    for name, fn in nodes_pkg.NODES.items():
        assert fn is not nodes_pkg._RAW_NODES[name], (
            f"node {name!r} is not wrapped with progress printer"
        )
