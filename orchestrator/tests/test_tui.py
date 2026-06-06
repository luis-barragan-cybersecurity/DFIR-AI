"""Tests for the orchestrator TUI dashboard module.

Focus areas:
  - Rendered frames contain the expected fixed sections (banner, panes,
    NOW area, progress bar) — not exact byte-equality, since color and
    timing make exact matching brittle.
  - Append-only fallback path produces output (asciicast-safe).
  - MH_QUIET=1 short-circuits everything (CI safety).
  - derive_state_summary correctly buckets findings + counts ATT&CK.
"""
from __future__ import annotations

import io
import re

import pytest

from mh_orchestrator import tui as tui_mod


def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test starts with a clean module-level _TUI."""
    tui_mod._TUI = None
    yield
    tui_mod._TUI = None


@pytest.fixture
def buf_tui(monkeypatch) -> tuple[tui_mod.Tui, io.StringIO]:
    monkeypatch.delenv("MH_QUIET", raising=False)
    buf = io.StringIO()
    # Force append-only to avoid ANSI cursor-move escape codes in the buffer.
    t = tui_mod.Tui(
        case_id="test-case",
        evidence_summary="1 artifact · 297.0MB · memory.raw",
        stream=buf,
        in_place=False,
    )
    return t, buf


# ──────────────────────────────────────────────────────────────────────────
# Renderer surface — frame contains required sections
# ──────────────────────────────────────────────────────────────────────────


def test_frame_has_banner_with_case_id(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    out = _strip_ansi(buf.getvalue())
    assert "MemoryHound · test-case" in out
    assert "1 artifact · 297.0MB · memory.raw" in out


def test_frame_has_both_panes(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    out = _strip_ansi(buf.getvalue())
    assert "PIPELINE" in out
    assert "LIVE STATE" in out
    # All 18 nodes appear by name in the left pane.
    for node in tui_mod.PIPELINE_NODES:
        assert node in out, f"node {node!r} missing from pipeline pane"


def test_frame_has_now_area(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    out = _strip_ansi(buf.getvalue())
    assert "NOW ›" in out


def test_frame_has_progress_bar(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    out = _strip_ansi(buf.getvalue())
    # The bar is filled with █/░, and the right-side counter is N/18.
    assert "/18" in out


# ──────────────────────────────────────────────────────────────────────────
# Node lifecycle reflects in pipeline pane
# ──────────────────────────────────────────────────────────────────────────


def test_node_start_marks_running(buf_tui, monkeypatch) -> None:
    monkeypatch.setattr("time.monotonic", lambda: 100.0)
    t, buf = buf_tui
    t.start()
    buf.truncate(0); buf.seek(0)
    t.node_start("triage")
    out = _strip_ansi(buf.getvalue())
    assert "▶ triage" in out
    assert t.node_status["triage"] == "running"


def test_node_end_marks_done(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    t.node_start("triage")
    t.node_end("triage", ok=True, elapsed_s=42.5)
    out = _strip_ansi(buf.getvalue())
    assert "✓ triage" in out
    assert t.node_status["triage"] == "done"


def test_node_end_failed_marks_failed(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    t.node_start("triage")
    t.node_end("triage", ok=False, elapsed_s=120.0)
    out = _strip_ansi(buf.getvalue())
    assert "✗ triage" in out
    assert t.node_status["triage"] == "failed"


# ──────────────────────────────────────────────────────────────────────────
# NOW area updates
# ──────────────────────────────────────────────────────────────────────────


def test_now_updates_both_lines(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    buf.truncate(0); buf.seek(0)
    # Append-mode throttles to 2s between frames. Bypass by forcing a final
    # render via stop().
    t.now("WindowsAgent · calling memory_volatility",
          "windows.psscan on 19.0GB image · 00:42")
    t.stop()
    out = _strip_ansi(buf.getvalue())
    assert "WindowsAgent · calling memory_volatility" in out
    assert "windows.psscan on 19.0GB image · 00:42" in out


def test_now_line2_omitted_renders_em_dash(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    buf.truncate(0); buf.seek(0)
    t.now("idle")
    t.stop()
    out = _strip_ansi(buf.getvalue())
    assert "└ —" in out  # explicit empty marker


# ──────────────────────────────────────────────────────────────────────────
# State panel
# ──────────────────────────────────────────────────────────────────────────


def test_update_state_merges_kwargs(buf_tui) -> None:
    t, buf = buf_tui
    t.start()
    t.update_state(severity="high", findings="11  (4 high · 4 med · 3 low)")
    t.stop()
    out = _strip_ansi(buf.getvalue())
    assert "high" in out
    assert "11  (4 high · 4 med · 3 low)" in out


# ──────────────────────────────────────────────────────────────────────────
# MH_QUIET=1 silences everything (CI/test safety)
# ──────────────────────────────────────────────────────────────────────────


def test_mh_quiet_returns_null_tui(monkeypatch) -> None:
    monkeypatch.setenv("MH_QUIET", "1")
    t = tui_mod.start(case_id="c", evidence_summary="x")
    assert isinstance(t, tui_mod._NullTui)
    # All facade methods must accept the same calls without exploding.
    tui_mod.node_start("triage")
    tui_mod.node_end("triage", ok=True, elapsed_s=1.0)
    tui_mod.now("a", "b")
    tui_mod.update_state(severity="high")
    tui_mod.stop()


# ──────────────────────────────────────────────────────────────────────────
# derive_state_summary
# ──────────────────────────────────────────────────────────────────────────


def test_derive_state_summary_counts_findings_by_confidence() -> None:
    state = {
        "phase": "analyze", "iso27035_phase": "assessment_and_decision",
        "severity": "high",
        "_findings": [
            {"finding_id": "F-1", "confidence": "high",
             "mitre_attck": ["T1005", "T1041"]},
            {"finding_id": "F-2", "confidence": "high",
             "mitre_attck": ["T1041"]},
            {"finding_id": "F-3", "confidence": "medium",
             "mitre_attck": ["T1059.001"]},
            {"finding_id": "F-4", "confidence": "low", "mitre_attck": []},
        ],
        "csf_subcategories_satisfied": {"DE.AE-02", "RS.MA-03"},
        "_verifier_decisions": [
            {"decision": "agree"}, {"decision": "dissent"},
        ],
    }
    s = tui_mod.derive_state_summary(state)
    assert s["phase"] == "analyze"
    assert s["iso27035"] == "assessment_and_decision"
    assert s["severity"] == "high"
    assert "4" in s["findings"]
    assert "2 high" in s["findings"]
    assert "1 med" in s["findings"]
    assert "1 low" in s["findings"]
    assert s["attck"] == "3"  # 3 unique techniques across findings
    assert s["csf"] == "2"
    assert s["dissent"] == "1 of 2"


def test_derive_state_summary_handles_empty_state() -> None:
    s = tui_mod.derive_state_summary({})
    assert s["findings"] == "0"
    assert s["attck"] == "0"
    assert s["csf"] == "0"
    assert s["dissent"] == "—"


# ──────────────────────────────────────────────────────────────────────────
# Facade smoke (no-op when singleton not started)
# ──────────────────────────────────────────────────────────────────────────


def test_facade_noops_when_not_started() -> None:
    tui_mod._TUI = None
    # None of these should raise.
    tui_mod.node_start("triage")
    tui_mod.node_end("triage", ok=True, elapsed_s=1.0)
    tui_mod.now("a", "b")
    tui_mod.update_state(severity="high")
    tui_mod.stop()
