"""Tests for the accuracy-fix bundle landed before the rocba re-run.

Each test pins one of the four fixes:

  1. analyze MAX_ITER is env-configurable (was hardcoded 3 → default 5)
  2. detect node reads state["_input_dir"] (was env-only, missed every
     orchestrator-launched run)
  3. D3FEND crosswalk covers the rocba-finding techniques (was 25 entries
     → now 40, includes T1021.001, T1133, T1567.002, T1052.001 etc)
  4. analyze prompt includes strict pin format guidance (artifact + tool +
     structured locator + verbatim raw_excerpt + captured_at)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ──────────────────────────────────────────────────────────────────────────
# Fix 1 — analyze RCA cap is env-configurable
# ──────────────────────────────────────────────────────────────────────────


def test_analyze_max_iter_default_is_5(monkeypatch) -> None:
    """Default bumped 3 → 5 to give large-image cases enough RCA budget."""
    monkeypatch.delenv("MH_ANALYZE_MAX_ITER", raising=False)
    # Re-import to pick up env at module load
    import importlib
    from mh_orchestrator.nodes import analyze as analyze_mod
    importlib.reload(analyze_mod)
    assert analyze_mod.MAX_ITER == 5


def test_analyze_max_iter_honors_env(monkeypatch) -> None:
    monkeypatch.setenv("MH_ANALYZE_MAX_ITER", "10")
    import importlib
    from mh_orchestrator.nodes import analyze as analyze_mod
    importlib.reload(analyze_mod)
    assert analyze_mod.MAX_ITER == 10


def test_graph_analyze_iter_cap_matches_env(monkeypatch) -> None:
    """graph._ANALYZE_ITER_CAP must match analyze.MAX_ITER so route_after_analyze
    and the RCA loop never disagree on the cap."""
    monkeypatch.setenv("MH_ANALYZE_MAX_ITER", "7")
    import importlib
    from mh_orchestrator import graph as graph_mod
    importlib.reload(graph_mod)
    assert graph_mod._ANALYZE_ITER_CAP == 7


# ──────────────────────────────────────────────────────────────────────────
# Fix 2 — detect node reads state["_input_dir"]
# ──────────────────────────────────────────────────────────────────────────


def test_detect_reads_state_input_dir_not_just_env(tmp_path: Path, monkeypatch) -> None:
    """Pre-fix detect only checked EVIDENCE_PATH env var which mh-orchestrate
    doesn't set. Every orchestrator run got _detected_os='unknown' → fallback
    to WindowsAgent regardless of real OS."""
    from mh_orchestrator.nodes import detect
    from mh_orchestrator.state import new_state

    # Build a fake evidence dir with a Windows-y artifact name so the
    # heuristic returns "windows" (not just "unknown").
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "NTUSER.DAT").write_bytes(b"")

    monkeypatch.delenv("EVIDENCE_PATH", raising=False)
    s = new_state("input-dir-test")
    s["_input_dir"] = str(evidence)
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir()
    s = detect.run(s)
    assert s["_detected_os"] == "windows", (
        "detect ignored state['_input_dir'] — should classify from there "
        "when EVIDENCE_PATH is unset"
    )


def test_detect_falls_back_to_env_when_state_input_dir_missing(
    tmp_path: Path, monkeypatch,
) -> None:
    """Back-compat: env var path still works for legacy callers."""
    from mh_orchestrator.nodes import detect
    from mh_orchestrator.state import new_state
    evidence = tmp_path / "ev"
    evidence.mkdir()
    (evidence / "NTUSER.DAT").write_bytes(b"")
    monkeypatch.setenv("EVIDENCE_PATH", str(evidence))
    s = new_state("env-fallback")
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir()
    # Intentionally leave _input_dir blank
    s["_input_dir"] = ""
    s = detect.run(s)
    assert s["_detected_os"] == "windows"


def test_detect_raw_memory_image_classifies_via_kernel_banner(
    tmp_path: Path, monkeypatch,
) -> None:
    """A .raw file with a Windows kernel banner in the first probe window
    should classify as 'windows' (not 'memory_dump' fallback). Pre-fix
    rocba's 17.7GB .raw fell through to 'unknown' because nothing matched."""
    from mh_orchestrator.nodes import detect
    from mh_orchestrator.state import new_state
    evidence = tmp_path / "ev"
    evidence.mkdir()
    raw = evidence / "fake.raw"
    raw.write_bytes(
        b"\x00" * 4096 + b"\\SystemRoot\\system32\\ntoskrnl.exe" + b"\x00" * 4096
    )
    monkeypatch.delenv("EVIDENCE_PATH", raising=False)
    s = new_state("raw-banner-test")
    s["_input_dir"] = str(evidence)
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir()
    s = detect.run(s)
    assert s["_detected_os"] == "windows", (
        "raw memory image with Windows banner should classify as 'windows'"
    )


# ──────────────────────────────────────────────────────────────────────────
# Fix 3 — D3FEND crosswalk covers the rocba findings
# ──────────────────────────────────────────────────────────────────────────


_ROCBA_REQUIRED_TECHNIQUES = (
    "T1021.001", "T1133", "T1567.002", "T1052.001",
    "T1074.001", "T1560", "T1070.004",
    # New ones we explicitly added
    "T1025", "T1114", "T1071", "T1185", "T1217", "T1485", "T1588.002",
    "T1567",
)


@pytest.mark.parametrize("technique", _ROCBA_REQUIRED_TECHNIQUES)
def test_d3fend_crosswalk_covers_rocba_technique(technique: str) -> None:
    """Every ATT&CK technique surfaced by the rocba case must have at least
    one D3FEND countermeasure in the crosswalk so compliance_map.json
    doesn't read 'tactics_unmapped' for half the kill chain."""
    from mh_orchestrator import d3fend_crosswalk
    assert technique in d3fend_crosswalk.CROSSWALK, (
        f"{technique} missing from D3FEND crosswalk — "
        "d3fend_recommend will emit a crosswalk_miss audit event"
    )
    countermeasures = d3fend_crosswalk.CROSSWALK[technique]
    assert len(countermeasures) >= 1
    # Each countermeasure must have the minimum required fields.
    for cm in countermeasures:
        assert "d3fend_id" in cm and cm["d3fend_id"]
        assert "name" in cm and cm["name"]
        assert "tactic" in cm and cm["tactic"] in {
            "Detect", "Isolate", "Harden", "Recover", "Deceive", "Evict",
        }
        assert "rationale" in cm and cm["rationale"]


def test_d3fend_crosswalk_size_at_least_40() -> None:
    """Coverage threshold: we added 15 entries to reach 40 total. Guards
    against accidental data-file truncation."""
    from mh_orchestrator import d3fend_crosswalk
    assert len(d3fend_crosswalk.CROSSWALK) >= 40


# ──────────────────────────────────────────────────────────────────────────
# Fix 4 — analyze prompt teaches strict pin format
# ──────────────────────────────────────────────────────────────────────────


def test_analyze_prompt_specifies_pin_format(tmp_path: Path, monkeypatch) -> None:
    """The prompt must instruct the subagent to use the strict pin
    schema (vol_row locator + verbatim raw_excerpt + captured_at)."""
    monkeypatch.setenv("MH_NO_CLAUDE", "0")
    from mh_orchestrator.nodes import analyze
    from mh_orchestrator.state import new_state
    (tmp_path / "input").mkdir()
    s = new_state("pin-test")
    s["_output_dir"] = str(tmp_path / "output")
    s["_input_dir"] = str(tmp_path / "input")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    s["_detected_os"] = "windows"
    captured: dict[str, str] = {}
    def _capture(*, prompt: str, **_):
        captured["prompt"] = prompt
        return MagicMock(final_text="DONE (0, 0)", exit_code=0)
    with patch("mh_orchestrator.nodes.analyze.invoke_subagent",
               side_effect=_capture):
        analyze.run(s)
    prompt = captured["prompt"]
    # All four required pin-schema cues must appear.
    assert "Pin format" in prompt
    assert "vol_row" in prompt or "structured locator" in prompt
    assert "VERBATIM" in prompt or "verbatim" in prompt
    assert "captured_at" in prompt
