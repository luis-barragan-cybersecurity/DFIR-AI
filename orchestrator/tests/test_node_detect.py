"""detect node tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from mh_orchestrator.nodes import detect
from mh_orchestrator.state import new_state


def test_detect_sets_detected_os_and_phase(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = detect.run(s)
    assert s["_detected_os"] in {"windows", "macos", "linux", "memory_dump", "unknown"}
    assert s["phase"] == "triage"
    assert "DE.AE-02" in s["csf_subcategories_satisfied"]
    assert "detect" in s["_node_history"]


def test_detect_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    detect.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()


@pytest.mark.parametrize("filename", [
    "Rocba-Memory.raw",
    "image.mem",
    "windows.dmp",
    "vm.vmem",
    "linux.lime",
    "evidence.aff",
])
def test_memory_dump_extensions_classify_as_memory_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    """Regression: rocba case (2026-05) shipped Rocba-Memory.raw and the
    detect node returned 'unknown' because .raw was missing from this
    heuristic. Triage then routed to WindowsAgent via the fallback default,
    WindowsAgent ran the wrong tools on raw bytes, 0 findings recorded.
    Every common memory-image extension must now classify as memory_dump."""
    evidence = tmp_path / "input"
    evidence.mkdir()
    (evidence / filename).write_bytes(b"\x00" * 256)
    monkeypatch.setenv("EVIDENCE_PATH", str(evidence))

    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = detect.run(s)
    assert s["_detected_os"] == "memory_dump", (
        f"{filename} should classify as memory_dump, got {s['_detected_os']!r}"
    )


def test_windows_os_artifacts_outrank_memory_dump_extension(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a case dir has BOTH a memory image AND OS-side artifacts, the
    OS classification wins because OS artifacts are higher-signal triage
    targets (you triage the EVTX directly rather than carving it from memory).
    Order in _detect_os_from_evidence reflects this: memory_dump branch
    comes after OS branches."""
    evidence = tmp_path / "input"
    evidence.mkdir()
    (evidence / "Rocba-Memory.raw").write_bytes(b"\x00" * 256)
    (evidence / "Security.evtx").write_bytes(b"\x00" * 256)
    monkeypatch.setenv("EVIDENCE_PATH", str(evidence))

    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s = detect.run(s)
    assert s["_detected_os"] == "windows"
