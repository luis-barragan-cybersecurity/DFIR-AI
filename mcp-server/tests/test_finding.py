"""Finding pin-validation tests. The 'no un-pinned findings' Pydantic gate MUST reject empty pins."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError


def test_finding_record_rejects_empty_pins(tmp_path: Path) -> None:
    from protocol_sift_mcp.tools import finding as fd

    findings = tmp_path / "output" / "findings.json"
    bad = {
        "finding_id": "F-1",
        "claim": "test",
        "confidence": "inferred",
        "pins": [],
    }
    with pytest.raises(ValidationError):
        fd.finding_record(findings, bad)


def test_finding_record_accepts_valid_pin(tmp_path: Path) -> None:
    from protocol_sift_mcp.tools import finding as fd

    findings = tmp_path / "output" / "findings.json"
    good = {
        "finding_id": "F-1",
        "claim": "test claim",
        "confidence": "inferred",
        "confidence_rationale": "single artifact (pslist VAD) with well-understood semantics",
        "pins": [
            {
                "artifact": "memory.dmp",
                "tool": "windows.pslist",
                "locator": {"type": "memory_vad", "value": "pid=1234 vad=0x100"},
                "raw_excerpt": "deadbeef",
                "captured_at": "2026-04-25T22:00:00Z",
            }
        ],
    }
    record = fd.finding_record(findings, good)
    assert record["finding_id"] == "F-1"
    assert record["confidence_rationale"].startswith("single artifact")
    assert findings.exists()


def test_finding_record_rejects_missing_rationale(tmp_path: Path) -> None:
    """Anti-hallucination guard: schema MUST reject findings without an
    explicit confidence rationale. Owners need the 'why' to act on output.
    """
    from protocol_sift_mcp.tools import finding as fd

    findings = tmp_path / "output" / "findings.json"
    bad = {
        "finding_id": "F-2",
        "claim": "another test claim",
        "confidence": "inferred",
        "pins": [
            {
                "artifact": "memory.dmp",
                "tool": "windows.pslist",
                "locator": {"type": "memory_vad", "value": "pid=4321 vad=0x200"},
                "raw_excerpt": "cafebabe",
                "captured_at": "2026-04-25T22:00:00Z",
            }
        ],
    }
    with pytest.raises(ValidationError):
        fd.finding_record(findings, bad)


def test_finding_record_rejects_empty_rationale(tmp_path: Path) -> None:
    """min_length=1 — empty string fails the gate just like missing field."""
    from protocol_sift_mcp.tools import finding as fd

    findings = tmp_path / "output" / "findings.json"
    bad = {
        "finding_id": "F-3",
        "claim": "claim",
        "confidence": "uncertain",
        "confidence_rationale": "",
        "pins": [
            {
                "artifact": "x", "tool": "y",
                "locator": {"type": "log_line", "value": "1"},
                "raw_excerpt": "z",
                "captured_at": "2026-04-25T22:00:00Z",
            }
        ],
    }
    with pytest.raises(ValidationError):
        fd.finding_record(findings, bad)
