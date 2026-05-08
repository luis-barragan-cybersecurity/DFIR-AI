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
    assert findings.exists()
