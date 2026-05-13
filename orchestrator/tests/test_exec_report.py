"""End-to-end smoke for scripts/exec-report.py — reads a synthetic case and
asserts the rendered Markdown carries every required exec-grade section.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXEC_SCRIPT = REPO_ROOT / "scripts" / "exec-report.py"


def _make_case(case_dir: Path, *, detected_os: str = "windows") -> None:
    out = case_dir / "output"
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps([
        {
            "finding_id": "F-001",
            "claim": "PowerShell launched from explorer.exe with obfuscated args",
            "confidence": "confirmed",
            "confidence_rationale": (
                "confirmed because parent-child PID consistency + prefetch + "
                "EPROCESS pool tag agree"
            ),
            "pins": [{
                "artifact": "memory.raw",
                "tool": "windows.psscan",
                "locator": {"type": "memory_vad", "value": "0x1"},
                "raw_excerpt": "PID=4960",
                "captured_at": "2026-04-25T22:00:00Z",
            }],
            "mitre_attck": ["T1059.001"],
        },
    ]))
    (out / "state.json").write_text(json.dumps({
        "incident_id": case_dir.name,
        "severity": "high",
        "_detected_os": detected_os,
        "attack_techniques": ["T1059.001", "T1547.001"],
        "affected_hosts": ["10.0.2.15"],
        "affected_users": ["bob"],
        "affected_services": ["explorer.exe"],
        "affected_data": [],
    }))
    (out / "audit.jsonl").write_text(
        '{"seq":0,"ts":"2026-04-25T22:00:00Z","event":"evidence_ingest","data":{}}\n'
        '{"seq":1,"ts":"2026-04-25T22:00:01Z","event":"finding_recorded","data":{}}\n',
    )


def _run(case_dir: Path) -> str:
    result = subprocess.run(
        [sys.executable, str(EXEC_SCRIPT), str(case_dir)],
        check=True, capture_output=True, text=True,
    )
    assert "Wrote" in result.stdout
    return (case_dir / "output" / "exec-report.md").read_text()


@pytest.fixture
def windows_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "exec-windows"
    _make_case(case_dir, detected_os="windows")
    return case_dir


def test_exec_report_writes_file(windows_case: Path) -> None:
    md = _run(windows_case)
    assert md
    assert "Executive Incident Report" in md


def test_exec_report_has_at_a_glance(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "## At a Glance" in md
    assert "**Severity**: high" in md
    assert "**Detected OS**: windows" in md


def test_exec_report_has_top_3_actions(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "## What To Do in the Next 4 Hours" in md
    assert "### 1. snapshot_evidence" in md
    assert "### 2. isolate_host" in md
    assert "### 3. rotate_credentials" in md


def test_exec_report_top_3_carry_platform_specific_commands(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "DumpIt.exe" in md          # snapshot — windows
    assert "New-NetFirewallRule" in md  # isolate — windows
    assert "Set-ADAccountPassword" in md  # rotate — windows


def test_exec_report_includes_mermaid_timeline(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "## Attack Timeline" in md
    assert "```mermaid" in md
    assert "flowchart LR" in md


def test_exec_report_risk_reduction_score(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "Risk Reduction Detail" in md
    # T1059.001 + T1547.001 are both in containment_commands.json → 100%
    assert "100.0%" in md or "100%" in md


def test_exec_report_finding_table_carries_rationale(windows_case: Path) -> None:
    md = _run(windows_case)
    # The exact rationale string we wrote should round-trip into the report.
    assert "parent-child PID consistency" in md


def test_exec_report_legacy_finding_marker_when_missing_rationale(tmp_path: Path) -> None:
    case_dir = tmp_path / "legacy"
    out = case_dir / "output"
    out.mkdir(parents=True)
    (out / "findings.json").write_text(json.dumps([{
        "finding_id": "F-LEGACY",
        "claim": "old finding",
        "confidence": "inferred",
        "pins": [{
            "artifact": "x", "tool": "y",
            "locator": {"type": "log_line", "value": "1"},
            "raw_excerpt": "z",
            "captured_at": "2026-04-25T22:00:00Z",
        }],
        # NB: no confidence_rationale — legacy
    }]))
    (out / "state.json").write_text("{}")
    md = _run(case_dir)
    assert "(legacy finding — no rationale)" in md


def test_exec_report_advisory_footer(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "MemoryHound never executes" in md
    assert "advisory" in md.lower()


def test_exec_report_starts_with_executive_summary(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "## Executive Summary" in md
    # Executive Summary must come BEFORE At a Glance
    assert md.index("## Executive Summary") < md.index("## At a Glance")


def test_exec_report_executive_summary_is_plain_english(windows_case: Path) -> None:
    md = _run(windows_case)
    exec_section = md.split("## Executive Summary", 1)[1].split("## At a Glance", 1)[0]
    # No raw MITRE T-codes inside the exec summary section; they live in
    # the Technical Appendix instead.
    import re
    matches = re.findall(r"\bT1\d{3}\b", exec_section)
    assert not matches, f"Exec Summary leaked technical codes: {matches}"


def test_exec_report_per_role_table_present(windows_case: Path) -> None:
    md = _run(windows_case)
    exec_section = md.split("## Executive Summary", 1)[1].split("## At a Glance", 1)[0]
    # The roles we care about are surfaced when relevant concerns trigger.
    # Windows-test fixture has T1059.001 (PowerShell) + T1547.001 (Run keys),
    # which trigger persistence_implant → COO + CISO and that's it. Make
    # the assertion conditional on the role's concerns matching the case.
    assert "What this means for each leader" in exec_section
    assert "**CISO**" in exec_section


def test_exec_report_three_calls_section(windows_case: Path) -> None:
    md = _run(windows_case)
    assert "The three calls leadership has to make this week" in md


def test_exec_report_handles_missing_state_json(tmp_path: Path) -> None:
    """Case with only findings.json (no orchestrator run) should still render."""
    case_dir = tmp_path / "no-state"
    out = case_dir / "output"
    out.mkdir(parents=True)
    (out / "findings.json").write_text(json.dumps([{
        "finding_id": "F-1", "claim": "x", "confidence": "uncertain",
        "confidence_rationale": "uncertain because only one weak artifact",
        "pins": [{
            "artifact": "a", "tool": "b",
            "locator": {"type": "log_line", "value": "1"},
            "raw_excerpt": "c",
            "captured_at": "2026-04-25T22:00:00Z",
        }],
    }]))
    md = _run(case_dir)
    # No detected_os means top-3 actions are skipped gracefully.
    assert "Severity**: unknown" in md or "Detected OS**: unknown" in md
