"""Invariant tests for scripts/exec-report.py — guard against the
fabrication failures found in the dfrws-2008-memory exec-report:

  - phantom hosts (192.168.151.1 never appeared in any pin yet was rendered)
  - inflated data locations (regex against free text, ~12× the real count)
  - "the three calls" header with two items below it
  - "across 0 projects" template slot
  - destructive prose claim absent any Impact-tactic technique
  - ATT&CK truncation that doesn't disclose it's truncated
  - scope re-computed at render time when the orchestrator already wrote it

Each test pins ONE of these failure modes by constructing a minimal case
that would have triggered it and asserting the rendered Markdown does
not exhibit it.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXEC_SCRIPT = REPO_ROOT / "scripts" / "exec-report.py"


def _write_case(
    case_dir: Path,
    *,
    findings: list[dict],
    state: dict,
    audit_lines: list[str] | None = None,
) -> None:
    out = case_dir / "output"
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(findings))
    (out / "state.json").write_text(json.dumps(state))
    (out / "audit.jsonl").write_text(
        "\n".join(audit_lines or ['{"seq":0,"ts":"2026-04-25T22:00:00Z","event":"x","data":{}}']),
    )


def _render(case_dir: Path) -> str:
    result = subprocess.run(
        [sys.executable, str(EXEC_SCRIPT), str(case_dir)],
        check=True, capture_output=True, text=True,
    )
    return (case_dir / "output" / "exec-report.md").read_text()


# ──────────────────────────────────────────────────────────────────────────
# scope source-of-truth: prefer state over synthesis
# ──────────────────────────────────────────────────────────────────────────


def test_state_scope_empty_list_is_respected_not_overridden_by_regex(tmp_path: Path) -> None:
    """If the orchestrator wrote `affected_hosts = []` (scope ran, found
    nothing), the exec-report MUST NOT regex-scan findings to invent
    hosts. This is the bug that put '192.168.151.1' into a C-suite
    report when the underlying state recorded no hosts.
    """
    case = tmp_path / "case-explicit-empty"
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "noise",
            "confidence": "medium",
            "pins": [{
                "artifact": "x", "tool": "y",
                "locator": {"type": "log_line", "value": "1"},
                "raw_excerpt": "something about 192.168.151.1 in plain text",
                "captured_at": "2026-04-25T22:00:00Z",
            }],
            "mitre_attck": [],
        }],
        state={
            "incident_id": "case-explicit-empty", "severity": "medium",
            "_detected_os": "linux",
            "attack_techniques": [],
            "affected_hosts": [],
            "affected_users": [],
            "affected_services": [],
            "affected_data": [],
            "egress_destinations": [],
        },
    )
    md = _render(case)
    assert "192.168.151.1" not in md, (
        "phantom host bug: regex scraped an IP from raw_excerpt even though "
        "state recorded affected_hosts=[]"
    )
    assert "**Affected hosts**: 0" in md


def test_synthesis_only_when_state_truly_unpopulated(tmp_path: Path) -> None:
    """When *every* scope field in state is None (scope node never ran),
    fall back to regex synthesis and label it as such so leadership knows
    the numbers are indicative."""
    case = tmp_path / "case-no-scope"
    _write_case(case,
        findings=[{
            "finding_id": "F-1",
            "claim": "exfil to 10.20.30.40",
            "confidence": "high",
            "pins": [{
                "artifact": "x", "tool": "y",
                "locator": {"type": "log_line", "value": "1"},
                "raw_excerpt": "talked to 10.20.30.40",
                "captured_at": "2026-04-25T22:00:00Z",
            }],
            "mitre_attck": [],
        }],
        state={
            "incident_id": "case-no-scope", "severity": "medium",
            "_detected_os": "linux",
            "attack_techniques": [],
            # NB: every scope field intentionally absent (= None on .get)
        },
    )
    md = _render(case)
    assert "regex-inferred" in md
    assert "10.20.30.40" in md  # synthesis ran, picked up the IP


# ──────────────────────────────────────────────────────────────────────────
# Phantom hosts cannot appear in exec-report
# ──────────────────────────────────────────────────────────────────────────


def test_every_rendered_host_appears_in_a_pin_or_state(tmp_path: Path) -> None:
    """The hosts listed in the At-a-Glance MUST be a subset of
    state.affected_hosts. If they aren't, something is regex-fabricating
    again."""
    case = tmp_path / "case-pin-trace"
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "x",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": [],
        }],
        state={
            "incident_id": "case-pin-trace", "severity": "high",
            "_detected_os": "windows",
            "attack_techniques": [],
            "affected_hosts": ["10.0.0.5", "10.0.0.6"],
            "affected_users": [],
            "affected_services": [],
            "affected_data": [],
        },
    )
    md = _render(case)
    # Extract IPs from the At a Glance "Affected hosts" line.
    glance = md.split("## At a Glance", 1)[1].split("\n## ", 1)[0] if "## At a Glance" in md else md
    rendered_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", glance))
    state_hosts = {"10.0.0.5", "10.0.0.6"}
    phantom = rendered_ips - state_hosts
    assert not phantom, f"phantom hosts in exec-report: {phantom}"


# ──────────────────────────────────────────────────────────────────────────
# "N calls" header matches the list under it
# ──────────────────────────────────────────────────────────────────────────


def test_calls_header_word_matches_list_length(tmp_path: Path) -> None:
    """The header reads "the N call(s)..." where N must equal the number
    of items rendered below. Pre-fix the header was hardcoded "three"
    even when only two calls applied."""
    case = tmp_path / "case-calls"
    # Use ip_collection only (T1530) → produces exactly 1 call (Disclosure).
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "IP docs collected",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": ["T1530"],
        }],
        state={
            "incident_id": "case-calls", "severity": "high",
            "_detected_os": "linux",
            "attack_techniques": ["T1530"],
            "affected_hosts": [], "affected_users": [],
            "affected_services": [], "affected_data": [],
        },
    )
    md = _render(case)
    # Find the calls section header and the items beneath it.
    m = re.search(
        r"### The (\w+) calls? leadership has to make this week\n\n((?:\d+\.[^\n]+\n)+)",
        md,
    )
    assert m, f"could not locate calls section in:\n{md[:2000]}"
    word, body = m.group(1), m.group(2)
    n_items = len(re.findall(r"^\d+\.\s", body, re.MULTILINE))
    word_to_n = {"one": 1, "two": 2, "three": 3}
    assert word_to_n.get(word, int(word) if word.isdigit() else None) == n_items, (
        f"header says '{word}' but {n_items} item(s) listed"
    )


# ──────────────────────────────────────────────────────────────────────────
# Template hygiene: never render "across 0 projects"
# ──────────────────────────────────────────────────────────────────────────


def test_never_renders_across_zero_projects(tmp_path: Path) -> None:
    case = tmp_path / "case-zero-projects"
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "data exfiltrated",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": ["T1530"],
        }],
        state={
            "incident_id": "case-zero-projects", "severity": "high",
            "_detected_os": "linux",
            "attack_techniques": ["T1530"],
            "affected_hosts": [], "affected_users": [],
            "affected_services": [],
            "affected_data": ["/tmp/foo.docx"],  # no "Project" substring
        },
    )
    md = _render(case)
    assert "across 0 projects" not in md
    assert "across 0 project(s)" not in md


def test_renders_project_count_when_nonzero(tmp_path: Path) -> None:
    case = tmp_path / "case-some-projects"
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "data exfiltrated",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": ["T1530"],
        }],
        state={
            "incident_id": "case-some-projects", "severity": "high",
            "_detected_os": "linux",
            "attack_techniques": ["T1530"],
            "affected_hosts": [], "affected_users": [],
            "affected_services": [],
            "affected_data": ["/srv/Projects/Apollo/plan.docx",
                              "/srv/Projects/Gemini/budget.xlsx"],
        },
    )
    md = _render(case)
    assert "across 2 project(s)" in md


# ──────────────────────────────────────────────────────────────────────────
# Destructive prose claim must be evidence-gated
# ──────────────────────────────────────────────────────────────────────────


def test_no_destructive_claim_without_impact_technique(tmp_path: Path) -> None:
    """The exec paragraph should not claim 'destructive activity' unless
    an ATT&CK Impact technique (T1485/T1486/T1490) is present.
    """
    case = tmp_path / "case-no-impact"
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "data exfil",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": ["T1041", "T1005"],  # exfil + collection, no Impact
        }],
        state={
            "incident_id": "case-no-impact", "severity": "medium",
            "_detected_os": "linux",
            "attack_techniques": ["T1041", "T1005"],
            "affected_hosts": [], "affected_users": [],
            "affected_services": [], "affected_data": [],
        },
    )
    md = _render(case)
    exec_section = md.split("## Executive Summary", 1)[1].split("## At a Glance", 1)[0]
    assert "destructive" not in exec_section.lower()


def test_destructive_claim_appears_when_impact_technique_present(tmp_path: Path) -> None:
    """The mirror — if T1486 is in the findings, the destructive prose
    SHOULD fire. Confirms the gate isn't accidentally stuck off."""
    case = tmp_path / "case-impact"
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "ransomware",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": ["T1486"],
        }],
        state={
            "incident_id": "case-impact", "severity": "critical",
            "_detected_os": "windows",
            "attack_techniques": ["T1486"],
            "affected_hosts": [], "affected_users": [],
            "affected_services": [], "affected_data": [],
        },
    )
    md = _render(case)
    exec_section = md.split("## Executive Summary", 1)[1].split("## At a Glance", 1)[0]
    assert "destructive" in exec_section.lower()


# ──────────────────────────────────────────────────────────────────────────
# Severity must match state (no silent override)
# ──────────────────────────────────────────────────────────────────────────


def test_severity_in_glance_matches_state_severity(tmp_path: Path) -> None:
    case = tmp_path / "case-sev"
    _write_case(case,
        findings=[],
        state={
            "incident_id": "case-sev", "severity": "medium",
            "_detected_os": "linux",
            "attack_techniques": [],
            "affected_hosts": [], "affected_users": [],
            "affected_services": [], "affected_data": [],
        },
    )
    md = _render(case)
    assert "**Severity**: medium" in md
    assert "**Severity**: unknown" not in md


# ──────────────────────────────────────────────────────────────────────────
# ATT&CK count == list (no silent truncation)
# ──────────────────────────────────────────────────────────────────────────


def test_attck_truncation_is_disclosed_when_count_exceeds_12(tmp_path: Path) -> None:
    """If we render only the first 6 of N techniques, the user must see
    'showing 6 of N' — otherwise they assume the displayed 6 are the
    full set (which is what made the earlier exec-report appear to have
    fabricated technique IDs)."""
    case = tmp_path / "case-big-attck"
    many = [f"T{1000 + i}" for i in range(15)]  # 15 techniques
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "lots of techniques",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": many,
        }],
        state={
            "incident_id": "case-big-attck", "severity": "high",
            "_detected_os": "linux",
            "attack_techniques": many,
            "affected_hosts": [], "affected_users": [],
            "affected_services": [], "affected_data": [],
        },
    )
    md = _render(case)
    glance = md.split("## At a Glance", 1)[1].split("\n## ", 1)[0]
    assert "showing 6 of 15" in glance


def test_attck_under_12_shows_all_no_truncation(tmp_path: Path) -> None:
    case = tmp_path / "case-small-attck"
    techniques = ["T1003", "T1005", "T1041"]
    _write_case(case,
        findings=[{
            "finding_id": "F-1", "claim": "x",
            "confidence": "high",
            "pins": [{"artifact": "a", "tool": "b",
                      "locator": {"type": "log_line", "value": "1"},
                      "raw_excerpt": "c",
                      "captured_at": "2026-04-25T22:00:00Z"}],
            "mitre_attck": techniques,
        }],
        state={
            "incident_id": "case-small-attck", "severity": "high",
            "_detected_os": "linux",
            "attack_techniques": techniques,
            "affected_hosts": [], "affected_users": [],
            "affected_services": [], "affected_data": [],
        },
    )
    md = _render(case)
    glance = md.split("## At a Glance", 1)[1].split("\n## ", 1)[0]
    assert "showing" not in glance
    for t in techniques:
        assert t in glance


# ──────────────────────────────────────────────────────────────────────────
# Egress destinations surfaced separately from victims
# ──────────────────────────────────────────────────────────────────────────


def test_egress_destinations_row_appears_when_present(tmp_path: Path) -> None:
    case = tmp_path / "case-egress"
    _write_case(case,
        findings=[],
        state={
            "incident_id": "case-egress", "severity": "high",
            "_detected_os": "linux",
            "attack_techniques": ["T1041"],
            "affected_hosts": ["10.0.0.5"],
            "affected_users": [], "affected_services": [],
            "affected_data": [],
            "egress_destinations": ["219.93.175.67"],
        },
    )
    md = _render(case)
    assert "Egress destinations" in md
    assert "219.93.175.67" in md
    # And it must NOT be lumped into the hosts row
    hosts_line = [ln for ln in md.splitlines() if ln.startswith("- **Affected hosts**")][0]
    assert "219.93.175.67" not in hosts_line
