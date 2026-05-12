"""Tests for the cross-finding correlator node."""
from __future__ import annotations

from mh_orchestrator.nodes.correlate import correlate_findings, run
from mh_orchestrator.state import new_state


def _f(fid, claim, *, confidence="confirmed", mitre=None, related=None):
    return {
        "finding_id": fid,
        "claim": claim,
        "confidence": confidence,
        "confidence_rationale": "test fixture",
        "pins": [{"artifact": "a", "tool": "t",
                  "locator": {"type": "log_line", "value": "1"},
                  "raw_excerpt": "x",
                  "captured_at": "2026-05-11T00:00:00Z"}],
        "mitre_attck": list(mitre or []),
        "related_findings": list(related or []),
    }


def test_correlate_empty_findings():
    r = correlate_findings([])
    assert r["finding_count"] == 0
    assert r["contradictions"] == []
    assert r["tactic_gaps"] == []
    assert r["confidence_mismatches"] == []


def test_contradiction_detection_pid():
    findings = [
        _f("F-1", "Process exited cleanly PID=1234 at 22:00"),
        _f("F-2", "Process running and active PID=1234 at 22:05"),
    ]
    r = correlate_findings(findings)
    assert len(r["contradictions"]) == 1
    c = r["contradictions"][0]
    assert {c["finding_a"], c["finding_b"]} == {"F-1", "F-2"}
    assert "1234" in c["shared_subject"]


def test_no_contradiction_when_no_shared_subject():
    findings = [
        _f("F-1", "Process exited PID=1234"),
        _f("F-2", "Process running PID=5678"),
    ]
    r = correlate_findings(findings)
    assert r["contradictions"] == []


def test_tactic_gap_detection():
    # Execution observed but Persistence + Defense Evasion missing.
    findings = [_f("F-1", "PowerShell launched", mitre=["T1059.001"])]
    r = correlate_findings(findings)
    gaps = r["tactic_gaps"]
    assert any(g["observed_tactic"] == "Execution" for g in gaps)


def test_no_gap_when_neighbors_present():
    findings = [
        _f("F-1", "Execution", mitre=["T1059.001"]),       # Execution
        _f("F-2", "Run key set", mitre=["T1547.001"]),     # Persistence
        _f("F-3", "Obfuscated", mitre=["T1027"]),          # Defense Evasion
    ]
    r = correlate_findings(findings)
    exec_gaps = [g for g in r["tactic_gaps"] if g["observed_tactic"] == "Execution"]
    # Execution's expected neighbors (Persistence + Defense Evasion) are
    # present, so no gap reported for Execution.
    if exec_gaps:
        assert "Persistence" not in exec_gaps[0]["missing_neighbors"]
        assert "Defense Evasion" not in exec_gaps[0]["missing_neighbors"]


def test_confidence_mismatch_when_confirmed_cites_uncertain():
    findings = [
        _f("F-1", "high-confidence claim", confidence="confirmed",
           related=["F-2"]),
        _f("F-2", "weak supporting finding", confidence="uncertain"),
    ]
    r = correlate_findings(findings)
    assert len(r["confidence_mismatches"]) == 1
    m = r["confidence_mismatches"][0]
    assert m["claimant_id"] == "F-1"
    assert m["supporting_id"] == "F-2"


def test_no_mismatch_when_dependent_is_less_confident():
    """Inferred citing confirmed is fine — supporting evidence is stronger."""
    findings = [
        _f("F-1", "tentative", confidence="inferred", related=["F-2"]),
        _f("F-2", "rock solid", confidence="confirmed"),
    ]
    r = correlate_findings(findings)
    assert r["confidence_mismatches"] == []


def test_run_persists_correlation_and_audit(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    state = new_state("case-correlator")
    state["_output_dir"] = str(out)
    state["_findings"] = [
        _f("F-1", "Process exited PID=99"),
        _f("F-2", "Process active PID=99"),
    ]
    run(state)
    # Audit event landed.
    audit_lines = (out / "audit.jsonl").read_text().splitlines()
    assert any("correlation_complete" in line for line in audit_lines)
    # Report attached to state.
    assert "_correlation" in state  # type: ignore[operator]
    report = state["_correlation"]  # type: ignore[index]
    assert report["finding_count"] == 2
    assert len(report["contradictions"]) >= 1


def test_run_adds_self_to_node_history(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    state = new_state("case-h")
    state["_output_dir"] = str(out)
    state["_findings"] = []
    run(state)
    assert "correlate" in state["_node_history"]
