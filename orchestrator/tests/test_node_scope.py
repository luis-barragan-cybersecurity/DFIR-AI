"""Tests for the scope node — pure-Python entity extractor."""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import scope
from mh_orchestrator.state import Artifact, new_state


def _state_with_findings(findings: list[dict], tmp_path: Path):
    s = new_state("scope-test")
    s["_findings"] = findings
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    return s


def test_compute_scope_extracts_users_from_claim(tmp_path: Path) -> None:
    s = _state_with_findings([
        {"claim": "User: alice ran cmd.exe", "pins": []},
        {"claim": "DOMAIN\\bob accessed lsass", "pins": []},
    ], tmp_path)
    out = scope.compute_scope(s)
    assert "alice" in out["affected_users"]
    assert "bob" in out["affected_users"]


def test_compute_scope_extracts_hosts_from_pins(tmp_path: Path) -> None:
    s = _state_with_findings([
        {
            "claim": "outbound C2",
            "pins": [
                {
                    "artifact": "memory.raw",
                    "tool": "windows.netscan",
                    "locator": {"type": "memory_vad", "value": "tcp 10.0.2.15:443"},
                    "raw_excerpt": "ForeignAddr 142.250.182.3 ESTABLISHED",
                    "captured_at": "2026-04-25T22:00:00Z",
                },
            ],
        },
    ], tmp_path)
    out = scope.compute_scope(s)
    assert "10.0.2.15" in out["affected_hosts"]
    assert "142.250.182.3" in out["affected_hosts"]


def test_compute_scope_extracts_services(tmp_path: Path) -> None:
    s = _state_with_findings([
        {
            "claim": "explorer.exe spawned cmd.exe",
            "pins": [],
        },
        {
            "claim": "systemd unit suspicious-helper.service masked",
            "pins": [],
        },
    ], tmp_path)
    out = scope.compute_scope(s)
    assert any("explorer.exe" in s_ for s_ in out["affected_services"])
    assert any("cmd.exe" in s_ for s_ in out["affected_services"])
    assert any(".service" in s_ for s_ in out["affected_services"])


def test_compute_scope_extracts_data_paths(tmp_path: Path) -> None:
    s = _state_with_findings([
        {
            "claim": "files staged at /tmp/exfil/data.tar",
            "pins": [
                {
                    "artifact": "C:\\Users\\alice\\Documents\\secrets.docx",
                    "tool": "win_lnk_parse",
                    "locator": {"type": "file_offset", "value": "0"},
                    "raw_excerpt": "...",
                    "captured_at": "2026-04-25T22:00:00Z",
                },
            ],
        },
    ], tmp_path)
    out = scope.compute_scope(s)
    assert any("/tmp/exfil" in d for d in out["affected_data"])
    assert any("secrets.docx" in d for d in out["affected_data"])


def test_compute_scope_handles_empty_findings(tmp_path: Path) -> None:
    s = new_state("scope-empty")
    out = scope.compute_scope(s)
    assert out == {
        "affected_hosts": [],
        "affected_users": [],
        "affected_services": [],
        "affected_data": [],
    }


def test_compute_scope_includes_forensic_artifact_paths(tmp_path: Path) -> None:
    s = new_state("scope-with-art")
    s["forensic_artifacts"] = [Artifact(path="/input/memory.raw")]
    out = scope.compute_scope(s)
    assert "/input/memory.raw" in out["affected_data"]


def test_run_mutates_state_with_scope_buckets(tmp_path: Path) -> None:
    s = _state_with_findings([
        {"claim": "User alice ran malware.exe on 10.0.0.5", "pins": []},
    ], tmp_path)
    out = scope.run(s)
    assert "alice" in out["affected_users"]
    assert "10.0.0.5" in out["affected_hosts"]
    assert any("malware.exe" in svc for svc in out["affected_services"])


def test_run_emits_audit_event(tmp_path: Path) -> None:
    s = _state_with_findings([
        {"claim": "user joe", "pins": []},
    ], tmp_path)
    scope.run(s)
    audit_path = Path(s["_output_dir"]) / "audit.jsonl"
    assert audit_path.exists()
    contents = audit_path.read_text()
    assert "scope_complete" in contents


def test_run_marks_csf_rs_an_01(tmp_path: Path) -> None:
    s = _state_with_findings([{"claim": "x", "pins": []}], tmp_path)
    out = scope.run(s)
    assert "RS.AN-01" in out["csf_subcategories_satisfied"]


def test_run_appends_to_node_history(tmp_path: Path) -> None:
    s = _state_with_findings([{"claim": "x", "pins": []}], tmp_path)
    out = scope.run(s)
    assert out["_node_history"][-1] == "scope"


def test_normalize_user_strips_domain() -> None:
    assert scope._normalize_user("DOMAIN\\bob") == "bob"
    assert scope._normalize_user("alice") == "alice"
    assert scope._normalize_user("1") == "sessionid:1"
