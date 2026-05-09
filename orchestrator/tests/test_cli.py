"""mh-orchestrate CLI tests."""
from __future__ import annotations


def test_cli_run_dry_run(tmp_path, monkeypatch):
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    case_dir = tmp_path / "cases" / "case-001"
    (case_dir / "input").mkdir(parents=True)
    (case_dir / "input" / "x.bin").write_bytes(b"\x00")
    (case_dir / "output").mkdir()

    from mh_orchestrator.cli import main
    # Recursion limit must comfortably cover the full §11.2 walk
    # (15 nodes happy path + bounded retries).
    rc = main(["run", "case-001", "--cases-dir", str(tmp_path / "cases"),
               "--recursion-limit", "50"])
    assert rc == 0
    assert (case_dir / "output" / "state.json").exists()
    assert (case_dir / "output" / "agent_messages.jsonl").exists()


def test_cli_missing_evidence_returns_2(tmp_path, monkeypatch):
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    cases = tmp_path / "cases"
    cases.mkdir()
    from mh_orchestrator.cli import main
    rc = main(["run", "nonexistent", "--cases-dir", str(cases)])
    assert rc == 2
