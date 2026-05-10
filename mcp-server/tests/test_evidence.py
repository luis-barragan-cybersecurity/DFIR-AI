"""Hash file tests."""
from __future__ import annotations

from pathlib import Path

from protocol_sift_mcp.tools import evidence as ev


def test_hash_file_dual_algorithm(tmp_path: Path) -> None:
    f = tmp_path / "input" / "sample.bin"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(b"The quick brown fox jumps over the lazy dog")
    digest = ev.hash_file(f)
    assert digest["sha256"] == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    assert digest["sha1"] == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    assert digest["size"] == 43


def test_ingest_artifact_writes_to_audit_log(tmp_path: Path) -> None:
    # conftest autouse fixture already created input/ and output/ + set EVIDENCE_PATH/OUTPUT_PATH.
    input_dir = tmp_path / "input"
    artifact = input_dir / "sample.bin"
    artifact.write_bytes(b"hello")

    audit_log = tmp_path / "output" / "audit.jsonl"

    entry = ev.ingest_artifact(audit_log, artifact)
    assert entry["event"] == "evidence_ingest"
    assert "sha256" in entry["data"]
    assert audit_log.exists()
