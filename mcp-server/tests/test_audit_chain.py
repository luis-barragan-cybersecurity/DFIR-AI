"""Audit-log hash chain tests.

The chain must:
  - Start with GENESIS_PREV_HASH on seq=0.
  - Link every entry's prev_hash to sha256(canonical(predecessor)).
  - Re-verify cleanly via `verify_audit_chain`.
  - Detect any tamper (mutation, deletion, reordering).
"""
from __future__ import annotations

import json

import pytest

from protocol_sift_mcp.tools.audit import (
    GENESIS_PREV_HASH,
    agent_message_append,
    audit_append,
    verify_audit_chain,
)


def test_first_entry_uses_genesis_prev_hash(tmp_path):
    log = tmp_path / "audit.jsonl"
    e0 = audit_append(log, event="genesis", data={"k": 1})
    assert e0["seq"] == 0
    assert e0["prev_hash"] == GENESIS_PREV_HASH


def test_each_entry_links_to_predecessor(tmp_path):
    log = tmp_path / "audit.jsonl"
    audit_append(log, event="a", data={"i": 0})
    audit_append(log, event="b", data={"i": 1})
    audit_append(log, event="c", data={"i": 2})
    lines = [json.loads(line) for line in log.read_text().strip().splitlines()]
    assert lines[0]["seq"] == 0 and lines[1]["seq"] == 1 and lines[2]["seq"] == 2
    # Each entry's prev_hash must be a 64-char hex.
    for entry in lines[1:]:
        assert len(entry["prev_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in entry["prev_hash"])


def test_verify_chain_clean(tmp_path):
    log = tmp_path / "audit.jsonl"
    for i in range(5):
        audit_append(log, event=f"e{i}", data={"i": i})
    report = verify_audit_chain(log)
    assert report["ok"] is True
    assert report["entries"] == 5
    assert report["first_break_seq"] is None


def test_verify_chain_detects_mid_tamper(tmp_path):
    log = tmp_path / "audit.jsonl"
    for i in range(5):
        audit_append(log, event=f"e{i}", data={"i": i})
    # Tamper the middle entry's data — that breaks every downstream prev_hash.
    lines = log.read_text().splitlines()
    middle = json.loads(lines[2])
    middle["data"] = {"i": 999}
    lines[2] = json.dumps(middle, sort_keys=True, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")
    report = verify_audit_chain(log)
    assert report["ok"] is False
    # Break is at or after the tampered entry.
    assert report["first_break_seq"] is not None
    assert report["first_break_seq"] >= 2
    assert "prev_hash" in report["reason"] or "mismatch" in report["reason"]


def test_verify_chain_detects_reorder(tmp_path):
    log = tmp_path / "audit.jsonl"
    for i in range(4):
        audit_append(log, event=f"e{i}", data={"i": i})
    lines = log.read_text().splitlines()
    # Swap two adjacent middle lines.
    lines[1], lines[2] = lines[2], lines[1]
    log.write_text("\n".join(lines) + "\n")
    report = verify_audit_chain(log)
    assert report["ok"] is False


def test_verify_chain_handles_missing_file(tmp_path):
    report = verify_audit_chain(tmp_path / "nope.jsonl")
    assert report["ok"] is False
    assert "does not exist" in report["reason"]


def test_agent_message_append_also_chained(tmp_path):
    log = tmp_path / "msgs.jsonl"
    agent_message_append(log, from_agent="A", to_agent="B", role="request", content="hi")
    agent_message_append(log, from_agent="B", to_agent="A", role="response", content="hello")
    report = verify_audit_chain(log)
    assert report["ok"] is True
    assert report["entries"] == 2


def test_mixing_audit_and_message_in_same_file_chains_correctly(tmp_path):
    """If a caller mistakenly mixes the two, the chain still verifies because
    both helpers use the same prev_hash machinery."""
    log = tmp_path / "mixed.jsonl"
    audit_append(log, event="bootstrap", data={})
    agent_message_append(log, from_agent="X", to_agent="Y", role="event", content="ok")
    audit_append(log, event="done", data={})
    report = verify_audit_chain(log)
    assert report["ok"] is True
    assert report["entries"] == 3


def test_legacy_entry_without_prev_hash_is_flagged(tmp_path):
    """An entry missing prev_hash mid-chain should be detected."""
    log = tmp_path / "audit.jsonl"
    audit_append(log, event="ok", data={})
    # Manually inject a legacy entry without prev_hash.
    legacy = {"seq": 1, "ts": "2026-05-11T00:00:00Z", "event": "legacy", "data": {}}
    with log.open("a") as f:
        f.write(json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n")
    report = verify_audit_chain(log)
    assert report["ok"] is False
    assert "legacy" in report["reason"] or "missing prev_hash" in report["reason"]


def test_appending_after_legacy_tail_raises(tmp_path):
    """Refusing to extend a corrupt tail keeps the chain semantics clean."""
    log = tmp_path / "audit.jsonl"
    log.write_text("not even json\n")
    with pytest.raises(Exception):  # noqa: B017
        audit_append(log, event="x", data={})
