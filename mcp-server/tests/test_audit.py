"""Audit log tests. Plain append-only JSONL — no hash links, no signing."""
from __future__ import annotations

import json
from pathlib import Path

from protocol_sift_mcp.tools import audit


def test_audit_append_writes_one_jsonl_line(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    entry = audit.audit_append(log, event="tool_call", data={"tool": "os_detect", "path": "/input/x.plist"})
    assert log.exists()
    with log.open() as f:
        line = f.readline().strip()
    parsed = json.loads(line)
    assert parsed["event"] == "tool_call"
    assert parsed["data"]["tool"] == "os_detect"
    assert "ts" in parsed
    assert parsed["seq"] == 0
    assert entry == parsed


def test_audit_append_increments_seq(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    audit.audit_append(log, event="tool_call", data={"tool": "a"})
    audit.audit_append(log, event="tool_call", data={"tool": "b"})
    audit.audit_append(log, event="finding_recorded", data={"id": "F-001"})
    lines = log.read_text().strip().split("\n")
    assert len(lines) == 3
    seqs = [json.loads(line)["seq"] for line in lines]
    assert seqs == [0, 1, 2]


def test_audit_append_creates_parent_dir(tmp_path: Path) -> None:
    log = tmp_path / "deep" / "nested" / "audit.jsonl"
    audit.audit_append(log, event="tool_call", data={})
    assert log.exists()


def test_agent_message_append(tmp_path: Path) -> None:
    log = tmp_path / "agent_messages.jsonl"
    e = audit.agent_message_append(
        log,
        from_agent="triage-orchestrator",
        to_agent="windows-agent",
        role="dispatch",
        content="Analyze NTUSER.DAT for persistence keys",
        metadata={"artifact": "/input/NTUSER.DAT"},
    )
    assert e["from_agent"] == "triage-orchestrator"
    assert e["to_agent"] == "windows-agent"
    assert e["role"] == "dispatch"
    assert e["metadata"]["artifact"] == "/input/NTUSER.DAT"


import asyncio

from protocol_sift_mcp.server import call_tool, list_tools


def test_mcp_tools_does_not_list_chain_tools() -> None:
    tools = asyncio.run(list_tools())
    names = {t.name for t in tools}
    assert "chain_append" not in names
    assert "chain_verify" not in names
    assert "chain_acknowledge_gap" not in names


def test_mcp_tools_lists_audit_append() -> None:
    tools = asyncio.run(list_tools())
    names = {t.name for t in tools}
    assert "audit_append" in names
