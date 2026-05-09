"""MCP server tool registration + dispatch tests (Sub-Plan 04 / T7).

Verifies that `memory_volatility` and `linux_history_parse` — both promoted
from NotImplementedError stubs to real implementations in T6 and W4 — are
exposed via the MCP `list_tools()` registry and routed by the `call_tool()`
dispatcher. Without this wiring, MCP clients (the orchestrator, Claude
Code) cannot reach either tool regardless of how complete the underlying
implementation is.

Tests rely on the autouse `_sandbox_env` fixture in conftest.py to seed
EVIDENCE_PATH/OUTPUT_PATH; we deliberately do not duplicate that
monkeypatch here because the autouse fixture also reloads the sandbox
module and re-setting env mid-test would diverge from the live
INPUT_ROOT/OUTPUT_ROOT module-level constants.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest


def test_memory_volatility_listed_in_tools() -> None:
    """memory_volatility appears in list_tools() with correct schema."""
    from protocol_sift_mcp.server import list_tools

    tools = asyncio.run(list_tools())
    names = [t.name for t in tools]
    assert "memory_volatility" in names

    mv = next(t for t in tools if t.name == "memory_volatility")
    props = mv.inputSchema["properties"]
    assert "image_path" in props
    assert "plugin" in props
    assert "args" in props
    assert "timeout_sec" in props
    assert "image_path" in mv.inputSchema["required"]
    assert "plugin" in mv.inputSchema["required"]


def test_linux_history_parse_listed_in_tools() -> None:
    """linux_history_parse appears in list_tools() with correct schema."""
    from protocol_sift_mcp.server import list_tools

    tools = asyncio.run(list_tools())
    names = [t.name for t in tools]
    assert "linux_history_parse" in names

    lh = next(t for t in tools if t.name == "linux_history_parse")
    assert "history_path" in lh.inputSchema["properties"]
    assert "history_path" in lh.inputSchema["required"]


def test_call_tool_routes_linux_history_parse() -> None:
    """call_tool dispatches linux_history_parse and returns parsed JSON payload."""
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    p = input_dir / ".bash_history"
    p.write_text("ls -la\necho hi\n")

    from protocol_sift_mcp.server import call_tool

    result = asyncio.run(call_tool("linux_history_parse", {"history_path": str(p)}))
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert isinstance(payload, list)
    assert len(payload) == 2
    assert payload[0]["command"] == "ls -la"
    assert payload[1]["command"] == "echo hi"


def test_call_tool_routes_memory_volatility_rejects_bad_plugin() -> None:
    """call_tool dispatches memory_volatility; bad plugin surfaces as ValueError."""
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    img = input_dir / "memory.raw"
    img.write_bytes(b"\x00" * 16)

    from protocol_sift_mcp.server import call_tool

    with pytest.raises(ValueError) as exc_info:
        asyncio.run(
            call_tool(
                "memory_volatility",
                {"image_path": str(img), "plugin": "windows.evilplugin"},
            )
        )
    msg = str(exc_info.value).lower()
    assert "allowlist" in msg or "evilplugin" in msg
