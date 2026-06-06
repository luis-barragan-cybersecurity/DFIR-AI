"""``providers.tool_dispatch`` in-process MCP tool runner.

Pins ISC-17..19. Tests assert that:

- The bare and namespaced tool-name forms both dispatch correctly.
- The dispatch surface mirrors the MCP server: at least one tool per module
  routes to the correct underlying ``protocol_sift_mcp.tools.*`` function.
- Unknown tool names raise ``ProviderToolError`` (typed), not ``KeyError``.
- Underlying tool exceptions are wrapped as ``ProviderToolError`` with both
  the tool name and the offending argument excerpt.

Heavy tools (Volatility, plaso, EZ Tools) are not exercised — they need real
binaries / evidence. The lightweight parse + audit + finding probes prove the
dispatch wiring; the heavy tools share the exact same shape.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mh_orchestrator.providers import ProviderToolError, dispatch_tool
from mh_orchestrator.providers.tool_dispatch import _bare_name, mcp_tool_schemas


def test_bare_name_strips_namespace_prefix():
    assert _bare_name("mcp__protocol_sift__hash") == "hash"
    assert _bare_name("hash") == "hash"
    assert _bare_name("mcp__protocol_sift__win_evtx_query") == "win_evtx_query"


@pytest.fixture
def sandboxed(tmp_path, monkeypatch):
    """Re-anchor the MCP sandbox roots at tmp_path.

    ``protocol_sift_mcp.sandbox`` reads EVIDENCE_PATH / OUTPUT_PATH at import
    time, so a runtime env change has no effect — patch the module globals."""
    import protocol_sift_mcp.sandbox as sb
    input_root = tmp_path / "input"
    output_root = tmp_path / "out"
    input_root.mkdir()
    output_root.mkdir()
    monkeypatch.setattr(sb, "INPUT_ROOT", input_root.resolve())
    monkeypatch.setattr(sb, "OUTPUT_ROOT", output_root.resolve())
    monkeypatch.setenv("EVIDENCE_PATH", str(input_root))
    monkeypatch.setenv("OUTPUT_PATH", str(output_root))
    return input_root, output_root


def test_unknown_tool_raises_typed_error():
    with pytest.raises(ProviderToolError, match="unknown tool"):
        dispatch_tool("not_a_real_tool", {})


def test_namespaced_unknown_tool_also_raises():
    with pytest.raises(ProviderToolError, match="unknown tool"):
        dispatch_tool("mcp__protocol_sift__not_a_real_tool", {})


def test_underlying_tool_exception_wraps_to_provider_tool_error(sandboxed):
    """A tool function that raises must produce a ProviderToolError that
    preserves the tool name + an argument excerpt for forensic auditability."""
    with pytest.raises(ProviderToolError) as exc_info:
        dispatch_tool("magic_check", {"path": "/etc/passwd"})
    assert "magic_check" in str(exc_info.value)
    assert "args=" in str(exc_info.value)


def test_dispatch_parse_module_magic_check(sandboxed):
    input_root, _ = sandboxed
    target = input_root / "probe.bin"
    target.write_bytes(b"\x4d\x5a\x90\x00DOS")
    result = dispatch_tool("magic_check", {"path": str(target)})
    assert isinstance(result, dict)
    assert result.get("path") == str(target.resolve())
    assert "head_hex" in result
    assert result.get("size") == len(b"\x4d\x5a\x90\x00DOS")


def test_dispatch_parse_module_os_detect(sandboxed):
    input_root, _ = sandboxed
    target = input_root / "thing.bin"
    target.write_bytes(b"\x00" * 256)
    result = dispatch_tool("mcp__protocol_sift__os_detect", {"path": str(target)})
    assert isinstance(result, dict)
    assert "os" in result
    assert "evidence_class" in result


def test_dispatch_evidence_module_hash(sandboxed):
    input_root, _ = sandboxed
    target = input_root / "data.bin"
    target.write_bytes(b"hello world")
    result = dispatch_tool("hash", {"path": str(target)})
    assert isinstance(result, dict)
    assert "hash" in result
    digest_str = result["hash"]
    assert "sha256" in digest_str or "size" in digest_str


def test_dispatch_audit_module_audit_append(sandboxed):
    _, output_root = sandboxed
    result = dispatch_tool(
        "audit_append",
        {"event": "test_event", "data": {"key": "value"}},
    )
    assert isinstance(result, dict)
    audit_file = output_root / "audit.jsonl"
    assert audit_file.exists()
    lines = audit_file.read_text().splitlines()
    assert any("test_event" in line for line in lines)


def test_dispatch_finding_module_rejects_unpinned(sandboxed):
    """ISC-19 corollary: the finding module's own rejection of unpinned
    findings must surface as a ProviderToolError, not a bare exception."""
    with pytest.raises(ProviderToolError):
        dispatch_tool(
            "finding_record",
            {
                "finding_id": "F-test-001",
                "claim": "trying to record without pins",
                "confidence": "confirmed",
                "confidence_rationale": "test does not need a real reason",
                "pins": [],
            },
        )


def test_mcp_tool_schemas_loads_full_surface():
    """``mcp_tool_schemas`` must return every tool the MCP server registers
    in the right shape — providers translate this list directly into their
    tool wire format."""
    schemas = mcp_tool_schemas()
    assert isinstance(schemas, list)
    assert len(schemas) >= 30  # current surface is 47 tools; floor of 30 is safe.
    sample = schemas[0]
    assert {"name", "description", "input_schema"} <= sample.keys()
    names = {s["name"] for s in schemas}
    # Sanity: at least one tool per module we explicitly dispatch.
    for required in ("hash", "audit_append", "finding_record", "magic_check",
                     "os_detect", "win_registry_get", "memory_volatility",
                     "yara_scan", "tsk_fls", "zeek_log_read"):
        assert required in names, f"missing tool {required!r} from schema surface"
