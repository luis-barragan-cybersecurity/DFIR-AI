"""MCP server entry point.

Wires the typed tool surface (evidence + finding + per-OS triage primitives)
to MCP's stdio protocol. Per-OS tools start as stubs with TODO markers; trust
primitives are real on day one because they gate everything else.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import audit as au
from .tools import evidence as ev
from .tools import finding as fd
from .tools import macos as mac
from .tools import parse as ps
from .tools import windows as win

OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "/output"))
AUDIT_PATH = OUTPUT_PATH / "audit.jsonl"
FINDINGS_PATH = OUTPUT_PATH / "findings.json"

server: Server = Server("protocol-sift")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="hash",
            description="Compute sha256 + sha1 of an evidence file. Returns {sha256, sha1, size}.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        Tool(
            name="audit_append",
            description=(
                "Append a tool-call or lifecycle event to the plain audit log. "
                "Use when an event needs durable record. Most events are auto-logged "
                "by the PostToolUse hook."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "event": {"type": "string"},
                    "data": {"type": "object"},
                },
                "required": ["event", "data"],
            },
        ),
        Tool(
            name="finding_record",
            description=(
                "REJECTS if pins[] is empty — record gaps as a separate finding with "
                "confidence='unknown', at least one pin pointing at the artifact you "
                "could not conclude on, and a claim describing the gap."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "claim": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["confirmed", "inferred", "uncertain", "unknown"],
                    },
                    "confidence_rationale": {
                        "type": "string",
                        "minLength": 1,
                        "description": (
                            "One-sentence justification of the chosen confidence "
                            "in the form 'X because Y'. Mandatory; the schema rejects "
                            "missing/empty rationale."
                        ),
                    },
                    "pins": {"type": "array", "minItems": 1},
                    "mitre_attck": {"type": "array", "items": {"type": "string"}},
                    "related_findings": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["finding_id", "claim", "confidence", "confidence_rationale", "pins"],
            },
        ),
        Tool(
            name="win_registry_get",
            description=(
                "Read a Windows registry key from a hive (NTUSER.DAT, SOFTWARE, SYSTEM, "
                "SAM, USRCLASS.DAT). Returns {path, timestamp, hive_type, subkeys, values}. "
                "Each value includes raw_hex for evidence pinning. Empty registry_path = root."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string", "description": "Path to hive under /input"},
                    "registry_path": {
                        "type": "string",
                        "description": (
                            "Backslash path under hive root, "
                            "e.g. Software\\\\Microsoft\\\\Windows"
                        ),
                        "default": "",
                    },
                },
                "required": ["hive_path"],
            },
        ),
        Tool(
            name="win_prefetch_parse",
            description=(
                "Parse a Windows .pf prefetch file. Returns executable_name, version, "
                "run_count, last_run_times (up to 8 for Win8+), volumes, files_accessed, "
                "directories. Prefetch is the strongest single-source proof of execution."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "prefetch_path": {"type": "string", "description": "Path to .pf under /input"},
                },
                "required": ["prefetch_path"],
            },
        ),
        Tool(
            name="win_evtx_query",
            description=(
                "Query a Windows Event Log (.evtx). Returns {record_id, eid, channel, "
                "time_created, computer, xml} per record. Filter by event_ids and time_range. "
                "xml is the raw record — cite as raw_excerpt in pins."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {"type": "string", "description": "Path to .evtx under /input"},
                    "event_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Filter to these EIDs (e.g. [4624, 4625, 4648])",
                    },
                    "time_range": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": {"type": "string"},
                        "description": "(since_iso, until_iso) inclusive",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 1000,
                        "minimum": 1,
                        "maximum": 100000,
                    },
                },
                "required": ["log_path"],
            },
        ),
        Tool(
            name="win_lnk_parse",
            description=(
                "Parse a Windows shortcut (.lnk). Returns target, target MACB timestamps, "
                "drive serial + type, machine_id, working_dir, arguments, network_share. "
                "Use for File/Folder Opening + USB activity reconstruction."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "lnk_path": {"type": "string", "description": "Path to .lnk under /input"},
                },
                "required": ["lnk_path"],
            },
        ),
        Tool(
            name="os_detect",
            description=(
                "Identify which OS produced this evidence artifact. Returns "
                "{os: windows|macos|linux|memory_dump|unknown, confidence: 0-1, "
                "evidence_class, signals[], is_directory, size}. Use first on every "
                "ingested artifact to route to the correct OS specialist subagent. "
                "Confidence < 0.6 should trigger a second-signal lookup or a finding marked confidence='uncertain'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to file or directory under /input",
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="magic_check",
            description="Read first 16 bytes + size of a file. Quick signature probe.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        Tool(
            name="mac_plist_get",
            description=(
                "Parse a macOS property list (XML or binary). Returns {path, format, "
                "size, root_keys, key_path, value, value_type}. key_path is dot-separated "
                "(e.g. 'Apps.com.apple.dock.RecentDocs.0'). Bytes coerced to hex for JSON safety."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "plist_path": {"type": "string", "description": "Path to .plist under /input"},
                    "key_path": {
                        "type": "string",
                        "description": "Optional dot-separated traversal; empty = root",
                        "default": "",
                    },
                },
                "required": ["plist_path"],
            },
        ),
        Tool(
            name="mac_knowledgec_query",
            description=(
                "Read-only SQLite query against knowledgeC.db (app usage, screen time, "
                "focus). Pass either {table} for full dump or {sql} for SELECT/WITH only. "
                "Located at ~/Library/Application Support/Knowledge/knowledgeC.db."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {"type": "string"},
                    "table": {"type": "string", "description": "Table name to dump"},
                    "sql": {"type": "string", "description": "Custom SELECT/WITH query"},
                    "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 100000},
                },
                "required": ["db_path"],
            },
        ),
        Tool(
            name="memory_volatility",
            description=(
                "Wrap Volatility 3 CLI to parse a memory dump. Plugin must be in "
                "the allowlist (windows.* / linux.* / mac.* — see ALLOWED_PLUGINS). "
                "Image path sandbox-asserted under /input. Returns parsed JSON list."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Path to memory image (under /input)",
                    },
                    "plugin": {
                        "type": "string",
                        "description": "Volatility 3 plugin name (e.g., windows.pslist)",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional CLI args passed to vol",
                        "default": [],
                    },
                    "timeout_sec": {
                        "type": "integer",
                        "default": 300,
                        "minimum": 1,
                        "maximum": 1800,
                    },
                },
                "required": ["image_path", "plugin"],
            },
        ),
        Tool(
            name="linux_history_parse",
            description=(
                "Parse bash/zsh shell history file. Auto-detects format "
                "(plain bash, bash with HISTTIMEFORMAT, or zsh extended). "
                "Returns list of {line_num, ts, command, raw_excerpt} entries."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "history_path": {
                        "type": "string",
                        "description": "Path to .bash_history / .zsh_history (under /input)",
                    },
                },
                "required": ["history_path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "hash":
        digest = ev.hash_file(Path(arguments["path"]))
        return [TextContent(type="text", text=str(digest))]
    if name == "audit_append":
        entry = au.audit_append(
            AUDIT_PATH,
            event=arguments["event"],
            data=arguments["data"],
        )
        return [TextContent(type="text", text=str(entry))]
    if name == "finding_record":
        record = fd.finding_record(FINDINGS_PATH, arguments)
        au.audit_append(
            AUDIT_PATH,
            event="finding_recorded",
            data={"finding_id": record["finding_id"]},
        )
        return [TextContent(type="text", text=str(record))]
    if name == "win_registry_get":
        result = win.win_registry_get(
            arguments["hive_path"],
            arguments.get("registry_path", ""),
        )
        return [TextContent(type="text", text=str(result))]
    if name == "win_prefetch_parse":
        result = win.win_prefetch_parse(arguments["prefetch_path"])
        return [TextContent(type="text", text=str(result))]
    if name == "win_evtx_query":
        time_range_arg = arguments.get("time_range")
        time_tuple = (
            (time_range_arg[0], time_range_arg[1])
            if time_range_arg and len(time_range_arg) == 2
            else None
        )
        result = win.win_evtx_query(
            arguments["log_path"],
            event_ids=arguments.get("event_ids"),
            time_range=time_tuple,
            limit=arguments.get("limit", 1000),
        )
        return [TextContent(type="text", text=str(result))]
    if name == "win_lnk_parse":
        result = win.win_lnk_parse(arguments["lnk_path"])
        return [TextContent(type="text", text=str(result))]
    if name == "os_detect":
        result = ps.os_detect(arguments["path"])
        return [TextContent(type="text", text=str(result))]
    if name == "magic_check":
        result = ps.magic_check(arguments["path"])
        return [TextContent(type="text", text=str(result))]
    if name == "mac_plist_get":
        result = mac.mac_plist_get(
            arguments["plist_path"],
            arguments.get("key_path", ""),
        )
        return [TextContent(type="text", text=str(result))]
    if name == "mac_knowledgec_query":
        result = mac.mac_knowledgec_query(
            arguments["db_path"],
            sql=arguments.get("sql"),
            table=arguments.get("table"),
            limit=arguments.get("limit", 100),
        )
        return [TextContent(type="text", text=str(result))]
    if name == "memory_volatility":
        from .tools.memory import memory_volatility

        mem_result = memory_volatility(
            arguments["image_path"],
            arguments["plugin"],
            args=arguments.get("args"),
            timeout_sec=arguments.get("timeout_sec", 300),
        )
        return [TextContent(type="text", text=json.dumps(mem_result, default=str))]
    if name == "linux_history_parse":
        from .tools.linux import linux_history_parse

        hist_result = linux_history_parse(arguments["history_path"])
        return [TextContent(type="text", text=json.dumps(hist_result, default=str))]
    raise ValueError(f"Unknown tool: {name}")


def main() -> None:
    import asyncio

    async def _run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
