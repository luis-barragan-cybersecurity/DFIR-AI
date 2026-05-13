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
        Tool(
            name="yara_scan",
            description=(
                "Compile a YARA ruleset and scan a target file or directory under /input. "
                "Returns hits: {path, rule, namespace, tags, strings: [{identifier, offset, data_hex}]}. "
                "Bounded by max_hits to prevent OOM."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_path": {"type": "string", "description": "File or dir under /input"},
                    "rule_path":   {"type": "string", "description": "Path to .yar/.yara rule file"},
                    "recursive":   {"type": "boolean", "default": True},
                    "max_hits":    {"type": "integer", "default": 10000, "minimum": 1},
                },
                "required": ["target_path", "rule_path"],
            },
        ),
        Tool(
            name="memprocfs_findevil",
            description=(
                "Run MemProcFS FindEvil over a memory image and return parsed hit lines. "
                "Linux-only; requires the memprocfs binary. Mounts read-only via FUSE."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Memory image under /input"},
                    "mount_point": {"type": "string", "default": "/tmp/memprocfs-mh"},  # noqa: S108
                    "timeout_sec": {"type": "integer", "default": 1200, "minimum": 60, "maximum": 7200},
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="tsk_fls",
            description=(
                "Sleuth Kit `fls` — list files + directories in a disk image. "
                "Returns rows: {type, flags, inode, name}. recursive=True for full tree."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "inode":      {"type": "string"},
                    "recursive":  {"type": "boolean", "default": False},
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="tsk_icat",
            description=(
                "Sleuth Kit `icat` — extract file content by inode from a disk image. "
                "Returns {size_bytes, truncated, data_hex}. Bounded by max_bytes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "inode":      {"type": "string"},
                    "max_bytes":  {"type": "integer", "default": 52428800, "minimum": 1},
                },
                "required": ["image_path", "inode"],
            },
        ),
        Tool(
            name="tsk_mmls",
            description="Sleuth Kit `mmls` — list disk partition layout.",
            inputSchema={
                "type": "object",
                "properties": {"image_path": {"type": "string"}},
                "required": ["image_path"],
            },
        ),
        Tool(
            name="tsk_mactime",
            description=(
                "Sleuth Kit `mactime` — render an fls-generated bodyfile into a MACB "
                "timeline. body_path lives under /input."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "body_path":     {"type": "string"},
                    "output_format": {"type": "string", "enum": ["csv", "year"], "default": "csv"},
                },
                "required": ["body_path"],
            },
        ),
        Tool(
            name="tsk_istat",
            description="Sleuth Kit `istat` — detailed metadata about an inode in a disk image.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "inode":      {"type": "string"},
                },
                "required": ["image_path", "inode"],
            },
        ),
        Tool(
            name="plaso_log2timeline",
            description=(
                "Plaso `log2timeline.py` — extract a .plaso storage file from a source. "
                "source under /input, storage under /output. parsers defaults to "
                "'win_gen,webhist,sysreg' (IR triage subset); pass 'all' for full pass."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "source_path":  {"type": "string"},
                    "storage_path": {"type": "string"},
                    "parsers":      {"type": "string", "default": "win_gen,webhist,sysreg"},
                    "timeout_sec":  {"type": "integer", "default": 3600, "minimum": 60, "maximum": 14400},
                },
                "required": ["source_path", "storage_path"],
            },
        ),
        Tool(
            name="plaso_psort",
            description=(
                "Plaso `psort.py` — render a .plaso store into a sorted timeline. "
                "Default format json_line; events[] returned inline up to max_events."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "storage_path":  {"type": "string"},
                    "output_format": {"type": "string", "default": "json_line",
                                      "enum": ["json_line", "l2tcsv", "l2ttln", "dynamic", "tln"]},
                    "output_path":   {"type": "string"},
                    "max_events":    {"type": "integer", "default": 200000, "minimum": 1},
                },
                "required": ["storage_path"],
            },
        ),
        Tool(
            name="ez_evtxecmd",
            description=(
                "EZ Tools EvtxECmd — Windows event log parser (CSV output). "
                "Requires dotnet runtime + EZ_TOOLS_DIR. Falls back: use win_evtx_query."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path":    {"type": "string"},
                    "output_dir":  {"type": "string"},
                    "max_rows":    {"type": "integer", "default": 100000, "minimum": 1},
                },
                "required": ["log_path", "output_dir"],
            },
        ),
        Tool(
            name="ez_mftecmd",
            description="EZ Tools MFTECmd — NTFS $MFT parser (CSV output).",
            inputSchema={
                "type": "object",
                "properties": {
                    "mft_path":   {"type": "string"},
                    "output_dir": {"type": "string"},
                    "max_rows":   {"type": "integer", "default": 100000},
                },
                "required": ["mft_path", "output_dir"],
            },
        ),
        Tool(
            name="ez_recmd",
            description=(
                "EZ Tools RECmd — registry hive parser. Pass batch_keyword to run a "
                "named Batch (e.g. 'RegistryASEPs'). Falls back: win_registry_get."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path":     {"type": "string"},
                    "output_dir":    {"type": "string"},
                    "batch_keyword": {"type": "string"},
                },
                "required": ["hive_path", "output_dir"],
            },
        ),
        Tool(
            name="ez_amcacheparser",
            description="EZ Tools AmcacheParser — Amcache.hve execution evidence parser.",
            inputSchema={
                "type": "object",
                "properties": {
                    "amcache_path": {"type": "string"},
                    "output_dir":   {"type": "string"},
                },
                "required": ["amcache_path", "output_dir"],
            },
        ),
        Tool(
            name="tshark_extract",
            description=(
                "Wireshark `tshark` field extraction over a pcap. fields[] is the column "
                "list; display_filter is a sanitized Wireshark filter string."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path":      {"type": "string"},
                    "display_filter": {"type": "string"},
                    "fields":         {"type": "array", "items": {"type": "string"}},
                    "max_rows":       {"type": "integer", "default": 100000},
                },
                "required": ["pcap_path"],
            },
        ),
        Tool(
            name="zeek_log_read",
            description=(
                "Read a Zeek TSV log (conn.log, dns.log, ssl.log, etc.). Honors "
                "#fields header for column names; returns rows + fields."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {"type": "string"},
                    "max_rows": {"type": "integer", "default": 100000},
                },
                "required": ["log_path"],
            },
        ),
        Tool(
            name="bulk_extractor",
            description=(
                "bulk_extractor — pull IPs/URLs/emails/CCN patterns from any blob. "
                "Writes feature files under output_dir (must live under /output)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "output_dir": {"type": "string"},
                    "features":   {"type": "string", "default": "all"},
                },
                "required": ["image_path", "output_dir"],
            },
        ),
        Tool(
            name="binwalk",
            description=(
                "binwalk — identify embedded files / firmware structure in a binary. "
                "recursive=True enables matryoshka mode."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_path": {"type": "string"},
                    "recursive":   {"type": "boolean", "default": False},
                },
                "required": ["target_path"],
            },
        ),
        Tool(
            name="strings_extract",
            description=(
                "Pure-Python ASCII strings extraction. Returns {offset, length, ascii} "
                "per hit. No subprocess; bounded by max_strings + 1 GiB read cap."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_path": {"type": "string"},
                    "min_length":  {"type": "integer", "default": 6, "minimum": 4},
                    "max_strings": {"type": "integer", "default": 100000, "minimum": 1},
                },
                "required": ["target_path"],
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
    if name == "yara_scan":
        from .tools.parse import yara_scan

        yres = yara_scan(
            arguments["target_path"], arguments["rule_path"],
            recursive=arguments.get("recursive", True),
            max_hits=arguments.get("max_hits", 10000),
        )
        return [TextContent(type="text", text=json.dumps(yres, default=str))]
    if name == "memprocfs_findevil":
        from .tools.memory import memprocfs_findevil

        mres = memprocfs_findevil(
            arguments["memory_path"],
            mount_point=arguments.get("mount_point", "/tmp/memprocfs-mh"),  # noqa: S108
            timeout_sec=arguments.get("timeout_sec", 1200),
        )
        return [TextContent(type="text", text=json.dumps(mres, default=str))]
    if name == "tsk_fls":
        from .tools.filesystem import fls

        fres = fls(arguments["image_path"], inode=arguments.get("inode"),
                   recursive=arguments.get("recursive", False))
        return [TextContent(type="text", text=json.dumps(fres, default=str))]
    if name == "tsk_icat":
        from .tools.filesystem import icat

        ires = icat(arguments["image_path"], arguments["inode"],
                    max_bytes=arguments.get("max_bytes", 52428800))
        return [TextContent(type="text", text=json.dumps(ires, default=str))]
    if name == "tsk_mmls":
        from .tools.filesystem import mmls

        mmres = mmls(arguments["image_path"])
        return [TextContent(type="text", text=json.dumps(mmres, default=str))]
    if name == "tsk_mactime":
        from .tools.filesystem import mactime

        mtres = mactime(arguments["body_path"],
                        output_format=arguments.get("output_format", "csv"))
        return [TextContent(type="text", text=json.dumps(mtres, default=str))]
    if name == "tsk_istat":
        from .tools.filesystem import istat

        isres = istat(arguments["image_path"], arguments["inode"])
        return [TextContent(type="text", text=json.dumps(isres, default=str))]
    if name == "plaso_log2timeline":
        from .tools.timeline import log2timeline

        l2t = log2timeline(
            arguments["source_path"], arguments["storage_path"],
            parsers=arguments.get("parsers", "win_gen,webhist,sysreg"),
            timeout_sec=arguments.get("timeout_sec", 3600),
        )
        return [TextContent(type="text", text=json.dumps(l2t, default=str))]
    if name == "plaso_psort":
        from .tools.timeline import psort

        psort_result = psort(
            arguments["storage_path"],
            output_format=arguments.get("output_format", "json_line"),
            output_path=arguments.get("output_path"),
            max_events=arguments.get("max_events", 200000),
        )
        return [TextContent(type="text", text=json.dumps(psort_result, default=str))]
    if name == "ez_evtxecmd":
        from .tools.win_artifacts import evtxecmd

        ez_result = evtxecmd(arguments["log_path"], arguments["output_dir"],
                             max_rows=arguments.get("max_rows", 100000))
        return [TextContent(type="text", text=json.dumps(ez_result, default=str))]
    if name == "ez_mftecmd":
        from .tools.win_artifacts import mftecmd

        mft = mftecmd(arguments["mft_path"], arguments["output_dir"],
                      max_rows=arguments.get("max_rows", 100000))
        return [TextContent(type="text", text=json.dumps(mft, default=str))]
    if name == "ez_recmd":
        from .tools.win_artifacts import recmd

        rec = recmd(arguments["hive_path"], arguments["output_dir"],
                    batch_keyword=arguments.get("batch_keyword"))
        return [TextContent(type="text", text=json.dumps(rec, default=str))]
    if name == "ez_amcacheparser":
        from .tools.win_artifacts import amcacheparser

        amc = amcacheparser(arguments["amcache_path"], arguments["output_dir"])
        return [TextContent(type="text", text=json.dumps(amc, default=str))]
    if name == "tshark_extract":
        from .tools.network import tshark_extract

        tsk = tshark_extract(
            arguments["pcap_path"],
            display_filter=arguments.get("display_filter"),
            fields=arguments.get("fields"),
            max_rows=arguments.get("max_rows", 100000),
        )
        return [TextContent(type="text", text=json.dumps(tsk, default=str))]
    if name == "zeek_log_read":
        from .tools.network import zeek_log_read

        zk = zeek_log_read(arguments["log_path"], max_rows=arguments.get("max_rows", 100000))
        return [TextContent(type="text", text=json.dumps(zk, default=str))]
    if name == "bulk_extractor":
        from .tools.carving import bulk_extractor

        be = bulk_extractor(arguments["image_path"], arguments["output_dir"],
                            features=arguments.get("features", "all"))
        return [TextContent(type="text", text=json.dumps(be, default=str))]
    if name == "binwalk":
        from .tools.carving import binwalk

        bw = binwalk(arguments["target_path"], recursive=arguments.get("recursive", False))
        return [TextContent(type="text", text=json.dumps(bw, default=str))]
    if name == "strings_extract":
        from .tools.carving import strings_extract

        se = strings_extract(
            arguments["target_path"],
            min_length=arguments.get("min_length", 6),
            max_strings=arguments.get("max_strings", 100000),
        )
        return [TextContent(type="text", text=json.dumps(se, default=str))]
    raise ValueError(f"Unknown tool: {name}")


def main() -> None:
    import asyncio

    async def _run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
