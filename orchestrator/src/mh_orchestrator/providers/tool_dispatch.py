"""Translate ``mcp__protocol_sift__<name>`` → in-process Python call.

The Anthropic CLI provider invokes tools via the MCP server subprocess; that
server's call_tool dispatch lives in ``protocol_sift_mcp.server``. Non-CLI
providers (Anthropic API, OpenAI, Ollama) drive a model + tool loop in this
process and need the SAME tool surface without the stdio framing overhead.

``dispatch_tool`` is the in-process mirror of the MCP server's ``call_tool``
function. It accepts the bare tool name OR the namespaced
``mcp__protocol_sift__<name>`` form Claude Code uses, and returns the same
shape the MCP server would have wrapped in ``TextContent``.

``mcp_tool_schemas`` returns the same Tool definitions the MCP server's
``list_tools`` exposes — used to translate to Anthropic/OpenAI/Ollama tool
schemas in each provider.

The dispatch table mirrors ``protocol_sift_mcp/server.py`` line-for-line; if
the server gains a tool, add the same branch here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .base import ProviderToolError


_TOOL_PREFIX = "mcp__protocol_sift__"


def _bare_name(tool_name: str) -> str:
    """Strip the ``mcp__protocol_sift__`` prefix if present."""
    if tool_name.startswith(_TOOL_PREFIX):
        return tool_name[len(_TOOL_PREFIX):]
    return tool_name


def _output_dir() -> Path:
    """Where audit + findings JSON land. Mirrors the MCP server."""
    return Path(os.environ.get("OUTPUT_PATH", "/output"))


def _audit_path() -> Path:
    return _output_dir() / "audit.jsonl"


def _findings_path() -> Path:
    return _output_dir() / "findings.json"


def dispatch_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Run an MCP tool by name with the provided arguments.

    Accepts either the bare name (``"hash"``) or the Claude Code namespaced
    form (``"mcp__protocol_sift__hash"``). Returns whatever the underlying
    ``protocol_sift_mcp.tools.*`` function returned — typically a dict, but
    occasionally a string (``hash`` returns a `Digest` namedtuple stringified).

    Args:
        name: Tool name, bare or namespaced.
        arguments: Tool argument dict. ``None`` is treated as ``{}``.

    Returns:
        The tool function's return value. Always JSON-serialisable (the
        dispatch surface upstream of this function only contains tools that
        return JSON-friendly shapes; this mirrors the MCP server, which
        ``json.dumps(..., default=str)`` on the result).

    Raises:
        ProviderToolError: ``name`` is not a known tool, or the underlying
            tool function raised. The error message preserves both the
            tool name + a snippet of the arguments to aid post-mortem
            diagnosis from audit.jsonl.
    """
    args = dict(arguments or {})
    bare = _bare_name(name)
    try:
        return _dispatch(bare, args)
    except ProviderToolError:
        raise
    except Exception as exc:  # noqa: BLE001 — re-wrap with context
        argv_excerpt = json.dumps(args, default=str)[:200]
        raise ProviderToolError(
            f"tool {bare!r} raised {type(exc).__name__}: {exc}; args={argv_excerpt}"
        ) from exc


def _dispatch(bare: str, arguments: dict[str, Any]) -> Any:  # noqa: PLR0911, PLR0912, PLR0915
    """Hot dispatch — mirrors protocol_sift_mcp/server.py::call_tool.

    Kept as one long if/elif chain (matching the server) so adding a tool in
    one place reminds the contributor to add it in the other. Cyclomatic
    complexity is irrelevant here; the function is a flat switch.
    """
    from protocol_sift_mcp.tools import audit as au
    from protocol_sift_mcp.tools import evidence as ev
    from protocol_sift_mcp.tools import finding as fd
    from protocol_sift_mcp.tools import macos as mac
    from protocol_sift_mcp.tools import parse as ps
    from protocol_sift_mcp.tools import windows as win

    if bare == "hash":
        digest = ev.hash_file(Path(arguments["path"]))
        # Mirror the MCP server's "str(digest)" wrap so callers see the
        # same shape regardless of transport.
        return {"hash": str(digest)}
    if bare == "audit_append":
        entry = au.audit_append(
            _audit_path(),
            event=arguments["event"],
            data=arguments["data"],
        )
        return entry if isinstance(entry, dict) else {"audit": str(entry)}
    if bare == "finding_record":
        record = fd.finding_record(_findings_path(), arguments)
        au.audit_append(
            _audit_path(),
            event="finding_recorded",
            data={"finding_id": record["finding_id"]},
        )
        return record
    if bare == "win_registry_get":
        return win.win_registry_get(
            arguments["hive_path"],
            arguments.get("registry_path", ""),
        )
    if bare == "win_prefetch_parse":
        return win.win_prefetch_parse(arguments["prefetch_path"])
    if bare == "win_evtx_query":
        tr = arguments.get("time_range")
        time_tuple = (tr[0], tr[1]) if tr and len(tr) == 2 else None
        return win.win_evtx_query(
            arguments["log_path"],
            event_ids=arguments.get("event_ids"),
            time_range=time_tuple,
            limit=arguments.get("limit", 1000),
        )
    if bare == "win_lnk_parse":
        return win.win_lnk_parse(arguments["lnk_path"])
    if bare == "os_detect":
        return ps.os_detect(arguments["path"])
    if bare == "magic_check":
        return ps.magic_check(arguments["path"])
    if bare == "mac_plist_get":
        return mac.mac_plist_get(arguments["plist_path"], arguments.get("key_path", ""))
    if bare == "mac_knowledgec_query":
        return mac.mac_knowledgec_query(
            arguments["db_path"],
            sql=arguments.get("sql"),
            table=arguments.get("table"),
            limit=arguments.get("limit", 100),
        )
    if bare == "memory_volatility":
        from protocol_sift_mcp.tools.memory import memory_volatility
        return memory_volatility(
            arguments["image_path"],
            arguments["plugin"],
            args=arguments.get("args"),
            timeout_sec=arguments.get("timeout_sec", 300),
        )
    if bare == "linux_history_parse":
        from protocol_sift_mcp.tools.linux import linux_history_parse
        return linux_history_parse(arguments["history_path"])
    if bare == "yara_scan":
        from protocol_sift_mcp.tools.parse import yara_scan
        return yara_scan(
            arguments["target_path"], arguments["rule_path"],
            recursive=arguments.get("recursive", True),
            max_hits=arguments.get("max_hits", 10000),
        )
    if bare == "memprocfs_findevil":
        from protocol_sift_mcp.tools.memory import memprocfs_findevil
        return memprocfs_findevil(
            arguments["memory_path"],
            mount_point=arguments.get("mount_point", "/tmp/memprocfs-mh"),  # noqa: S108
            timeout_sec=arguments.get("timeout_sec", 1200),
        )
    if bare == "tsk_fls":
        from protocol_sift_mcp.tools.filesystem import fls
        return fls(arguments["image_path"], inode=arguments.get("inode"),
                   recursive=arguments.get("recursive", False))
    if bare == "tsk_icat":
        from protocol_sift_mcp.tools.filesystem import icat
        return icat(arguments["image_path"], arguments["inode"],
                    max_bytes=arguments.get("max_bytes", 52428800))
    if bare == "tsk_mmls":
        from protocol_sift_mcp.tools.filesystem import mmls
        return mmls(arguments["image_path"])
    if bare == "tsk_mactime":
        from protocol_sift_mcp.tools.filesystem import mactime
        return mactime(arguments["body_path"],
                       output_format=arguments.get("output_format", "csv"))
    if bare == "tsk_istat":
        from protocol_sift_mcp.tools.filesystem import istat
        return istat(arguments["image_path"], arguments["inode"])
    if bare == "plaso_log2timeline":
        from protocol_sift_mcp.tools.timeline import log2timeline
        return log2timeline(
            arguments["source_path"], arguments["storage_path"],
            parsers=arguments.get("parsers", "win_gen,webhist,sysreg"),
            timeout_sec=arguments.get("timeout_sec", 3600),
        )
    if bare == "plaso_psort":
        from protocol_sift_mcp.tools.timeline import psort
        return psort(
            arguments["storage_path"],
            output_format=arguments.get("output_format", "json_line"),
            output_path=arguments.get("output_path"),
            max_events=arguments.get("max_events", 200000),
        )
    if bare == "ez_evtxecmd":
        from protocol_sift_mcp.tools.win_artifacts import evtxecmd
        return evtxecmd(arguments["log_path"], arguments["output_dir"],
                        max_rows=arguments.get("max_rows", 100000))
    if bare == "ez_mftecmd":
        from protocol_sift_mcp.tools.win_artifacts import mftecmd
        return mftecmd(arguments["mft_path"], arguments["output_dir"],
                       max_rows=arguments.get("max_rows", 100000))
    if bare == "ez_recmd":
        from protocol_sift_mcp.tools.win_artifacts import recmd
        return recmd(arguments["hive_path"], arguments["output_dir"],
                     batch_keyword=arguments.get("batch_keyword"))
    if bare == "ez_amcacheparser":
        from protocol_sift_mcp.tools.win_artifacts import amcacheparser
        return amcacheparser(arguments["amcache_path"], arguments["output_dir"])
    if bare == "tshark_extract":
        from protocol_sift_mcp.tools.network import tshark_extract
        return tshark_extract(
            arguments["pcap_path"],
            display_filter=arguments.get("display_filter"),
            fields=arguments.get("fields"),
            max_rows=arguments.get("max_rows", 100000),
        )
    if bare == "zeek_log_read":
        from protocol_sift_mcp.tools.network import zeek_log_read
        return zeek_log_read(arguments["log_path"], max_rows=arguments.get("max_rows", 100000))
    if bare == "pcap_to_zeek":
        from protocol_sift_mcp.tools.network import pcap_to_zeek
        return pcap_to_zeek(arguments["pcap_path"], arguments["output_dir"])
    if bare == "pcap_to_netflow":
        from protocol_sift_mcp.tools.network import pcap_to_netflow
        return pcap_to_netflow(arguments["pcap_path"], arguments["output_dir"])
    if bare == "pcap_to_passivedns":
        from protocol_sift_mcp.tools.network import pcap_to_passivedns
        return pcap_to_passivedns(arguments["pcap_path"], arguments["output_dir"])
    if bare == "pcap_info":
        from protocol_sift_mcp.tools.network import pcap_info
        return pcap_info(arguments["pcap_path"])
    if bare == "pcap_slice_time":
        from protocol_sift_mcp.tools.network import pcap_slice_time
        return pcap_slice_time(
            arguments["pcap_path"], arguments["start_time"],
            arguments["end_time"], arguments["output_path"],
        )
    if bare == "pcap_merge":
        from protocol_sift_mcp.tools.network import pcap_merge
        return pcap_merge(arguments["pcap_list"], arguments["output_path"])
    if bare == "pcap_filter_bpf":
        from protocol_sift_mcp.tools.network import pcap_filter_bpf
        return pcap_filter_bpf(
            arguments["pcap_path"], arguments["bpf"], arguments["output_path"],
        )
    if bare == "tcp_reassemble":
        from protocol_sift_mcp.tools.network import tcp_reassemble
        return tcp_reassemble(arguments["pcap_path"], arguments["output_dir"])
    if bare == "nfdump_query":
        from protocol_sift_mcp.tools.network import nfdump_query
        return nfdump_query(
            arguments["nfcapd_path"],
            bpf_filter=arguments.get("bpf_filter"),
            aggregation=arguments.get("aggregation"),
            output_format=arguments.get("output_format", "csv"),
            top_n=arguments.get("top_n"),
        )
    if bare == "beacon_score":
        from protocol_sift_mcp.tools.network_analytics import beacon_score
        return beacon_score(
            arguments["conn_log_path"],
            dst_filter=arguments.get("dst_filter"),
            min_connections=arguments.get("min_connections", 8),
            top_n=arguments.get("top_n", 50),
        )
    if bare == "conn_top_talkers":
        from protocol_sift_mcp.tools.network_analytics import conn_top_talkers
        return conn_top_talkers(
            arguments["conn_log_path"],
            k=arguments.get("k", 20),
            by=arguments.get("by", "bytes"),
        )
    if bare == "dns_summarize":
        from protocol_sift_mcp.tools.network_analytics import dns_summarize
        return dns_summarize(arguments["dns_log_path"], k=arguments.get("k", 20))
    if bare == "http_ua_profile":
        from protocol_sift_mcp.tools.network_analytics import http_ua_profile
        return http_ua_profile(arguments["http_log_path"], k=arguments.get("k", 20))
    if bare == "bulk_extractor":
        from protocol_sift_mcp.tools.carving import bulk_extractor
        return bulk_extractor(arguments["image_path"], arguments["output_dir"],
                              features=arguments.get("features", "all"))
    if bare == "binwalk":
        from protocol_sift_mcp.tools.carving import binwalk
        return binwalk(arguments["target_path"], recursive=arguments.get("recursive", False))
    if bare == "strings_extract":
        from protocol_sift_mcp.tools.carving import strings_extract
        return strings_extract(
            arguments["target_path"],
            min_length=arguments.get("min_length", 6),
            max_strings=arguments.get("max_strings", 100000),
        )
    raise ProviderToolError(f"unknown tool: {bare!r}")


def mcp_tool_schemas() -> list[dict[str, Any]]:
    """Return MCP tool schemas in a provider-neutral shape.

    Each entry: ``{"name": str, "description": str, "input_schema": dict}``.
    Providers translate this list into their own tool-spec wire format
    (Anthropic ``tools=[]``, OpenAI ``functions=[]``, Ollama ``tools=[]``).

    The list is loaded by importing the running MCP server's ``list_tools``
    coroutine and awaiting it once. Cached after first call.
    """
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is not None:
        return _SCHEMA_CACHE
    import asyncio

    from protocol_sift_mcp.server import server as _srv

    # The MCP server registers handlers via decorators; the underlying
    # function isn't exposed as an attribute. Calling the handler through
    # the server's request handlers is brittle, so we mirror list_tools()
    # by importing it fresh.
    from protocol_sift_mcp import server as _srv_mod

    tools = asyncio.run(_srv_mod.list_tools())
    _SCHEMA_CACHE = [
        {
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.inputSchema or {"type": "object", "properties": {}},
        }
        for t in tools
    ]
    return _SCHEMA_CACHE


_SCHEMA_CACHE: list[dict[str, Any]] | None = None
