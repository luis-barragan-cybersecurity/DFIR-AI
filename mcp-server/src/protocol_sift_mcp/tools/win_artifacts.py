"""Eric Zimmerman (EZ) Tools wrappers — Windows artifact parsing at scale.

Wraps the .NET-based EZ Tools that ship with SIFT: EvtxECmd, MFTECmd, RECmd,
AmcacheParser. Each writes structured CSV / JSON to a working dir under
/output, and we shell out via `dotnet <tool>.dll` when the dotnet runtime
is available.

When the dotnet runtime is missing, every entry-point raises a clear
`EzToolsUnavailable` so the agent can fall back to the python-only
windows.py implementations (win_evtx_query, win_registry_get, etc.).
The fallback is documented at each function so the orchestrator can choose
a path without probing.
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path, assert_output_path

DEFAULT_TIMEOUT_SEC = 600


class EzToolsError(Exception):
    """EZ Tools subprocess failure or environment misconfiguration."""


class EzToolsUnavailable(EzToolsError):
    """dotnet runtime or the specific tool DLL is not installed."""


def _resolve_dotnet() -> str:
    path = shutil.which("dotnet")
    if not path:
        raise EzToolsUnavailable(
            "dotnet runtime not on PATH. Install: apt install dotnet-runtime-6.0 "
            "or use the python-only fallback in tools/windows.py."
        )
    return path


def _resolve_tool(tool_dll_name: str) -> Path:
    """Find the tool DLL under EZ_TOOLS_DIR (env) or /opt/EZ-Tools (SIFT default)."""
    candidates = [
        os.environ.get("EZ_TOOLS_DIR"),
        "/opt/EZ-Tools",
        "/usr/local/EZ-Tools",
        str(Path.home() / "EZ-Tools"),
    ]
    for c in candidates:
        if not c:
            continue
        p = Path(c) / tool_dll_name
        if p.exists():
            return p
    raise EzToolsUnavailable(
        f"{tool_dll_name} not found in EZ_TOOLS_DIR or default locations. "
        "Set EZ_TOOLS_DIR=/path/to/EZ-Tools or use python-only fallback."
    )


def _run(cmd: list[str], *, timeout_sec: int) -> tuple[str, str]:
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise EzToolsError(f"{cmd[0]} timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise EzToolsError(
            f"{cmd[0]} exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )
    return proc.stdout, proc.stderr or ""


def _read_csv(csv_path: Path, *, max_rows: int = 100_000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not csv_path.exists():
        return rows
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
            if len(rows) >= max_rows:
                break
    return rows


def evtxecmd(
    log_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """EvtxECmd — Windows event log parser.

    Python fallback: tools/windows.py:win_evtx_query.
    """
    src = assert_input_path(log_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("EvtxECmd.dll")

    cmd = [dotnet, str(dll), "-f", str(src), "--csv", str(out), "--csvf", "evtx.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "evtx.csv"
    return {
        "tool": "evtxecmd",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def mftecmd(
    mft_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """MFTECmd — NTFS $MFT parser."""
    src = assert_input_path(mft_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("MFTECmd.dll")

    cmd = [dotnet, str(dll), "-f", str(src), "--csv", str(out), "--csvf", "mft.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "mft.csv"
    return {
        "tool": "mftecmd",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
    }


def recmd(
    hive_path: str,
    output_dir: str,
    *,
    batch_keyword: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """RECmd — registry hive parser. Pass batch_keyword to run a Batch file
    pattern from RECmd's BatchExamples (e.g. 'RegistryASEPs')."""
    src = assert_input_path(hive_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("RECmd.dll")

    cmd = [dotnet, str(dll), "-f", str(src), "--csv", str(out)]
    if batch_keyword:
        cmd.extend(["--bn", batch_keyword])
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    # RECmd's CSV name depends on flags; glob for it.
    csv_files = sorted(out.glob("*.csv"))
    rows: list[dict[str, Any]] = []
    if csv_files:
        rows = _read_csv(csv_files[-1], max_rows=max_rows)
    return {
        "tool": "recmd",
        "source": str(src),
        "csv_paths": [str(p) for p in csv_files],
        "rows": rows,
        "stderr_tail": stderr[-512:],
    }


def amcacheparser(
    amcache_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """AmcacheParser — Amcache.hve execution-evidence parser."""
    src = assert_input_path(amcache_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("AmcacheParser.dll")

    cmd = [dotnet, str(dll), "-f", str(src), "--csv", str(out)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_files = sorted(out.glob("*.csv"))
    rows: list[dict[str, Any]] = []
    if csv_files:
        rows = _read_csv(csv_files[-1], max_rows=max_rows)
    return {
        "tool": "amcacheparser",
        "source": str(src),
        "csv_paths": [str(p) for p in csv_files],
        "rows": rows,
        "stderr_tail": stderr[-512:],
    }


def appcompatcacheparser(
    hive_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """AppCompatCacheParser — SYSTEM hive Shimcache/AppCompatCache parser.

    Shimcache records every executable seen on the system (full path + last
    modified time + size). Survives reboots; one of the few artifacts that
    captures execution evidence even after the file is deleted.

    Input: SYSTEM hive (extracted from /Windows/System32/config/SYSTEM).
    """
    src = assert_input_path(hive_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("AppCompatCacheParser.dll")

    cmd = [dotnet, str(dll), "-f", str(src), "--csv", str(out), "--csvf", "shimcache.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "shimcache.csv"
    return {
        "tool": "appcompatcacheparser",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def pecmd(
    prefetch_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """PECmd — Prefetch (.pf) parser, batch-capable.

    Prefetch tracks the last 8 execution times per binary, files accessed
    during launch, and run count. PECmd handles XPRESS-Huffman compression
    used on Win10+ (Python fallback: tools/windows.py:win_prefetch_parse,
    handles single files).

    Accepts a single .pf file OR a directory of .pf files (-d).
    """
    src = assert_input_path(prefetch_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("PECmd.dll")

    flag = "-d" if src.is_dir() else "-f"
    cmd = [dotnet, str(dll), flag, str(src), "--csv", str(out), "--csvf", "prefetch.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "prefetch.csv"
    return {
        "tool": "pecmd",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def lecmd(
    lnk_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """LECmd — Windows .lnk shortcut parser, batch-capable.

    Shortcuts capture the original target path, MAC times of the target,
    volume serial number, NetBIOS / MAC of the host (for remote shortcuts).
    LECmd batches a directory and recovers deleted entries from slack space.

    Accepts a single .lnk OR a directory (-d). Python fallback:
    tools/windows.py:win_lnk_parse (single file only).
    """
    src = assert_input_path(lnk_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("LECmd.dll")

    flag = "-d" if src.is_dir() else "-f"
    cmd = [dotnet, str(dll), flag, str(src), "--csv", str(out), "--csvf", "lnk.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "lnk.csv"
    return {
        "tool": "lecmd",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def jlecmd(
    jumplist_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """JLECmd — Jump List parser (AutomaticDestinations + CustomDestinations).

    Jump lists record the most-recently-used files per application (Office,
    browsers, Explorer). Live in
    `%APPDATA%\\Microsoft\\Windows\\Recent\\(Automatic|Custom)Destinations\\*`.
    AppID prefix in the filename identifies the source app.

    Accepts a single jumplist file OR a directory (-d).
    """
    src = assert_input_path(jumplist_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("JLECmd.dll")

    flag = "-d" if src.is_dir() else "-f"
    cmd = [dotnet, str(dll), flag, str(src), "--csv", str(out), "--csvf", "jumplist.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "jumplist.csv"
    return {
        "tool": "jlecmd",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def sbecmd(
    hive_dir: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """SBECmd — ShellBags Explorer (batch ShellBag extractor).

    Reads NTUSER.DAT and USRCLASS.DAT hives from `-d <dir>` and reconstructs
    the user's folder-access tree (which directories were visited even after
    deletion). Python fallback: tools/windows.py:win_shellbag_parse (single
    hive, less detail).
    """
    src = assert_input_path(hive_dir)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("SBECmd.dll")

    # SBECmd requires -d for a hive directory; -f for a single hive isn't
    # supported by the tool. We pass the parent dir of the supplied hive
    # if the user pointed at a single file.
    target = src if src.is_dir() else src.parent
    cmd = [dotnet, str(dll), "-d", str(target), "--csv", str(out)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_files = sorted(out.glob("*.csv"))
    rows: list[dict[str, Any]] = []
    if csv_files:
        rows = _read_csv(csv_files[-1], max_rows=max_rows)
    return {
        "tool": "sbecmd",
        "source": str(target),
        "csv_paths": [str(p) for p in csv_files],
        "rows": rows,
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def rbcmd(
    recyclebin_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """RBCmd — Recycle Bin $I/INFO2 parser, batch-capable.

    Parses Vista+ `$I######` headers AND legacy XP INFO2 records. Python
    fallback: tools/windows.py:win_recyclebin_parse (Vista+ only, single
    directory).

    Accepts a single $I/INFO2 file OR a directory of $I files (-d).
    """
    src = assert_input_path(recyclebin_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dotnet = _resolve_dotnet()
    dll = _resolve_tool("RBCmd.dll")

    flag = "-d" if src.is_dir() else "-f"
    cmd = [dotnet, str(dll), flag, str(src), "--csv", str(out), "--csvf", "recyclebin.csv"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    csv_path = out / "recyclebin.csv"
    return {
        "tool": "rbcmd",
        "source": str(src),
        "csv_path": str(csv_path),
        "rows": _read_csv(csv_path, max_rows=max_rows),
        "stderr_tail": stderr[-512:],
        "stdout_tail": stdout[-512:],
    }


def ez_tools_available() -> dict[str, Any]:
    """Probe whether EZ Tools are usable. Used by tools.list to gate registration."""
    try:
        _resolve_dotnet()
    except EzToolsUnavailable as exc:
        return {"available": False, "reason": str(exc)}
    found: dict[str, str] = {}
    for dll in (
        "EvtxECmd.dll", "MFTECmd.dll", "RECmd.dll", "AmcacheParser.dll",
        "AppCompatCacheParser.dll", "PECmd.dll", "LECmd.dll", "JLECmd.dll",
        "SBECmd.dll", "RBCmd.dll",
    ):
        try:
            p = _resolve_tool(dll)
            found[dll] = str(p)
        except EzToolsUnavailable:
            pass
    return {"available": bool(found), "found": found,
            "reason": None if found else "no EZ Tools DLLs in EZ_TOOLS_DIR"}


# Pretty-printed JSON helper used by some callers that want the structured
# tool surface as a string. Not part of the public schema; just convenience.
def _dump(rec: dict[str, Any]) -> str:
    return json.dumps(rec, default=str, indent=2)
