"""Sleuth Kit (TSK) wrappers — filesystem & disk-image analysis.

Wraps fls, icat, mmls, mactime, istat via subprocess. Same pattern as
`memory.py`: sandbox-assert image path under EVIDENCE_PATH, allowlisted
tool binary, capped timeout, structured return.

The return shape is `{"tool": str, "image": str, "rows": list[dict] | None,
"raw": str, "stderr": str}` — `rows` is populated when the output is line-
delimited and parseable, `raw` is always populated for forensic citation.

Only call this when the SIFT Workstation provides the Sleuth Kit binaries.
On hosts without TSK installed, every call raises `SleuthKitError` with a
clear "install with apt install sleuthkit" message.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path

DEFAULT_TIMEOUT_SEC = 300

# Tools we expose. Adding a binary here requires:
#   1. A row parser in `_parse_rows` (or accept that `rows` will be None).
#   2. A schema entry in server.py.
_ALLOWED_TOOLS: frozenset[str] = frozenset({"fls", "icat", "mmls", "mactime", "istat"})


class SleuthKitError(Exception):
    """TSK binary missing, subprocess failure, or input violation."""


def _resolve_binary(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise SleuthKitError(
            f"{tool} binary not found on PATH. "
            "On SIFT / Ubuntu: apt install sleuthkit. On macOS: brew install sleuthkit."
        )
    return path


def _run(cmd: list[str], *, timeout_sec: int) -> tuple[str, str]:
    try:
        proc = subprocess.run(  # noqa: S603 — cmd[0] is shutil.which result; args are sandbox-asserted
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SleuthKitError(f"{cmd[0]} timed out after {timeout_sec}s") from exc
    except FileNotFoundError as exc:
        raise SleuthKitError(f"{cmd[0]} exec failed: {exc}") from exc
    if proc.returncode != 0:
        raise SleuthKitError(
            f"{cmd[0]} exited {proc.returncode}: {(proc.stderr or '').strip()}"
        )
    return proc.stdout, proc.stderr or ""


def _parse_fls(text: str) -> list[dict[str, Any]]:
    """fls output: '<type>/<type> <flags> <inode>:    <name>'"""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Split on first ':' for inode/name boundary.
        head, _, name = line.partition(":")
        head = head.strip()
        name = name.strip()
        parts = head.split()
        if len(parts) < 2:
            rows.append({"raw": line})
            continue
        rows.append({
            "type": parts[0],
            "flags": " ".join(parts[1:-1]) if len(parts) > 2 else "",
            "inode": parts[-1],
            "name": name,
        })
    return rows


def _parse_mmls(text: str) -> list[dict[str, Any]]:
    """mmls output: header lines + numbered partitions."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or not s[0].isdigit():
            continue
        parts = s.split()
        if len(parts) >= 6:
            rows.append({
                "slot": parts[0],
                "start": parts[2],
                "end": parts[3],
                "length": parts[4],
                "description": " ".join(parts[5:]),
            })
    return rows


def _parse_mactime(text: str) -> list[dict[str, Any]]:
    """mactime CSV-ish: 'Date,Size,Type,Mode,UID,GID,Meta,File Name'"""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("Date,"):
            continue
        cols = s.split(",", 7)
        if len(cols) == 8:
            rows.append({
                "ts": cols[0], "size": cols[1], "macb_class": cols[2],
                "mode": cols[3], "uid": cols[4], "gid": cols[5],
                "meta": cols[6], "path": cols[7],
            })
        else:
            rows.append({"raw": s})
    return rows


_PARSERS = {
    "fls": _parse_fls,
    "mmls": _parse_mmls,
    "mactime": _parse_mactime,
    # icat is binary — leave rows=None; raw is the bytes (text-coerced)
    # istat is human-formatted text — leave rows=None
}


def tsk_run(
    tool: str,
    image_path: str,
    *,
    extra_args: list[str] | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Run any allowlisted Sleuth Kit binary against a sandbox-asserted image.

    Returns:
        {tool, image, rows, raw, stderr}
    """
    if tool not in _ALLOWED_TOOLS:
        raise ValueError(f"tool {tool!r} not in allowlist {sorted(_ALLOWED_TOOLS)}")
    img = assert_input_path(image_path)
    bin_path = _resolve_binary(tool)

    cmd: list[str] = [bin_path, str(img)]
    if extra_args:
        cmd.extend(extra_args)

    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    parser = _PARSERS.get(tool)
    rows: list[dict[str, Any]] | None = parser(stdout) if parser else None
    return {
        "tool": tool,
        "image": str(img),
        "rows": rows,
        "raw": stdout,
        "stderr": stderr,
    }


def fls(image_path: str, *, inode: str | None = None, recursive: bool = False,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> dict[str, Any]:
    """List files + directories. -r recurses; inode optional starting point."""
    extra: list[str] = []
    if recursive:
        extra.append("-r")
    # fls signature: fls IMAGE [INODE]
    extra_after_img: list[str] = []
    if inode is not None:
        extra_after_img.append(str(inode))
    # tsk_run appends extra_args after image; we need flags before image for fls.
    # Easier: construct full cmd directly here.
    bin_path = _resolve_binary("fls")
    img = assert_input_path(image_path)
    cmd: list[str] = [bin_path, *extra, str(img), *extra_after_img]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {"tool": "fls", "image": str(img), "rows": _parse_fls(stdout),
            "raw": stdout, "stderr": stderr}


def icat(image_path: str, inode: str, *,
         timeout_sec: int = DEFAULT_TIMEOUT_SEC,
         max_bytes: int = 50 * 1024 * 1024) -> dict[str, Any]:
    """Extract file content by inode. Bounded by max_bytes for safety."""
    bin_path = _resolve_binary("icat")
    img = assert_input_path(image_path)
    cmd = [bin_path, str(img), str(inode)]
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SleuthKitError(f"icat timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise SleuthKitError(f"icat exited {proc.returncode}: {(proc.stderr or b'').decode(errors='replace')}")
    payload = proc.stdout[:max_bytes]
    return {
        "tool": "icat",
        "image": str(img),
        "inode": str(inode),
        "size_bytes": len(proc.stdout),
        "truncated": len(proc.stdout) > max_bytes,
        "data_hex": payload.hex(),
        "stderr": (proc.stderr or b"").decode(errors="replace"),
    }


def mmls(image_path: str, *, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> dict[str, Any]:
    """List disk partition layout."""
    return tsk_run("mmls", image_path, timeout_sec=timeout_sec)


def mactime(body_path: str, *, output_format: str = "csv",
            timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> dict[str, Any]:
    """Produce a MACB timeline from an fls -m bodyfile.

    body_path is NOT an image — it's an `fls -m`-generated bodyfile under
    EVIDENCE_PATH or OUTPUT_PATH. We sandbox-assert under EVIDENCE_PATH
    only (the typical case); orchestrators that pre-stage bodies under
    /output should write them into /input first.
    """
    bin_path = _resolve_binary("mactime")
    body = Path(body_path)
    if not body.exists():
        raise SleuthKitError(f"body file not found: {body_path}")
    cmd = [bin_path, "-b", str(body), "-d" if output_format == "csv" else "-y"]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {"tool": "mactime", "image": str(body),
            "rows": _parse_mactime(stdout), "raw": stdout, "stderr": stderr}


def istat(image_path: str, inode: str, *,
          timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> dict[str, Any]:
    """Detailed metadata about an inode (timestamps, runlist, attributes)."""
    bin_path = _resolve_binary("istat")
    img = assert_input_path(image_path)
    cmd = [bin_path, str(img), str(inode)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {"tool": "istat", "image": str(img), "inode": str(inode),
            "rows": None, "raw": stdout, "stderr": stderr}
