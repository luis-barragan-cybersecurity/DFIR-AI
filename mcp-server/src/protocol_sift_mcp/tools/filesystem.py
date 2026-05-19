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
_ALLOWED_TOOLS: frozenset[str] = frozenset({
    "fls", "icat", "mmls", "mactime", "istat",
    # Block-layer + reverse-lookup utilities — added in Tier 2 to cover the
    # unallocated/slack-recovery + inode↔block reverse-lookup workflows.
    "fsstat", "blkcat", "blkls", "blkcalc", "blkstat",
    "ils", "ifind", "ffind",
})


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


# ─── Block-layer / reverse-lookup utilities (Tier 2) ─────────────────────────


def fsstat(image_path: str, *, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> dict[str, Any]:
    """Filesystem statistics (block size, inode count, FS type, volume label).

    First call on any new image. The `raw` field is the human-formatted dump
    that mounts/forensic-recipe documents reference; `rows` is None because
    fsstat output isn't line-structured.
    """
    bin_path = _resolve_binary("fsstat")
    img = assert_input_path(image_path)
    stdout, stderr = _run([bin_path, str(img)], timeout_sec=timeout_sec)
    return {"tool": "fsstat", "image": str(img), "rows": None,
            "raw": stdout, "stderr": stderr}


def blkcat(
    image_path: str,
    block: str,
    *,
    count: int = 1,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_bytes: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    """Read raw block content by block number. Bounded by max_bytes."""
    bin_path = _resolve_binary("blkcat")
    img = assert_input_path(image_path)
    cmd = [bin_path, str(img), str(block), str(count)]
    try:
        proc = subprocess.run(  # noqa: S603 — bin_path is shutil.which result
            cmd, capture_output=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SleuthKitError(f"blkcat timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise SleuthKitError(
            f"blkcat exited {proc.returncode}: {(proc.stderr or b'').decode(errors='replace')}"
        )
    payload = proc.stdout[:max_bytes]
    return {
        "tool": "blkcat", "image": str(img), "block": str(block), "count": count,
        "size": len(payload), "truncated": len(proc.stdout) > max_bytes,
        "data_hex": payload.hex(),
        "stderr": (proc.stderr or b"").decode(errors="replace"),
    }


def blkls(
    image_path: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    out_path: str | None = None,
    max_bytes: int = 200 * 1024 * 1024,
) -> dict[str, Any]:
    """Extract unallocated block content (slack + free space).

    Writes to `out_path` (under /output) when supplied — recommended for
    images with substantial unallocated space. Otherwise returns the first
    `max_bytes` of unallocated content inline (hex).

    Pair with `bulk_extractor` or `strings_extract` for IOC carving.
    """
    bin_path = _resolve_binary("blkls")
    img = assert_input_path(image_path)
    cmd = [bin_path, str(img)]
    if out_path:
        # Stream to file via redirect (safer than holding 200 MB in memory).
        from ..sandbox import assert_output_path
        target = assert_output_path(out_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as fh:
            try:
                proc = subprocess.run(  # noqa: S603
                    cmd, stdout=fh, stderr=subprocess.PIPE, timeout=timeout_sec, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise SleuthKitError(f"blkls timed out after {timeout_sec}s") from exc
        if proc.returncode != 0:
            raise SleuthKitError(
                f"blkls exited {proc.returncode}: {(proc.stderr or b'').decode(errors='replace')}"
            )
        return {
            "tool": "blkls", "image": str(img),
            "out_path": str(target), "size": target.stat().st_size,
            "stderr": (proc.stderr or b"").decode(errors="replace"),
        }
    # Inline mode — bounded by max_bytes.
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SleuthKitError(f"blkls timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise SleuthKitError(
            f"blkls exited {proc.returncode}: {(proc.stderr or b'').decode(errors='replace')}"
        )
    payload = proc.stdout[:max_bytes]
    return {
        "tool": "blkls", "image": str(img), "size": len(payload),
        "truncated": len(proc.stdout) > max_bytes,
        "data_hex": payload.hex(),
        "stderr": (proc.stderr or b"").decode(errors="replace"),
    }


def blkcalc(
    image_path: str,
    block: str,
    *,
    mode: str = "unallocated",
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Map between block numbers in original image and blkls output.

    `mode` is one of: 'unallocated' (-u, default — unalloc N → original N),
    'allocated' (-a — original N → unalloc N), or 'slack' (-s — slack N →
    original N). The Sleuth Kit flag set is the wire interface.
    """
    flag_map = {"unallocated": "-u", "allocated": "-a", "slack": "-s"}
    if mode not in flag_map:
        raise ValueError(f"mode must be one of {list(flag_map)}")
    bin_path = _resolve_binary("blkcalc")
    img = assert_input_path(image_path)
    cmd = [bin_path, flag_map[mode], str(block), str(img)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {
        "tool": "blkcalc", "image": str(img), "block": str(block), "mode": mode,
        "mapped": stdout.strip(), "rows": None, "raw": stdout, "stderr": stderr,
    }


def blkstat(
    image_path: str,
    block: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Block allocation status (allocated/unallocated/meta) + group info."""
    bin_path = _resolve_binary("blkstat")
    img = assert_input_path(image_path)
    cmd = [bin_path, str(img), str(block)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {"tool": "blkstat", "image": str(img), "block": str(block),
            "rows": None, "raw": stdout, "stderr": stderr}


def _parse_ils(text: str) -> list[dict[str, Any]]:
    """ils output: 'inode|status|uid|gid|mtime|atime|ctime|...' pipe-delimited."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "|" not in s:
            continue
        parts = s.split("|")
        if len(parts) >= 6:
            rows.append({
                "inode": parts[0],
                "status": parts[1] if len(parts) > 1 else "",
                "uid": parts[2] if len(parts) > 2 else "",
                "gid": parts[3] if len(parts) > 3 else "",
                "mtime": parts[4] if len(parts) > 4 else "",
                "atime": parts[5] if len(parts) > 5 else "",
                "ctime": parts[6] if len(parts) > 6 else "",
                "extras": parts[7:],
            })
    return rows


def ils(
    image_path: str,
    *,
    mode: str = "all",  # "all" | "removed" | "open"
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """List inode metadata. Default mode 'all'; 'removed' walks deleted
    inodes only (highest DFIR value — recovers metadata for deleted files
    even when the directory entry is gone)."""
    flag_map = {"all": [], "removed": ["-r"], "open": ["-O"]}
    if mode not in flag_map:
        raise ValueError(f"mode must be one of {list(flag_map)}")
    bin_path = _resolve_binary("ils")
    img = assert_input_path(image_path)
    cmd = [bin_path, *flag_map[mode], str(img)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {"tool": "ils", "image": str(img), "mode": mode,
            "rows": _parse_ils(stdout), "raw": stdout, "stderr": stderr}


def ifind(
    image_path: str,
    *,
    block: str | None = None,
    file_path: str | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Reverse lookup: block→inode (block=) or path→inode (file_path=).

    Exactly one of `block` or `file_path` must be supplied.
    """
    if (block is None) == (file_path is None):
        raise ValueError("Provide exactly one of block or file_path")
    bin_path = _resolve_binary("ifind")
    img = assert_input_path(image_path)
    if block is not None:
        cmd = [bin_path, "-d", str(block), str(img)]
        mode = "block_to_inode"
    else:
        cmd = [bin_path, "-n", str(file_path), str(img)]
        mode = "path_to_inode"
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    return {"tool": "ifind", "image": str(img), "mode": mode,
            "result": stdout.strip(), "rows": None, "raw": stdout, "stderr": stderr}


def ffind(
    image_path: str,
    inode: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """inode → file path(s). Multiple paths possible for hard-linked files."""
    bin_path = _resolve_binary("ffind")
    img = assert_input_path(image_path)
    cmd = [bin_path, str(img), str(inode)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec)
    rows = [{"path": line.strip()} for line in stdout.splitlines() if line.strip()]
    return {"tool": "ffind", "image": str(img), "inode": str(inode),
            "rows": rows, "raw": stdout, "stderr": stderr}


# ─── Forensic image mounting (Tier 2) ────────────────────────────────────────
#
# These wrap external mount utilities. They REQUIRE FUSE on Linux and the
# target user must have permission to mount. They are inherently destructive
# (they modify the host's mount table), so we sandbox the mount POINT under
# /output and let assert_output_path catch escapes.

class MountToolError(Exception):
    """Boundary error for ewfmount / vshadowmount — missing binary, FUSE
    not available, mount-point conflict, or non-zero exit."""


def ewfmount(
    image_path: str,
    mount_point: str,
    *,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    """Mount an EnCase E01 image read-only via ewfmount (libewf-tools).

    Output of an `ewfmount E01 /mnt/X` is a directory with a raw `ewf1`
    pseudo-file representing the decoded image. Downstream tools (Sleuth Kit,
    Volatility) read `<mount_point>/ewf1` as if it were a raw image.

    Args:
        image_path: path under /input to .E01 (or first segment of a split set).
        mount_point: path under /output for the FUSE mount.

    Note: caller is responsible for `fusermount -u <mount_point>` cleanup.
    """
    bin_path = shutil.which("ewfmount")
    if not bin_path:
        raise MountToolError(
            "ewfmount not on PATH. Install: apt install ewf-tools / brew install libewf."
        )
    img = assert_input_path(image_path)
    from ..sandbox import assert_output_path
    mp = assert_output_path(mount_point)
    mp.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(  # noqa: S603 — bin_path is shutil.which result
            [bin_path, str(img), str(mp)],
            capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise MountToolError(f"ewfmount timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise MountToolError(
            f"ewfmount exited {proc.returncode}: {(proc.stderr or '').strip()}"
        )
    raw_image = mp / "ewf1"
    return {
        "tool": "ewfmount",
        "image": str(img),
        "mount_point": str(mp),
        "raw_image": str(raw_image) if raw_image.exists() else None,
        "stderr": proc.stderr,
        "cleanup_cmd": f"fusermount -u '{mp}'",
    }


def vshadowmount(
    volume_path: str,
    mount_point: str,
    *,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    """Mount a Windows volume's Volume Shadow Copies via vshadowmount
    (libvshadow). Output is a directory of `vss1`, `vss2`, ... pseudo-files
    — one per shadow copy. Each is mountable as a raw image (NTFS) via
    Sleuth Kit or a loop mount.

    Args:
        volume_path: path under /input to a raw NTFS volume image.
        mount_point: path under /output for the FUSE mount.

    Note: caller is responsible for `fusermount -u <mount_point>` cleanup.
    """
    bin_path = shutil.which("vshadowmount")
    if not bin_path:
        raise MountToolError(
            "vshadowmount not on PATH. Install: apt install libvshadow-utils."
        )
    vol = assert_input_path(volume_path)
    from ..sandbox import assert_output_path
    mp = assert_output_path(mount_point)
    mp.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(  # noqa: S603 — bin_path is shutil.which result
            [bin_path, str(vol), str(mp)],
            capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise MountToolError(f"vshadowmount timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise MountToolError(
            f"vshadowmount exited {proc.returncode}: {(proc.stderr or '').strip()}"
        )
    shadows = sorted([str(p) for p in mp.glob("vss*")])
    return {
        "tool": "vshadowmount",
        "volume": str(vol),
        "mount_point": str(mp),
        "shadows": shadows,
        "shadow_count": len(shadows),
        "stderr": proc.stderr,
        "cleanup_cmd": f"fusermount -u '{mp}'",
    }
