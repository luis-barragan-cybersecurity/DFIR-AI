"""File-carving + binary-inspection wrappers — bulk_extractor, binwalk, strings.

Three entrypoints — every one wraps a SIFT binary with a sandbox-asserted
input path, capped subprocess wall clock, and structured return shape.

  bulk_extractor(image_path, output_dir, features="all")
      Pulls IPs, URLs, emails, credit-card patterns, etc. from any binary
      blob. Writes feature files into output_dir; we parse the summary.

  binwalk(target_path, *, recursive=False)
      Identifies embedded files / firmware structure in a binary.

  strings_extract(target_path, *, min_length=6, encoding="utf-8")
      Pure-Python strings emulation — no subprocess, no allowlist.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path, assert_output_path

DEFAULT_TIMEOUT_SEC = 1800

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]+")


class CarvingError(Exception):
    """bulk_extractor / binwalk binary missing or non-zero exit."""


def _resolve(bin_name: str) -> str:
    path = shutil.which(bin_name)
    if not path:
        raise CarvingError(f"{bin_name} not on PATH. SIFT: apt install {bin_name}.")
    return path


def bulk_extractor(
    image_path: str,
    output_dir: str,
    *,
    features: str = "all",
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Run bulk_extractor and return a summary of feature files emitted.

    features: 'all' or a single-feature name (e.g. 'email', 'url', 'ccn').
    The output_dir must live under /output.
    """
    src = assert_input_path(image_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bin_path = _resolve("bulk_extractor")

    cmd: list[str] = [bin_path, "-o", str(out), str(src)]
    if features != "all":
        # Disable everything, then enable the one feature.
        cmd[-2:] = ["-x", "all", "-e", features, "-o", str(out), str(src)]

    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CarvingError(f"bulk_extractor timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise CarvingError(
            f"bulk_extractor exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )

    # Inventory feature files written.
    features_out: dict[str, dict[str, int]] = {}
    for f in sorted(out.glob("*.txt")):
        try:
            n = sum(1 for line in f.open() if line.strip() and not line.startswith("#"))
        except OSError:
            n = 0
        features_out[f.name] = {"path": str(f), "row_count": n}  # type: ignore[dict-item]
    return {
        "tool": "bulk_extractor",
        "source": str(src),
        "output_dir": str(out),
        "features": features_out,
        "stderr_tail": (proc.stderr or "")[-512:],
    }


def binwalk(
    target_path: str,
    *,
    recursive: bool = False,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Identify embedded files / firmware structure inside a binary blob."""
    src = assert_input_path(target_path)
    bin_path = _resolve("binwalk")

    cmd: list[str] = [bin_path]
    if recursive:
        cmd.append("--matryoshka")
    cmd.append(str(src))

    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CarvingError(f"binwalk timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise CarvingError(
            f"binwalk exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )

    # Parse the columnar output: DECIMAL HEXADECIMAL DESCRIPTION
    rows: list[dict[str, Any]] = []
    in_table = False
    for line in proc.stdout.splitlines():
        if line.startswith("--"):
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split(None, 2)
        if len(parts) >= 3 and parts[0].isdigit():
            rows.append({"decimal_offset": parts[0], "hex_offset": parts[1],
                         "description": parts[2]})
    return {
        "tool": "binwalk",
        "source": str(src),
        "rows": rows,
        "raw": proc.stdout,
    }


def strings_extract(
    target_path: str,
    *,
    min_length: int = 6,
    max_strings: int = 100_000,
) -> dict[str, Any]:
    """Pure-Python ASCII-strings extraction. No subprocess.

    Reads up to 1 GiB; longer blobs are truncated with `truncated=True` flag.
    """
    p = assert_input_path(target_path)
    cap = 1 << 30  # 1 GiB hard read cap
    out: list[dict[str, Any]] = []
    bytes_read = 0
    truncated = False
    with p.open("rb") as f:
        while bytes_read < cap and len(out) < max_strings:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            offset_base = bytes_read
            for m in _PRINTABLE_RE.finditer(chunk):
                if m.end() - m.start() >= min_length:
                    out.append({
                        "offset": offset_base + m.start(),
                        "length": m.end() - m.start(),
                        "ascii": chunk[m.start():m.end()].decode("ascii", errors="replace"),
                    })
                    if len(out) >= max_strings:
                        truncated = True
                        break
            bytes_read += len(chunk)
        if bytes_read >= cap:
            truncated = True
    return {
        "tool": "strings_extract",
        "source": str(p),
        "bytes_scanned": bytes_read,
        "string_count": len(out),
        "truncated": truncated,
        "strings": out,
    }
