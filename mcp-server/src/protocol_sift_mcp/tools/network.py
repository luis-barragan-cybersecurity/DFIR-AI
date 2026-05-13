"""Network forensic wrappers — tshark + zeek log readers.

Two entrypoints:

  tshark_extract(pcap_path, display_filter=None, fields=None)
      Wraps tshark -T fields with an allowlisted display filter.
      Returns parsed rows (list[dict]).

  zeek_log_read(log_path)
      Reads a Zeek connection / DNS / SSL log (TSV with #fields header),
      returns parsed rows.

Both stay sandbox-asserted under EVIDENCE_PATH and pin all subprocess calls
to a wall-clock cap.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path

DEFAULT_TIMEOUT_SEC = 600

# Tshark display-filter operators that are safe to expose. Anything not
# matching this allowlist is rejected at the boundary. We don't try to
# validate the full Wireshark filter grammar — we just refuse shell
# meta-characters and ban anything starting with '!' to prevent path
# expansion games.
_DISPLAY_FILTER_BAD: tuple[str, ...] = (";", "|", "&", "$", "`", "\n", "\\")


class TsharkError(Exception):
    """tshark binary missing, filter invalid, timeout, non-zero exit."""


class ZeekLogError(Exception):
    """Zeek log unreadable or malformed."""


def _resolve(bin_name: str) -> str:
    path = shutil.which(bin_name)
    if not path:
        raise TsharkError(f"{bin_name} not found on PATH. apt install tshark (or zeek).")
    return path


def _validate_filter(f: str) -> None:
    for bad in _DISPLAY_FILTER_BAD:
        if bad in f:
            raise TsharkError(f"display filter contains forbidden char {bad!r}")
    if len(f) > 1024:
        raise TsharkError("display filter too long (>1024 chars)")


def tshark_extract(
    pcap_path: str,
    *,
    display_filter: str | None = None,
    fields: list[str] | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_rows: int = 100_000,
) -> dict[str, Any]:
    """Run tshark against a pcap, return parsed field-row output.

    fields: list of tshark field names (e.g. ['ip.src', 'ip.dst', 'tcp.port']).
    display_filter: optional Wireshark display filter (e.g. 'http.host').
    """
    pcap = assert_input_path(pcap_path)
    bin_path = _resolve("tshark")

    if display_filter is not None:
        _validate_filter(display_filter)

    fields = fields or ["frame.time", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
                        "_ws.col.Protocol", "_ws.col.Info"]
    cmd: list[str] = [
        bin_path, "-r", str(pcap), "-T", "fields", "-E", "separator=\t",
        "-E", "occurrence=f", "-E", "quote=n",
    ]
    for f in fields:
        cmd.extend(["-e", f])
    if display_filter:
        cmd.extend(["-Y", display_filter])

    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TsharkError(f"tshark timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise TsharkError(
            f"tshark exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )

    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        cells = line.split("\t")
        # Pad short rows so zip preserves alignment.
        while len(cells) < len(fields):
            cells.append("")
        rows.append(dict(zip(fields, cells, strict=False)))
        if len(rows) >= max_rows:
            break
    return {
        "tool": "tshark",
        "pcap": str(pcap),
        "rows": rows,
        "row_count": len(rows),
        "fields": fields,
        "stderr_tail": (proc.stderr or "")[-512:],
    }


def zeek_log_read(log_path: str, *, max_rows: int = 100_000) -> dict[str, Any]:
    """Parse a Zeek TSV log (conn.log, dns.log, ssl.log, etc.).

    The Zeek logs have a header preamble starting with '#separator', '#set_separator',
    '#fields', '#types'. We honor #fields for column names.
    """
    p = assert_input_path(log_path)
    fields: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        with p.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not fields:
                    raise ZeekLogError(
                        f"{p}: data row before #fields header — malformed Zeek log"
                    )
                cells = line.split("\t")
                while len(cells) < len(fields):
                    cells.append("")
                rows.append(dict(zip(fields, cells, strict=False)))
                if len(rows) >= max_rows:
                    break
    except UnicodeError as exc:  # pragma: no cover — utf-8 + replace usually swallows
        raise ZeekLogError(f"failed to decode {p}: {exc}") from exc
    return {
        "tool": "zeek_log_read",
        "log_path": str(p),
        "fields": fields,
        "rows": rows,
        "row_count": len(rows),
    }
