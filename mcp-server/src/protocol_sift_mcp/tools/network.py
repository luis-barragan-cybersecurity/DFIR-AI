"""Network forensic wrappers — tshark + zeek + pcap distillation + NetFlow + pcap manipulation.

Two original entrypoints (Tier-1):

  tshark_extract(pcap_path, display_filter=None, fields=None)
      Wraps tshark -T fields with an allowlisted display filter. Returns parsed rows.

  zeek_log_read(log_path)
      Reads a Zeek TSV log (TSV with #fields header), returns parsed rows.

Tier-3 Phase 3a additions:

  Group A — Pcap distillation pipeline (FOR572 "Ingest and Distill"):
    pcap_to_zeek(pcap, out_dir)        — `zeek -r`
    pcap_to_netflow(pcap, out_dir)     — `nfpcapd -r ... -l`
    pcap_to_passivedns(pcap, out_dir)  — `passivedns -r ... -l`

  Group B — Pcap manipulation toolkit (FOR572 "Reduce and Filter"):
    pcap_info(pcap)                                  — `capinfos`
    pcap_slice_time(pcap, start, end, out)           — `editcap -A/-B`
    pcap_merge(pcap_list, out)                       — `mergecap -w`
    pcap_filter_bpf(pcap, bpf, out)                  — `tcpdump -r ... -w ... <bpf>`
    tcp_reassemble(pcap, out_dir)                    — `tcpflow -o ... -r`

  Group C — NetFlow query:
    nfdump_query(nfcapd_files, filter, agg, fmt, top_n)  — `nfdump`

All wrappers sandbox-assert input paths under EVIDENCE_PATH and output paths under
OUTPUT_PATH, cap subprocess wall-clock, and raise typed boundary errors with
"install with apt ..." hints when binaries are missing.

The analytics layer that consumes distilled Zeek logs lives in `network_analytics.py`.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any

from ..sandbox import assert_input_path, assert_output_path

DEFAULT_TIMEOUT_SEC = 600
PCAP_DISTILL_TIMEOUT_SEC = 1800  # zeek/nfpcapd can chew on a large pcap for a while

# Tshark display-filter operators that are safe to expose. Anything not
# matching this allowlist is rejected at the boundary. We don't try to
# validate the full Wireshark filter grammar — we just refuse shell
# meta-characters and ban anything starting with '!' to prevent path
# expansion games.
_DISPLAY_FILTER_BAD: tuple[str, ...] = (";", "|", "&", "$", "`", "\n", "\\")

# Same allowlist applies to BPF strings passed to tcpdump.
_BPF_BAD: tuple[str, ...] = (";", "|", "&", "$", "`", "\n", "\\", ">", "<")

# editcap accepts "YYYY-MM-DD HH:MM:SS" or ISO "YYYY-MM-DDTHH:MM:SS"; accept both,
# normalize to editcap's preferred space form.
_ISO_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)


class TsharkError(Exception):
    """tshark binary missing, filter invalid, timeout, non-zero exit."""


class ZeekLogError(Exception):
    """Zeek log unreadable or malformed."""


class PcapToolError(Exception):
    """zeek/nfpcapd/passivedns/capinfos/editcap/mergecap/tcpdump/tcpflow failure or missing binary."""


class NetFlowError(Exception):
    """nfdump binary missing, output unparseable, or non-zero exit."""


def _resolve(bin_name: str) -> str:
    """Backwards-compatible resolver used by tshark_extract. Prefer `_resolve_binary` for new wrappers."""
    path = shutil.which(bin_name)
    if not path:
        raise TsharkError(f"{bin_name} not found on PATH. apt install tshark (or zeek).")
    return path


def _resolve_binary(bin_name: str, *, error_cls: type[Exception], install_hint: str) -> str:
    """Resolve a tool binary or raise the caller's typed boundary error with an install hint.

    Each Phase-3a wrapper uses this so an analyst on a non-SIFT host gets a clear next step
    rather than a generic FileNotFoundError.
    """
    path = shutil.which(bin_name)
    if not path:
        raise error_cls(f"{bin_name} not found on PATH. {install_hint}")
    return path


def _run(cmd: list[str], *, timeout_sec: int, error_cls: type[Exception]) -> tuple[str, str]:
    """Shared subprocess.run wrapper. Returns (stdout, stderr) or raises `error_cls`."""
    try:
        proc = subprocess.run(  # noqa: S603 — argv only; first arg from shutil.which, rest sandbox-asserted
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise error_cls(f"{cmd[0]} timed out after {timeout_sec}s") from exc
    except FileNotFoundError as exc:
        raise error_cls(f"{cmd[0]} exec failed: {exc}") from exc
    if proc.returncode != 0:
        raise error_cls(
            f"{cmd[0]} exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )
    return proc.stdout, proc.stderr or ""


def _validate_filter(f: str) -> None:
    if f.startswith("-"):
        raise TsharkError(f"display filter may not start with '-' (got {f[:32]!r})")
    for bad in _DISPLAY_FILTER_BAD:
        if bad in f:
            raise TsharkError(f"display filter contains forbidden char {bad!r}")
    if len(f) > 1024:
        raise TsharkError("display filter too long (>1024 chars)")


def _validate_bpf(b: str) -> None:
    """Reject BPF strings containing shell-metacharacters, redirection, or argument-injection patterns.

    Three defenses, in order:
      1. No shell metacharacters — even though we pass argv list (not shell=True), defense in depth.
      2. No leading dash — prevents an attacker-supplied "BPF" from being interpreted as a CLI flag
         by tcpdump/nfdump (`-w /etc/passwd`, `--config=…`). This is the argument-injection class
         that argv-list-passing alone does NOT defeat.
      3. Length cap — bounds parser work.
    """
    if b.startswith("-"):
        raise PcapToolError(f"BPF/filter argument may not start with '-' (got {b[:32]!r})")
    for bad in _BPF_BAD:
        if bad in b:
            raise PcapToolError(f"BPF filter contains forbidden char {bad!r}")
    if len(b) > 1024:
        raise PcapToolError("BPF filter too long (>1024 chars)")


def _validate_editcap_ts(ts: str) -> str:
    """Validate timestamp format and return the editcap-friendly form (space-separated)."""
    if not _ISO_TS_RE.match(ts):
        raise PcapToolError(
            f"timestamp {ts!r} not in ISO format (expected YYYY-MM-DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS)"
        )
    return ts.replace("T", " ")


# ────────────────────────────────────────────────────────────────────────────
# Tier-1 originals (unchanged)
# ────────────────────────────────────────────────────────────────────────────


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


# ────────────────────────────────────────────────────────────────────────────
# Group A — Pcap distillation pipeline
# ────────────────────────────────────────────────────────────────────────────


def pcap_to_zeek(
    pcap_path: str,
    output_dir: str,
    *,
    timeout_sec: int = PCAP_DISTILL_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Distill a pcap into Zeek logs via `zeek -r`.

    Zeek writes conn.log, dns.log, http.log, ssl.log, files.log, etc. to its CWD.
    We run it with cwd=output_dir so logs land where the caller asked.

    Returns:
        {tool, pcap, logs_dir, log_files, stderr_tail}
    """
    pcap = assert_input_path(pcap_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bin_path = _resolve_binary(
        "zeek", error_cls=PcapToolError,
        install_hint="On SIFT/Ubuntu: apt install zeek. On macOS: brew install zeek.",
    )

    cmd = [bin_path, "-r", str(pcap)]
    try:
        proc = subprocess.run(  # noqa: S603 — argv only; bin from shutil.which, pcap sandbox-asserted
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False, cwd=str(out),
        )
    except subprocess.TimeoutExpired as exc:
        raise PcapToolError(f"zeek timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise PcapToolError(
            f"zeek exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )

    log_files = sorted(str(p) for p in out.glob("*.log"))
    return {
        "tool": "pcap_to_zeek",
        "pcap": str(pcap),
        "logs_dir": str(out),
        "log_files": log_files,
        "stderr_tail": (proc.stderr or "")[-512:],
    }


def pcap_to_netflow(
    pcap_path: str,
    output_dir: str,
    *,
    timeout_sec: int = PCAP_DISTILL_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Distill a pcap into NetFlow v5 records via `nfpcapd`.

    Returns:
        {tool, pcap, netflow_dir, netflow_files, stderr_tail}
    """
    pcap = assert_input_path(pcap_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bin_path = _resolve_binary(
        "nfpcapd", error_cls=PcapToolError,
        install_hint="On SIFT/Ubuntu: apt install nfdump (provides nfpcapd).",
    )

    cmd = [bin_path, "-r", str(pcap), "-l", str(out)]
    _stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    netflow_files = sorted(str(p) for p in out.iterdir() if p.is_file() and p.name.startswith("nfcapd."))
    return {
        "tool": "pcap_to_netflow",
        "pcap": str(pcap),
        "netflow_dir": str(out),
        "netflow_files": netflow_files,
        "stderr_tail": stderr[-512:],
    }


def pcap_to_passivedns(
    pcap_path: str,
    output_dir: str,
    *,
    timeout_sec: int = PCAP_DISTILL_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Distill a pcap into PassiveDNS log entries via `passivedns -r`.

    Returns:
        {tool, pcap, passivedns_log, stderr_tail}
    """
    pcap = assert_input_path(pcap_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bin_path = _resolve_binary(
        "passivedns", error_cls=PcapToolError,
        install_hint=(
            "Not always shipped on SIFT — build from gamelinux/passivedns "
            "or use Suricata's dns.log as a substitute."
        ),
    )

    log_path = out / "passivedns.log"
    cmd = [bin_path, "-r", str(pcap), "-l", str(log_path)]
    _stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    return {
        "tool": "pcap_to_passivedns",
        "pcap": str(pcap),
        "passivedns_log": str(log_path),
        "exists": log_path.exists(),
        "size_bytes": log_path.stat().st_size if log_path.exists() else 0,
        "stderr_tail": stderr[-512:],
    }


# ────────────────────────────────────────────────────────────────────────────
# Group B — Pcap manipulation toolkit
# ────────────────────────────────────────────────────────────────────────────


def pcap_info(
    pcap_path: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Run `capinfos` and parse key/value summary lines."""
    pcap = assert_input_path(pcap_path)
    bin_path = _resolve_binary(
        "capinfos", error_cls=PcapToolError,
        install_hint="apt install wireshark-common (provides capinfos).",
    )

    cmd = [bin_path, str(pcap)]
    stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    summary: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        summary[key.strip()] = val.strip()

    return {
        "tool": "pcap_info",
        "pcap": str(pcap),
        "summary": summary,
        "raw": stdout,
        "stderr_tail": stderr[-512:],
    }


def pcap_slice_time(
    pcap_path: str,
    start_time: str,
    end_time: str,
    output_path: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Slice a pcap to packets whose timestamp falls in [start_time, end_time] via `editcap -A/-B`.

    Times accepted in ISO-8601 ("YYYY-MM-DDTHH:MM:SS") or editcap's native space form;
    we normalize internally.
    """
    pcap = assert_input_path(pcap_path)
    out_path = assert_output_path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    start_norm = _validate_editcap_ts(start_time)
    end_norm = _validate_editcap_ts(end_time)
    bin_path = _resolve_binary(
        "editcap", error_cls=PcapToolError,
        install_hint="apt install wireshark-common (provides editcap).",
    )

    cmd = [bin_path, "-A", start_norm, "-B", end_norm, str(pcap), str(out_path)]
    _stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    return {
        "tool": "pcap_slice_time",
        "pcap": str(pcap),
        "output_path": str(out_path),
        "exists": out_path.exists(),
        "size_bytes": out_path.stat().st_size if out_path.exists() else 0,
        "start": start_norm,
        "end": end_norm,
        "stderr_tail": stderr[-512:],
    }


def pcap_merge(
    pcap_list: list[str],
    output_path: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Merge multiple pcaps chronologically via `mergecap -w`."""
    if not pcap_list:
        raise ValueError("pcap_list is empty — nothing to merge")

    resolved_inputs = [str(assert_input_path(p)) for p in pcap_list]
    out_path = assert_output_path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path = _resolve_binary(
        "mergecap", error_cls=PcapToolError,
        install_hint="apt install wireshark-common (provides mergecap).",
    )

    cmd = [bin_path, "-w", str(out_path), *resolved_inputs]
    _stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    return {
        "tool": "pcap_merge",
        "inputs": resolved_inputs,
        "output_path": str(out_path),
        "exists": out_path.exists(),
        "size_bytes": out_path.stat().st_size if out_path.exists() else 0,
        "stderr_tail": stderr[-512:],
    }


def pcap_filter_bpf(
    pcap_path: str,
    bpf: str,
    output_path: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Filter a pcap with a validated BPF string via `tcpdump -r ... -w ...`.

    BPF strings are passed as a single argv element (not via shell), and shell
    meta-characters are rejected at the boundary for defense-in-depth.
    """
    pcap = assert_input_path(pcap_path)
    out_path = assert_output_path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _validate_bpf(bpf)
    bin_path = _resolve_binary(
        "tcpdump", error_cls=PcapToolError,
        install_hint="apt install tcpdump.",
    )

    cmd = [bin_path, "-r", str(pcap), "-w", str(out_path), bpf]
    _stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    return {
        "tool": "pcap_filter_bpf",
        "pcap": str(pcap),
        "bpf": bpf,
        "output_path": str(out_path),
        "exists": out_path.exists(),
        "size_bytes": out_path.stat().st_size if out_path.exists() else 0,
        "stderr_tail": stderr[-512:],
    }


def tcp_reassemble(
    pcap_path: str,
    output_dir: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Reassemble TCP streams to per-flow files via `tcpflow -o <dir> -r <pcap>`."""
    pcap = assert_input_path(pcap_path)
    out = assert_output_path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bin_path = _resolve_binary(
        "tcpflow", error_cls=PcapToolError,
        install_hint="apt install tcpflow.",
    )

    cmd = [bin_path, "-o", str(out), "-r", str(pcap)]
    _stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=PcapToolError)

    flow_files = sorted(str(p) for p in out.iterdir() if p.is_file())
    return {
        "tool": "tcp_reassemble",
        "pcap": str(pcap),
        "output_dir": str(out),
        "flow_files": flow_files,
        "flow_count": len(flow_files),
        "stderr_tail": stderr[-512:],
    }


# ────────────────────────────────────────────────────────────────────────────
# Group C — NetFlow query (nfdump)
# ────────────────────────────────────────────────────────────────────────────


_NFDUMP_OUTPUT_FORMATS: frozenset[str] = frozenset({"line", "long", "extended", "csv", "json", "raw"})


def nfdump_query(
    nfcapd_path: str,
    *,
    bpf_filter: str | None = None,
    aggregation: str | None = None,
    output_format: str = "csv",
    top_n: int | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Query NetFlow records via `nfdump -r`.

    nfcapd_path can be a single nfcapd file or a directory (nfdump understands both
    via -R for ranges; we use -r for the simple single-file/single-dir-glob case).

    aggregation: one of nfdump's -A keys, e.g. "srcip,dstip" or "srcip,dstport".
    output_format: nfdump -o key — "csv" (default, parsed into rows), "line", "long",
        "extended", "json", "raw".
    top_n: passed to -c for record cap.
    bpf_filter: passed as the trailing positional filter expression (sanitized).
    """
    src = assert_input_path(nfcapd_path)
    if output_format not in _NFDUMP_OUTPUT_FORMATS:
        raise NetFlowError(
            f"output_format {output_format!r} not in allowlist {sorted(_NFDUMP_OUTPUT_FORMATS)}"
        )
    if bpf_filter is not None:
        _validate_bpf(bpf_filter)
    bin_path = _resolve_binary(
        "nfdump", error_cls=NetFlowError,
        install_hint="apt install nfdump.",
    )

    cmd: list[str] = [bin_path, "-r", str(src), "-o", output_format]
    if aggregation:
        _validate_bpf(aggregation)  # same character allowlist applies
        cmd.extend(["-A", aggregation])
    if top_n is not None:
        cmd.extend(["-c", str(int(top_n))])
    if bpf_filter:
        cmd.append(bpf_filter)

    stdout, stderr = _run(cmd, timeout_sec=timeout_sec, error_cls=NetFlowError)

    rows: list[dict[str, Any]] | None = None
    if output_format == "csv":
        rows = _parse_nfdump_csv(stdout)

    return {
        "tool": "nfdump_query",
        "source": str(src),
        "aggregation": aggregation,
        "output_format": output_format,
        "rows": rows,
        "raw": stdout,
        "stderr_tail": stderr[-512:],
    }


def _parse_nfdump_csv(text: str) -> list[dict[str, Any]]:
    """Parse nfdump's CSV output. Header line first, then data rows; trailing summary
    block starts with 'Summary:' or 'Time window:' lines we should skip.
    """
    rows: list[dict[str, Any]] = []
    headers: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith(("Summary:", "Time window:", "Total flows:",
                            "Total bytes:", "Total packets:", "Aggregated")):
            continue
        cells = [c.strip() for c in line.split(",")]
        if not headers:
            if any(h in cells for h in ("ts", "te", "sa", "da", "sp", "dp", "pr")):
                headers = cells
                continue
            # First non-summary line that isn't a header — skip rather than crash.
            continue
        if len(cells) != len(headers):
            continue
        rows.append(dict(zip(headers, cells, strict=False)))
    return rows
