"""Plaso wrappers — log2timeline + psort for unified timeline reconstruction.

Plaso is the de-facto SIFT timeline tool. log2timeline.py extracts every
parsable artifact from a disk image / directory / file into a .plaso store;
psort.py renders the store into a sorted timeline (JSON, l2tcsv, etc.).

We expose two top-level entrypoints:
  - log2timeline(source, storage_path, parsers="all", timeout_sec=3600)
  - psort(storage_path, output_format="json_line", timeout_sec=1800)

Both shell out to the system `log2timeline.py` and `psort.py` binaries with
the same sandbox + allowlist + timeout pattern as memory.py.

Storage path lives under /output (writable). Source lives under /input.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ..sandbox import assert_input_path, assert_output_path

DEFAULT_L2T_TIMEOUT = 3600  # 1h cap on log2timeline
DEFAULT_PSORT_TIMEOUT = 1800  # 30m cap on psort

# psort output formats we'll accept. json_line is the canonical agent target.
_ALLOWED_OUTPUT_FORMATS: frozenset[str] = frozenset({
    "json_line", "l2tcsv", "l2ttln", "dynamic", "tln",
})


class PlasoError(Exception):
    """log2timeline / psort binary missing, timeout, non-zero exit."""


def _resolve(bin_name: str) -> str:
    # log2timeline.py + psort.py historically used the .py suffix; modern
    # distributions sometimes drop it. Probe both.
    candidates = [bin_name, bin_name.removesuffix(".py")]
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    raise PlasoError(
        f"{bin_name} not found on PATH. Install plaso (pip install plaso or apt install plaso-tools)."
    )


def log2timeline(
    source_path: str,
    storage_path: str,
    *,
    parsers: str = "win_gen,webhist,sysreg",
    timeout_sec: int = DEFAULT_L2T_TIMEOUT,
) -> dict[str, Any]:
    """Extract a Plaso .plaso storage file from a source under /input.

    parsers: comma-separated parser/preset names. Default 'win_gen,webhist,
        sysreg' covers Windows OS artifacts, browser history, registry —
        the typical IR-triage subset. Pass 'all' to run every parser
        (significantly slower).

    Returns: {storage_path, source, exit_code, stderr_tail, elapsed_hint}
    """
    src = assert_input_path(source_path)
    storage = assert_output_path(storage_path)
    storage.parent.mkdir(parents=True, exist_ok=True)

    bin_path = _resolve("log2timeline.py")
    cmd: list[str] = [
        bin_path, "--status_view", "none",
        "--parsers", parsers,
        "--storage_file", str(storage),
        str(src),
    ]
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PlasoError(f"log2timeline timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise PlasoError(
            f"log2timeline exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )
    return {
        "tool": "log2timeline",
        "source": str(src),
        "storage_path": str(storage),
        "exit_code": proc.returncode,
        "stderr_tail": (proc.stderr or "")[-1024:],
        "size_bytes": storage.stat().st_size if storage.exists() else 0,
    }


def psort(
    storage_path: str,
    *,
    output_format: str = "json_line",
    output_path: str | None = None,
    time_slice: tuple[str, str] | None = None,
    timeout_sec: int = DEFAULT_PSORT_TIMEOUT,
    max_events: int = 200_000,
) -> dict[str, Any]:
    """Render a .plaso store into a sorted timeline.

    output_format: one of json_line, l2tcsv, l2ttln, dynamic, tln.
    output_path: where to write. Defaults to <storage>.<format>.
    time_slice: optional (since_iso, until_iso) filter.
    max_events: when output_format=json_line, parse + return up to this
        many events in `events` for direct consumption.

    Returns:
        {storage_path, output_format, output_path, event_count,
         events (json_line only, truncated to max_events), stderr_tail}
    """
    if output_format not in _ALLOWED_OUTPUT_FORMATS:
        raise ValueError(f"output_format {output_format!r} not in {sorted(_ALLOWED_OUTPUT_FORMATS)}")

    storage = assert_output_path(storage_path)  # storage file lives under /output
    if not storage.exists():
        raise PlasoError(f"plaso storage not found: {storage}")

    if output_path is None:
        ext = {"json_line": "jsonl", "l2tcsv": "csv"}.get(output_format, output_format)
        out = assert_output_path(str(storage.with_suffix(f".{ext}")))
    else:
        out = assert_output_path(output_path)

    bin_path = _resolve("psort.py")
    cmd: list[str] = [
        bin_path, "-o", output_format, "-w", str(out), str(storage),
    ]
    if time_slice:
        cmd.extend(["--slice", time_slice[0], "--slice_size", time_slice[1]])
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PlasoError(f"psort timed out after {timeout_sec}s") from exc
    if proc.returncode != 0:
        raise PlasoError(
            f"psort exited {proc.returncode}: {(proc.stderr or '').strip()[:512]}"
        )

    result: dict[str, Any] = {
        "tool": "psort",
        "storage_path": str(storage),
        "output_format": output_format,
        "output_path": str(out),
        "stderr_tail": (proc.stderr or "")[-1024:],
        "event_count": 0,
        "events": None,
    }
    if output_format == "json_line" and out.exists():
        events: list[dict[str, Any]] = []
        with out.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(events) >= max_events:
                    result["truncated"] = True
                    break
        result["events"] = events
        result["event_count"] = len(events)
    return result
