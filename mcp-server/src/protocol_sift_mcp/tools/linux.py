"""Linux DFIR primitives.

`linux_history_parse` is real (Sub-Plan 04 / W4). The remaining functions
(journal, audit, systemd, cron) are intentional NotImplementedError stubs
deferred to Sub-Plan 05+.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path
from .audit import audit_append

# zsh extended history: ":<sp><unix-ts>:<duration>;<cmd>"
_ZSH_RE = re.compile(r"^:\s+(\d+):(\d+);(.*)$")
# bash HISTTIMEFORMAT writes a comment line "#<unix-ts>" before each command.
# 10 digits covers 2001-09 .. 2286-11; 11 digits covers up through year ~5138.
_BASH_TS_RE = re.compile(r"^#(\d{10,11})$")


def linux_journal_query(
    journal_dir: str,
    *,
    unit: str | None = None,
    since: str | None = None,
    until: str | None = None,
    predicate: str | None = None,
) -> list[dict[str, Any]]:
    """Sub-Plan 05+ deferred: systemd-journalctl-style query against journal files."""
    _ = assert_input_path(journal_dir)
    raise NotImplementedError("linux_journal_query — Sub-Plan 05+ deferred")


def linux_audit_query(
    audit_log_path: str,
    *,
    syscall: str | None = None,
    time_range: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Sub-Plan 05+ deferred: parse audit.log with event correlation."""
    _ = assert_input_path(audit_log_path)
    raise NotImplementedError("linux_audit_query — Sub-Plan 05+ deferred")


def linux_history_parse(history_path: str) -> list[dict[str, Any]]:
    """Parse bash/.bash_history or zsh/.zsh_history.

    Returns list of {line_num, ts, command, raw_excerpt} dicts.

    - line_num: 1-based source line number for the *command* (for
      HISTTIMEFORMAT bash, the command line — not the timestamp comment).
    - ts: ISO 8601 string if HISTTIMEFORMAT or zsh extended detected; else None.
    - command: the shell command text.
    - raw_excerpt: the original line(s) for evidence pinning.

    Path is sandbox-asserted under /input via assert_input_path. Format is
    auto-detected (zsh > bash_histtimeformat > plain_bash) and a single
    `format_detected` audit event is emitted. Per-line parse errors are
    swallowed gracefully and counted in the format_detected event; a
    `tool_failure` audit event is emitted only on a top-level crash.
    """
    p = assert_input_path(history_path)
    audit_log = _audit_log_path()

    try:
        text = p.read_text(errors="replace")
    except Exception as exc:
        audit_append(
            audit_log,
            event="tool_failure",
            data={
                "tool": "linux_history_parse",
                "path": str(p),
                "error": f"read failed: {exc}",
            },
        )
        return []

    lines = text.splitlines()
    fmt = _detect_format(lines)

    try:
        if fmt == "zsh":
            entries, skipped = _parse_zsh(lines)
        elif fmt == "bash_histtimeformat":
            entries, skipped = _parse_bash_histtimeformat(lines)
        else:
            entries, skipped = _parse_plain(lines)
    except Exception as exc:
        audit_append(
            audit_log,
            event="tool_failure",
            data={
                "tool": "linux_history_parse",
                "path": str(p),
                "format": fmt,
                "error": str(exc),
            },
        )
        return []

    audit_append(
        audit_log,
        event="format_detected",
        data={
            "tool": "linux_history_parse",
            "path": str(p),
            "format": fmt,
            "entries": len(entries),
            "skipped_lines": skipped,
        },
    )
    return entries


def linux_systemd_units(image_path: str) -> list[dict[str, Any]]:
    """Sub-Plan 05+ deferred: enumerate units from /etc/systemd, /lib/systemd, ~/.config/systemd/user."""
    _ = assert_input_path(image_path)
    raise NotImplementedError("linux_systemd_units — Sub-Plan 05+ deferred")


def linux_cron_parse(image_path: str) -> list[dict[str, Any]]:
    """Sub-Plan 05+ deferred: parse all cron locations: /etc/crontab, /etc/cron.*, /var/spool/cron/."""
    _ = assert_input_path(image_path)
    raise NotImplementedError("linux_cron_parse — Sub-Plan 05+ deferred")


# ─── internal helpers ─────────────────────────────────────────────────────────


def _audit_log_path() -> Path:
    """Resolve the audit log path from OUTPUT_PATH (the conftest/server convention).

    Falls back to /output/audit.jsonl when the env var is unset (production
    container default). Does not validate existence — `audit_append` creates
    the parent directory.
    """
    output_root = os.environ.get("OUTPUT_PATH", "/output")
    return Path(output_root) / "audit.jsonl"


def _detect_format(lines: list[str]) -> str:
    """Heuristic: read first ~20 non-empty lines to pick a format.

    Order: zsh > bash_histtimeformat > plain_bash. Zsh wins because its
    regex is strict enough that a false positive is unlikely.
    """
    sample = [ln for ln in lines[:20] if ln.strip()]
    if not sample:
        return "plain_bash"
    if any(_ZSH_RE.match(ln) for ln in sample):
        return "zsh"
    for i, ln in enumerate(sample[:-1]):
        if _BASH_TS_RE.match(ln) and not _BASH_TS_RE.match(sample[i + 1]):
            return "bash_histtimeformat"
    return "plain_bash"


def _ts_iso(unix_ts: int) -> str:
    return datetime.fromtimestamp(unix_ts, tz=UTC).isoformat()


def _parse_zsh(lines: list[str]) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    skipped = 0
    for i, ln in enumerate(lines, 1):
        if not ln.strip():
            continue
        m = _ZSH_RE.match(ln)
        if not m:
            skipped += 1
            continue
        ts_unix, _dur, cmd = m.groups()
        try:
            ts_iso = _ts_iso(int(ts_unix))
        except (ValueError, OSError, OverflowError):
            skipped += 1
            continue
        out.append(
            {
                "line_num": i,
                "ts": ts_iso,
                "command": cmd,
                "raw_excerpt": ln,
            }
        )
    return out, skipped


def _parse_bash_histtimeformat(lines: list[str]) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    skipped = 0
    pending_ts: str | None = None
    pending_ts_raw: str | None = None
    for i, ln in enumerate(lines, 1):
        m = _BASH_TS_RE.match(ln)
        if m:
            try:
                pending_ts = _ts_iso(int(m.group(1)))
                pending_ts_raw = ln
            except (ValueError, OSError, OverflowError):
                pending_ts = None
                pending_ts_raw = None
                skipped += 1
            continue
        if not ln.strip():
            continue
        raw = (pending_ts_raw + "\n" + ln) if pending_ts_raw is not None else ln
        out.append(
            {
                "line_num": i,
                "ts": pending_ts,
                "command": ln,
                "raw_excerpt": raw,
            }
        )
        pending_ts = None
        pending_ts_raw = None
    return out, skipped


def _parse_plain(lines: list[str]) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    for i, ln in enumerate(lines, 1):
        if not ln.strip():
            continue
        out.append(
            {
                "line_num": i,
                "ts": None,
                "command": ln,
                "raw_excerpt": ln,
            }
        )
    return out, 0
