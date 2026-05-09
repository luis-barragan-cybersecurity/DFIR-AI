"""linux_history_parse real implementation tests (Sub-Plan 04 / W4).

Replaces the NotImplementedError stub with a stdlib-only regex parser that
handles plain bash, bash with HISTTIMEFORMAT, and zsh extended history.
Audit events are written to OUTPUT_PATH/audit.jsonl (via the conftest
_sandbox_env fixture which seeds OUTPUT_PATH at tmp_path/output).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from protocol_sift_mcp.tools.linux import linux_history_parse


def _audit_lines(tmp_output: Path) -> list[dict]:
    log = tmp_output / "audit.jsonl"
    if not log.exists():
        return []
    return [json.loads(ln) for ln in log.read_text().splitlines() if ln.strip()]


def test_plain_bash_history(tmp_path: Path) -> None:
    """Plain bash history returns one entry per non-empty line, ts=None."""
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    p = input_dir / ".bash_history"
    p.write_text("ls -la\necho hi\nrm /tmp/foo\n")

    entries = linux_history_parse(str(p))

    assert len(entries) == 3
    assert entries[0]["command"] == "ls -la"
    assert entries[0]["ts"] is None
    assert entries[0]["line_num"] == 1
    assert entries[0]["raw_excerpt"] == "ls -la"
    assert entries[2]["command"] == "rm /tmp/foo"
    assert entries[2]["line_num"] == 3

    output_dir = Path(os.environ["OUTPUT_PATH"])
    audit = _audit_lines(output_dir)
    assert any(
        e["event"] == "format_detected" and e["data"].get("format") == "plain_bash"
        for e in audit
    ), "plain_bash format_detected audit event missing"


def test_bash_histtimeformat(tmp_path: Path) -> None:
    """HISTTIMEFORMAT-decorated bash decodes ts to ISO 8601 UTC."""
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    p = input_dir / ".bash_history"
    p.write_text("#1714581234\nls -la\n#1714581235\necho hi\n")

    entries = linux_history_parse(str(p))

    assert len(entries) == 2
    assert entries[0]["command"] == "ls -la"
    # Unix ts 1714581234 = 2024-05-01 18:33:54 UTC
    assert entries[0]["ts"].startswith("2024-")
    assert "T" in entries[0]["ts"]
    assert entries[0]["ts"].endswith("+00:00")
    assert entries[1]["command"] == "echo hi"
    assert entries[1]["ts"] is not None

    output_dir = Path(os.environ["OUTPUT_PATH"])
    audit = _audit_lines(output_dir)
    assert any(
        e["event"] == "format_detected" and e["data"].get("format") == "bash_histtimeformat"
        for e in audit
    ), "bash_histtimeformat format_detected audit event missing"


def test_zsh_extended_history(tmp_path: Path) -> None:
    """zsh extended history parses ': <ts>:<dur>;<cmd>' format."""
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    p = input_dir / ".zsh_history"
    p.write_text(": 1714581234:0;ls -la\n: 1714581235:5;echo hi\n")

    entries = linux_history_parse(str(p))

    assert len(entries) == 2
    assert entries[0]["command"] == "ls -la"
    assert entries[0]["ts"] is not None
    assert entries[0]["ts"].startswith("2024-")
    assert entries[1]["command"] == "echo hi"
    assert entries[1]["ts"] is not None

    output_dir = Path(os.environ["OUTPUT_PATH"])
    audit = _audit_lines(output_dir)
    assert any(
        e["event"] == "format_detected" and e["data"].get("format") == "zsh"
        for e in audit
    ), "zsh format_detected audit event missing"


def test_malformed_line_does_not_crash(tmp_path: Path) -> None:
    """A zsh-shaped line in a bash file is absorbed gracefully — no crash."""
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    p = input_dir / ".bash_history"
    # Embedded zsh-shaped header that won't match the strict zsh regex.
    p.write_text("ls -la\n: not-a-ts:bad;cmd\necho hi\n")

    # The contract: must not raise. Plain-bash fallback is acceptable; if the
    # parser instead emits a tool_failure that's also fine — the load-bearing
    # assertion is that we got a list without crashing.
    entries = linux_history_parse(str(p))

    assert isinstance(entries, list)
    # At minimum the two valid bash lines survive.
    cmds = [e["command"] for e in entries]
    assert "ls -la" in cmds
    assert "echo hi" in cmds
