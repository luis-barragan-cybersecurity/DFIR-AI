"""Append-only JSONL audit log with sha256 hash-chain.

Every entry carries `prev_hash` = sha256 of the previous entry's canonical JSON
(sorted keys, compact separators). Genesis entry (seq=0) gets prev_hash =
"0" * 64. The chain lets `mh verify` detect tampering: any mutation, deletion,
or reordering of a prior line breaks the chain at the first downstream entry.

This is not legal-grade chain-of-custody (no signing yet — Phase B B2 adds GPG
signing), but it raises the bar materially: a single-byte change in audit.jsonl
is immediately detectable without external state.

The hash itself is computed over the canonical serialization of the entry,
NOT including the prev_hash field of the entry being hashed — i.e. we hash
the predecessor's full record (including its own prev_hash) before writing
the successor.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_PREV_HASH = "0" * 64


def _canonical(entry: dict[str, Any]) -> str:
    """Canonical JSON for hashing — sorted keys, compact separators, str-coerced."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def _hash_entry(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def _scan_tail(log_path: Path) -> tuple[int, str]:
    """Return (next_seq, prev_hash_for_next_entry) by scanning the existing log.

    Tolerates legacy entries without `prev_hash` — when found we continue the
    chain from a hash of that legacy entry's canonical form. That way old
    audit logs aren't unverifiable; they just start the chain at the first
    new entry written.
    """
    if not log_path.exists() or log_path.stat().st_size == 0:
        return 0, GENESIS_PREV_HASH

    last_line = ""
    n = 0
    with log_path.open() as f:
        for line in f:
            if line.strip():
                last_line = line
                n += 1
    if not last_line:
        return 0, GENESIS_PREV_HASH

    try:
        last_entry = json.loads(last_line)
    except json.JSONDecodeError as exc:
        # Corrupt tail — refuse to extend rather than silently break the chain.
        raise AuditChainError(
            f"audit log {log_path} has unparseable tail line"
        ) from exc
    return n, _hash_entry(last_entry)


class AuditChainError(Exception):
    """Raised when the audit chain is broken or unparseable."""


def audit_append(log_path: Path, *, event: str, data: dict[str, Any]) -> dict[str, Any]:
    """Append a tool-call / lifecycle event with prev_hash linking to the prior entry."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    next_seq, prev_hash = _scan_tail(log_path)
    entry = {
        "seq": next_seq,
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        "data": data,
        "prev_hash": prev_hash,
    }
    with log_path.open("a") as f:
        f.write(_canonical(entry) + "\n")
    return entry


def agent_message_append(
    log_path: Path,
    *,
    from_agent: str,
    to_agent: str,
    role: str,
    content: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append an inter-agent message. Also chained via prev_hash."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    next_seq, prev_hash = _scan_tail(log_path)
    entry = {
        "seq": next_seq,
        "ts": datetime.now(UTC).isoformat(),
        "from_agent": from_agent,
        "to_agent": to_agent,
        "role": role,
        "content": content,
        "metadata": metadata or {},
        "prev_hash": prev_hash,
    }
    with log_path.open("a") as f:
        f.write(_canonical(entry) + "\n")
    return entry


def verify_audit_chain(log_path: Path) -> dict[str, Any]:
    """Re-walk the log and verify every prev_hash. Returns a structured report.

    Returns:
        {
          "ok": bool,
          "entries": int,
          "first_break_seq": int | None,
          "reason": str | None,
        }

    A "break" is the first entry whose declared prev_hash does not match the
    sha256 of the predecessor's serialized form (or the genesis sentinel for
    the first entry). Legacy entries without a prev_hash field are treated as
    a break the moment they appear after a chained entry — i.e. silent
    downgrades are flagged.
    """
    if not log_path.exists():
        return {"ok": False, "entries": 0, "first_break_seq": None,
                "reason": "log file does not exist"}

    expected_prev = GENESIS_PREV_HASH
    n = 0
    with log_path.open() as f:
        for lineno, raw in enumerate(f):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                return {"ok": False, "entries": n, "first_break_seq": n,
                        "reason": f"line {lineno + 1}: unparseable JSON ({exc})"}
            declared = entry.get("prev_hash")
            if declared is None:
                return {"ok": False, "entries": n, "first_break_seq": entry.get("seq", n),
                        "reason": f"line {lineno + 1}: missing prev_hash (legacy entry)"}
            if declared != expected_prev:
                return {"ok": False, "entries": n, "first_break_seq": entry.get("seq", n),
                        "reason": (
                            f"line {lineno + 1}: prev_hash mismatch "
                            f"(declared {declared[:12]}…, expected {expected_prev[:12]}…)"
                        )}
            expected_prev = _hash_entry(entry)
            n += 1
    return {"ok": True, "entries": n, "first_break_seq": None, "reason": None}
