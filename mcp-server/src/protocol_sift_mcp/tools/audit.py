"""Plain append-only JSONL audit log.

Replaces the prior hash-chained chain-of-custody. No cryptographic linking,
no signing, no attestation. Internal admin IR only — not legal-grade.
Every entry has seq + ts + event + data.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _next_seq(log_path: Path) -> int:
    if not log_path.exists() or log_path.stat().st_size == 0:
        return 0
    n = 0
    with log_path.open() as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def audit_append(log_path: Path, *, event: str, data: dict[str, Any]) -> dict[str, Any]:
    """Append a tool-call / lifecycle event to the audit log."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "seq": _next_seq(log_path),
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        "data": data,
    }
    with log_path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str) + "\n")
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
    """Append an inter-agent message. Required for hackathon multi-agent submissions."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "seq": _next_seq(log_path),
        "ts": datetime.now(UTC).isoformat(),
        "from_agent": from_agent,
        "to_agent": to_agent,
        "role": role,
        "content": content,
        "metadata": metadata or {},
    }
    with log_path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str) + "\n")
    return entry
