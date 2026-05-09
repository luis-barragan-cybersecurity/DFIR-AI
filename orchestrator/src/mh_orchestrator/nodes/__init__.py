"""Node registry + shared helpers."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from protocol_sift_mcp.tools.audit import agent_message_append, audit_append

from ..state import IncidentState
from . import claude_dispatch, session_finalize, session_init


def emit_message(
    state: IncidentState, *, from_agent: str, to_agent: str, role: str,
    content: str, metadata: dict[str, Any] | None = None,
) -> None:
    out = Path(state["_output_dir"])
    agent_message_append(
        out / "agent_messages.jsonl",
        from_agent=from_agent, to_agent=to_agent, role=role,
        content=content, metadata=metadata or {},
    )


def record_audit(state: IncidentState, *, event: str, data: dict[str, Any]) -> None:
    out = Path(state["_output_dir"])
    audit_append(out / "audit.jsonl", event=event, data=data)


NODES: dict[str, Callable[[IncidentState], IncidentState]] = {
    "session_init": session_init.run,
    "claude_dispatch": claude_dispatch.run,
    "session_finalize": session_finalize.run,
}
