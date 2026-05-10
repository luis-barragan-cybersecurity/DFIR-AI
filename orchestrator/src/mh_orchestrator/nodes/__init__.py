"""Node registry + shared helpers."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from protocol_sift_mcp.tools.audit import agent_message_append, audit_append

from ..state import IncidentState
from . import (
    analyze,
    attack_tag,
    contain,
    d3fend_recommend,
    declare_incident,
    detect,
    eradicate,
    human_in_loop,
    kill_chain,
    lessons_learned,
    recover,
    remediation,
    session_finalize,
    session_init,
    suppress,
    triage,
    verifier_pass,
)


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


# §11.2 registry — 14 IR nodes plus session_init + session_finalize framing.
# Note: kill_chain_classify is registered as "kill_chain" and remediation_plan
# is registered as "remediation" (graph-key names match the LangGraph nodes;
# §11.4 phase mapping in picerl.NODE_TO_PICERL uses the longer descriptive
# names — see picerl.picerl_phase_for callers in each node body).
NODES: dict[str, Callable[[IncidentState], IncidentState]] = {
    "session_init": session_init.run,
    "detect": detect.run,
    "triage": triage.run,
    "declare_incident": declare_incident.run,
    "suppress": suppress.run,
    "analyze": analyze.run,
    "attack_tag": attack_tag.run,
    "kill_chain": kill_chain.run,
    "d3fend_recommend": d3fend_recommend.run,
    "contain": contain.run,
    "human_in_loop": human_in_loop.run,
    "eradicate": eradicate.run,
    "recover": recover.run,
    "lessons_learned": lessons_learned.run,
    "remediation": remediation.run,
    "verifier_pass": verifier_pass.run,
    "session_finalize": session_finalize.run,
}
