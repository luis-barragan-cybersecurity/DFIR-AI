"""triage node — invokes per-OS specialist subagent for severity classification."""
from __future__ import annotations

from pathlib import Path

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "triage"

# Map _detected_os → subagent name (per .claude/agents/*.md frontmatter)
# memory_dump routes to WindowsAgent because WindowsAgent already has
# memory_volatility in its tool allowlist + its prompt has an explicit
# "For memory dumps, additionally apply memory-forensics skill" clause.
# This avoids creating a separate MemoryAgent that would duplicate that
# tool surface; it also means a memory-only case (no registry/EVTX) flows
# correctly through windows-triage skill → memory-forensics skill fallback.
OS_TO_SUBAGENT = {
    "windows": "WindowsAgent",
    "macos": "MacOSAgent",
    "linux": "LinuxAgent",
    "memory_dump": "WindowsAgent",
    "unknown": "WindowsAgent",  # Fallback; real triage would refuse
}

def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    subagent = OS_TO_SUBAGENT.get(state.get("_detected_os", "unknown"), "WindowsAgent")

    emit_message(state, from_agent="orchestrator", to_agent=subagent,
                 role="dispatch", content="triage: classify severity and confirm OS")

    # Fail-loud: when unknown OS routes through here, leave a loud audit
    # breadcrumb so accuracy-report can flag the fallback (#6). The actual
    # routing decision still goes through OS_TO_SUBAGENT's "unknown" entry
    # because suppressing the route would break the smoke-graph test path
    # and the existing fallback contract; the breadcrumb just makes it
    # visible instead of silent.
    if state.get("_detected_os", "unknown") == "unknown":
        record_audit(
            state, event="triage_unknown_os_routed_to_fallback",
            data={"fallback_subagent": subagent,
                  "note": "OS detection failed — fallback agent may produce wrong-OS findings"},
        )

    # Explicit-false-positive verdict tokens. ONLY these suppress the pipeline.
    # A bare "low" does NOT — the full investigation runs and findings speak.
    _FALSE_POSITIVE_TOKENS = {
        "false_positive", "false-positive", "falsepositive",
        "none", "no_incident", "no-incident", "benign",
    }

    if should_stub(NODE_NAME):
        # Deterministic stub for CI: medium severity, never a false positive.
        state["severity"] = "medium"
        state["_triage_false_positive"] = False
        emit_message(state, from_agent=subagent, to_agent="orchestrator",
                     role="response", content="[stub] severity=medium",
                     metadata={"exit_code": 0, "stub": True})
        record_audit(state, event="triage_complete_stub", data={"subagent": subagent, "severity": "medium"})
    else:
        result = invoke_subagent(
            subagent_name=subagent,
            prompt=(
                "Classify this alert. Reply with ONE word: low / medium / high / "
                "critical for a real incident, OR 'false_positive' ONLY if you can "
                "affirmatively confirm it is benign / no incident. When in doubt, "
                "pick a severity — do NOT reply false_positive unless you are sure, "
                "because that suppresses the entire investigation."
            ),
            headless=True,
        )
        if result.timed_out:
            state["severity"] = "unknown"
            state["_triage_false_positive"] = False  # fail-open: investigate
            emit_message(
                state, from_agent=subagent, to_agent="orchestrator",
                role="tool_failure",
                content=f"[timeout:{result.timeout_reason}] triage terminated",
                metadata={"timed_out": True, "reason": result.timeout_reason},
            )
            record_audit(
                state, event="triage_timeout",
                data={"subagent": subagent, "reason": result.timeout_reason},
            )
            csf_tags.mark_satisfied(state, csf_tags.RS_MA_03)
            picerl.advance_iso27035(state, picerl.picerl_phase_for("triage"))
            state["_node_history"].append("triage")
            write_checkpoint(state, out)
            append_history(state, out, node="triage")
            return state
        # Trust-contract fix (#3): when the subagent reply is empty or doesn't
        # parse to an allowed token, do NOT silently default to "medium" —
        # that synthesizes confidence we don't have. Record severity="unknown"
        # so downstream nodes can branch (or skip), and emit a `tool_failure`
        # message so the dissent trace in agent_messages.jsonl carries the
        # parse failure verbatim. Parse errors fail OPEN (investigate), never
        # to a false positive — only an explicit FP token suppresses.
        raw = (result.final_text or "").strip()
        sev_text = raw.lower()
        if sev_text in _FALSE_POSITIVE_TOKENS:
            state["severity"] = "low"
            state["_triage_false_positive"] = True
            severity_parsed = True
        elif sev_text in {"low", "medium", "high", "critical"}:
            state["severity"] = sev_text  # type: ignore[typeddict-item]
            state["_triage_false_positive"] = False
            severity_parsed = True
        else:
            state["severity"] = "unknown"
            state["_triage_false_positive"] = False
            severity_parsed = False
        emit_message(
            state, from_agent=subagent, to_agent="orchestrator",
            role="response" if severity_parsed else "tool_failure",
            content=result.final_text or "[no result]",
            metadata={
                "exit_code": result.exit_code,
                "severity_parsed": severity_parsed,
                "false_positive": state["_triage_false_positive"],
                "raw_reply": raw[:200],
            },
        )
        record_audit(
            state,
            event="triage_complete" if severity_parsed else "triage_parse_error",
            data={"subagent": subagent, "severity": state["severity"],
                  "false_positive": state["_triage_false_positive"],
                  "raw_reply": raw[:200], "exit_code": result.exit_code},
        )

    csf_tags.mark_satisfied(state, csf_tags.RS_MA_03)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("triage"))
    state["_node_history"].append("triage")
    write_checkpoint(state, out)
    append_history(state, out, node="triage")
    return state
