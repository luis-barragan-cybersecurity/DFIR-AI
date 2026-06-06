"""triage node — invokes per-OS specialist subagent for severity classification."""
from __future__ import annotations

import os
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

ALLOWED_TOOLS = [
    "mcp__protocol_sift__hash",
    "mcp__protocol_sift__os_detect",
    "mcp__protocol_sift__magic_check",
    # memory_volatility is the only forensic tool triage gets. The intent
    # is a SINGLE cheap-ish probe (e.g. windows.info to confirm the kernel
    # build + identify whether it's a server / workstation / DC) — not a
    # full memory sweep, which is analyze's job. Without this, triage on
    # a raw memory image has zero signal and reflexively grades "low",
    # which lets route_after_triage short-circuit the pipeline through
    # suppress and judges never see analyze/contain/eradicate run.
    "mcp__protocol_sift__memory_volatility",
    "mcp__protocol_sift__finding_record",
    "Read", "Glob", "Grep",
]



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
        # Build a case-brief-aware probe prompt. The base structure here is
        # mine: evidence listing + mandatory probe sequence so triage grounds
        # severity in real Volatility output instead of reflexively answering
        # "low" on empty input. Layered on top is the team's false_positive
        # contract (route_after_triage now suppresses on _triage_false_positive
        # not on severity) plus their tool-call discipline override.
        #
        # Team's invoke_subagent no longer takes case_dir / mcp_config / timeout
        # explicitly — it resolves project root internally and uses MH_SUBAGENT_*
        # env vars for the liveness monitor. We use the input dir off the state.
        evidence_dir = Path(state.get("_input_dir") or "") if state.get("_input_dir") else out.parent / "input"
        case_brief = ""
        brief_path = evidence_dir / "_case-brief.md"
        if brief_path.exists():
            try:
                case_brief = brief_path.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                case_brief = ""

        evidence_listing = ""
        if evidence_dir.exists():
            try:
                evidence_listing = "\n".join(
                    f"  - {p.name} ({p.stat().st_size:,} bytes)"
                    for p in sorted(evidence_dir.iterdir()) if p.is_file()
                )
            except OSError:
                evidence_listing = "  (could not enumerate evidence dir)"

        probe_directive = (
            "**Mandatory probe sequence (DO NOT skip — these tool calls "
            "ground your severity classification in real evidence):**\n"
            "1. Call mcp__protocol_sift__magic_check on each evidence file "
            "to confirm format.\n"
            "2. If a memory image (.raw / .mem / .dmp / .vmem) is present, "
            "call mcp__protocol_sift__memory_volatility ONCE with "
            "plugin='windows.info' against that image. This confirms the "
            "kernel build and tells you whether you're looking at a "
            "workstation, server, or domain controller — all of which "
            "shift the severity floor.\n"
            "3. THEN classify severity. The classification must reflect "
            "what the probe revealed PLUS the case brief context (if "
            "present). A confirmed incident in the brief with a real "
            "kernel build behind it is at minimum 'medium', not 'low'.\n"
        )
        brief_section = (
            "=== CASE BRIEF (READ FIRST — sets the threat model) ===\n"
            f"{case_brief}\n"
            "=== END CASE BRIEF ===\n\n"
            if case_brief else ""
        )
        prompt = (
            f"{brief_section}"
            "Evidence files in this case:\n"
            f"{evidence_listing}\n\n"
            f"{probe_directive}\n"
            "After the probe sequence completes, reply with ONE word: "
            "low | medium | high | critical for a real incident, OR "
            "'false_positive' ONLY if you can affirmatively confirm the "
            "evidence is benign / no incident. When in doubt, pick a "
            "severity — do NOT reply false_positive unless you are sure, "
            "because that suppresses the entire investigation."
            # NOTE: the Phase-1 "issue ONE tool call per turn, do NOT batch"
            # directive was deliberately REMOVED here. Its only error-prone
            # cascade trigger (Bash) is now subtracted at spawn via
            # providers.anthropic_cli.DISALLOWED_TOOLS, so the remaining toolset
            # (mcp__protocol_sift__*, Read, Glob, Grep) is reliable and
            # parallelizing it never cascades. Forbidding parallelism was
            # pure wall-time cost; removing it restores the harness default
            # (safe MCP/Read parallelism) by subtraction. Re-add only if a
            # real `Cancelled: parallel tool call mcp__protocol_sift__*`
            # event is ever observed.
        )
        result = invoke_subagent(
            subagent_name=subagent, prompt=prompt,
            allowed_tools=ALLOWED_TOOLS, headless=True,
        )

        # Timeout handling — team's invoke_subagent returns timed_out=True
        # (never raises) so the caller can degrade gracefully. Treat the
        # same as the prior subprocess.TimeoutExpired catch: severity=unknown,
        # _triage_false_positive=False (fail-open: investigate), continue.
        if getattr(result, "timed_out", False):
            state["severity"] = "unknown"
            state["_triage_false_positive"] = False
            emit_message(
                state, from_agent=subagent, to_agent="orchestrator",
                role="tool_failure",
                content=f"[timeout:{getattr(result, 'timeout_reason', 'unknown')}] triage terminated",
                metadata={"timed_out": True,
                          "reason": getattr(result, 'timeout_reason', 'unknown')},
            )
            record_audit(
                state, event="triage_timeout",
                data={"subagent": subagent,
                      "reason": getattr(result, 'timeout_reason', 'unknown')},
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
