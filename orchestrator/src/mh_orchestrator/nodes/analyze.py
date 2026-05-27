"""analyze node — per-OS specialist dispatch with bounded RCA loop.

Routes to WindowsAgent / MacOSAgent / LinuxAgent based on state['_detected_os'],
collects findings, deduplicates by finding_id, and stops when:
  * subagent returns no new findings, OR
  * _analyze_iter >= MAX_ITER (cap), OR
  * MH_NO_CLAUDE=1 stub returned no findings (one-shot deterministic path)

Marks RS.AN-01 (Analysis: notifications + cause). Sets phase='analyze'.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "analyze"
MAX_ITER = 3

# Map _detected_os → subagent name (mirrors triage.OS_TO_SUBAGENT).
# memory_dump intentionally routes to WindowsAgent — the agent's prompt
# (.claude/agents/windows-agent.md) already has the "For memory dumps,
# additionally apply memory-forensics skill" clause and memory_volatility
# is in its tool allowlist. This explicit entry avoids the misleading
# 'analyze_unknown_os_fallback' audit event the prior fallback path emitted.
OS_TO_SUBAGENT: dict[str, str] = {
    "windows": "WindowsAgent",
    "macos": "MacOSAgent",
    "linux": "LinuxAgent",
    "memory_dump": "WindowsAgent",
}
FALLBACK_SUBAGENT = "WindowsAgent"


def _select_subagent(state: IncidentState) -> tuple[str, bool]:
    """Return (subagent_name, is_fallback)."""
    detected = state.get("_detected_os", "unknown")
    if detected in OS_TO_SUBAGENT:
        return OS_TO_SUBAGENT[detected], False
    return FALLBACK_SUBAGENT, True


def _merge_findings(state: IncidentState, new_findings: list[dict[str, Any]]) -> int:
    """Append new findings deduped by finding_id. Return count of newly added."""
    existing_ids = {f.get("finding_id") for f in state.get("_findings", [])}
    added = 0
    for f in new_findings:
        fid = f.get("finding_id")
        if fid and fid not in existing_ids:
            state["_findings"].append(f)
            existing_ids.add(fid)
            added += 1
    return added


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    case_dir = out.parent
    subagent, is_fallback = _select_subagent(state)

    if is_fallback:
        record_audit(
            state, event="analyze_unknown_os_fallback",
            data={"detected_os": state.get("_detected_os", "unknown"),
                  "fallback_subagent": subagent},
        )

    # Bounded RCA loop. Each pass increments _analyze_iter and dispatches to
    # the chosen subagent. Stop on: cap, no new findings, or empty stub.
    while state["_analyze_iter"] < MAX_ITER and not state["_rca_complete"]:
        state["_analyze_iter"] += 1
        iter_num = state["_analyze_iter"]

        emit_message(
            state, from_agent="orchestrator", to_agent=subagent,
            role="dispatch",
            content=f"analyze: root-cause iteration {iter_num}",
            metadata={"iter": iter_num, "phase": "analyze"},
        )

        if should_stub(NODE_NAME):
            # Deterministic stub: no new findings → RCA complete after one pass.
            emit_message(
                state, from_agent=subagent, to_agent="orchestrator",
                role="response", content="[stub] no findings returned",
                metadata={"exit_code": 0, "stub": True, "iter": iter_num},
            )
            record_audit(
                state, event="analyze_stub_pass",
                data={"subagent": subagent, "iter": iter_num, "added": 0},
            )
            state["_rca_complete"] = True
            break

        evidence_dir = case_dir / "input"
        evidence_listing = "\n".join(
            f"  - {p.name} ({p.stat().st_size} bytes)"
            for p in sorted(evidence_dir.iterdir()) if p.exists()
        ) if evidence_dir.exists() else "  (no evidence files found)"

        # Case-brief context: read /input/_case-brief.md if present and inject
        # its contents into the prompt. This is the only place the subagent
        # learns the threat model (victim of break-in vs. insider threat vs.
        # remote compromise). Without it, the agent defaults to "user account
        # = actor" framing, which is a categorical failure on victim cases.
        # See accuracy-report 2026-05-20 for the rocba miscategorization that
        # motivated this change.
        case_brief_path = evidence_dir / "_case-brief.md"
        case_brief_section = ""
        if case_brief_path.exists():
            try:
                brief_text = case_brief_path.read_text(encoding="utf-8", errors="replace")[:8000]
                case_brief_section = (
                    "=== CASE BRIEF (READ FIRST — sets threat model) ===\n"
                    f"{brief_text}\n"
                    "=== END CASE BRIEF ===\n\n"
                    "**Threat-model attribution rule:** if the case brief above describes "
                    "an external threat actor (break-in, intruder, stolen device, phishing, "
                    "compromised credentials, RAT, malware), the local user account is the "
                    "VICTIM, not the actor. Activity inside any named compromise window must "
                    "be attributed to the threat actor (not the user) — even when it runs "
                    "under the user's session. Outside the window, attribute to the user "
                    "normally. If the brief describes an insider-threat case, attribute "
                    "activity to the local user.\n\n"
                )
            except OSError:
                case_brief_section = ""

        # OS-specific mandatory tool sequence. For memory dumps the agent
        # previously replied 'DONE' after 1-2 min without invoking the
        # heavy-cost Volatility plugins; the explicit MUST list forces the
        # full memory-triage sweep.
        detected_os = state.get("_detected_os", "unknown")
        os_specific_directive = ""
        if detected_os == "memory_dump":
            os_specific_directive = (
                "**Memory-image triage — MANDATORY plugin sequence:**\n"
                "Call mcp__protocol_sift__memory_volatility for EACH of these plugins, in order, "
                "against the .raw / .mem / .dmp / .vmem image in the evidence dir:\n"
                "  1. windows.info               (validate the kernel; identify build)\n"
                "  2. windows.pslist             (process tree; identify high-value PIDs)\n"
                "  3. windows.psscan             (carved EPROCESS; surfaces hidden/exited)\n"
                "  4. windows.cmdline            (process command lines)\n"
                "  5. windows.netscan            (live network endpoints — slow; allow up to 30 min)\n"
                "  6. windows.malfind            (RWX injected memory regions)\n"
                "  7. windows.svcscan            (services)\n"
                "  8. windows.registry.userassist (per-user execution evidence)\n"
                "  9. windows.dumpfiles --pid <PID>  for cloud-sync / messaging / browser PIDs "
                "(see triage-orchestrator skill 'Handle-Dump Discipline' — recovers OneDrive "
                "downloads3.txt, AODL logs, Slack DBs, browser History from cached pages)\n\n"
                "For each plugin result, record findings via mcp__protocol_sift__finding_record "
                "with at least one pin to the specific plugin output. If a plugin times out, "
                "record a gap finding with confidence='unknown' explaining which plugin and why, "
                "then proceed to the next.\n\n"
            )

        prompt = (
            f"Case: {case_dir.name}\n"
            f"Detected OS: {detected_os}\n"
            f"Severity: {state.get('severity', 'unknown')}\n"
            f"Iteration: {iter_num}\n\n"
            f"Evidence files under {evidence_dir}/:\n{evidence_listing}\n\n"
            f"{case_brief_section}"
            f"{os_specific_directive}"
            "Analyze the evidence for root cause and IOCs. Use the per-OS "
            "MCP forensic tools available to you (e.g., mcp__protocol_sift__"
            "memory_volatility for memory dumps, mcp__protocol_sift__linux_"
            "history_parse for shell history, mcp__protocol_sift__win_* for "
            "Windows artifacts). Record EVERY "
            "finding via mcp__protocol_sift__finding_record with: claim, "
            "confidence, confidence_rationale (one sentence in the form "
            "'X because Y' justifying the chosen confidence), and >=1 pin. "
            "Tag MITRE ATT&CK techniques (T####) in the claim text where "
            "relevant. **Do NOT reply DONE without first invoking the "
            "mandatory tool sequence above** — a reply of 'DONE' with zero "
            "finding_record calls is a doctrine violation. After the tool "
            "sequence completes, reply with one line summarizing: DONE "
            "(<N> findings recorded, <M> gaps acknowledged)."
        )
        result = invoke_subagent(
            subagent_name=subagent,
            prompt=prompt,
            headless=True,
            timeout_sec=1200,
        )
        if result.exit_code != 0:
            record_audit(
                state, event="analyze_subagent_failed",
                data={"subagent": subagent, "iter": iter_num,
                      "exit_code": result.exit_code,
                      "stderr": (result.final_text or "")[:500]},
            )
            raise RuntimeError(
                f"analyze subagent {subagent!r} failed at iter {iter_num}: "
                f"exit_code={result.exit_code}"
            )
        # Findings are recorded out-of-band by the subagent via the
        # finding_record MCP tool, which writes to <output>/findings.json
        # (mcp-server/tools/finding.py). Re-read that file each iteration
        # to surface any new entries into state["_findings"].
        new_findings: list[dict] = []
        findings_path = Path(state["_output_dir"]) / "findings.json"
        if findings_path.exists():
            try:
                raw = json.loads(findings_path.read_text())
                if isinstance(raw, list):
                    new_findings = raw
                elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
                    new_findings = raw["findings"]
            except (json.JSONDecodeError, OSError):
                new_findings = []
        added = _merge_findings(state, new_findings)
        emit_message(
            state, from_agent=subagent, to_agent="orchestrator",
            role="response",
            content=result.final_text or "[no result]",
            metadata={"exit_code": result.exit_code, "iter": iter_num, "added": added},
        )
        record_audit(
            state, event="analyze_pass_complete",
            data={"subagent": subagent, "iter": iter_num,
                  "exit_code": result.exit_code, "added": added},
        )
        if added == 0:
            state["_rca_complete"] = True
            break

    # Honesty fix (#5): when the loop exits because _analyze_iter hit MAX_ITER
    # WITHOUT _rca_complete being set naturally, the RCA didn't actually
    # complete — we just ran out of iteration budget. Set _rca_capped=True so
    # session_finalize / lessons_learned / accuracy-report can surface the
    # gap instead of pretending RCA completed.
    if not state["_rca_complete"] and state["_analyze_iter"] >= MAX_ITER:
        state["_rca_capped"] = True
        record_audit(
            state, event="analyze_iter_cap_reached",
            data={"subagent": subagent, "max_iter": MAX_ITER,
                  "iters_actually_run": state["_analyze_iter"],
                  "note": "RCA halted at iteration cap; not naturally complete"},
        )

    state["phase"] = "analyze"
    csf_tags.mark_satisfied(state, csf_tags.RS_AN_01)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("analyze"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="analyze_complete",
        data={"subagent": subagent, "iters": state["_analyze_iter"],
              "rca_complete": state["_rca_complete"],
              "rca_capped": state.get("_rca_capped", False),
              "findings_count": len(state.get("_findings", []))},
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
