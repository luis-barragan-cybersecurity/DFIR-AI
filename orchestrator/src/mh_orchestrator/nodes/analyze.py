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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "analyze"
# RCA iteration cap. Was hardcoded at 3, which on large memory images
# (rocba-memory 17.7GB) routinely tripped before the subagent finished
# surveying all plugin outputs — left "analyze_iter_cap_reached" in the
# audit log and ~10 documented IOCs unsurfaced. Env-configurable so ops
# can scale with case size without code change.
import os as _os_mod  # noqa: E402
MAX_ITER = int(_os_mod.environ.get("MH_ANALYZE_MAX_ITER", "5"))

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


# Finding-id prefix the analyze node uses for its own confidence='unknown'
# timeout-disclosure stubs. Those describe the *absence* of work, not work
# done — so the prior-findings-summary in iter N+1 must exclude them or the
# subagent would believe iter N actually found something when iter N timed
# out before recording anything.
_TIMEOUT_GAP_PREFIX = "analyze-timeout-gap-"


def _build_analyze_prompt(state: IncidentState, case_dir: Path, iter_num: int) -> str:
    """Construct the analyze-iteration prompt sent to the OS specialist subagent.

    Pulled out of `run()` so it can be unit-tested directly. Composes five
    sections in order:

      1. Header — case id, OS, severity, iteration number.
      2. Evidence directory listing (top-level entries with sizes).
      3. Case-brief section (if `/input/_case-brief.md` present) — sets the
         threat model so the agent attributes activity to actor vs. victim
         correctly.
      4. Prior-findings section — when `iter_num > 1` and state carries real
         findings from earlier iterations (excluding analyze-timeout-gap-*
         stubs), summarize them so a fresh subagent process doesn't redo
         iter N-1's evidence enumeration. Subagents have NO memory between
         invocations — this is the only way iter 2/3 builds on iter 1.
      5. OS-specific mandatory tool sequence (memory_dump only).
      6. Generic analysis instruction + record-as-you-go discipline.

    The record-as-you-go directive in (6) is load-bearing for cases that
    hit the wallclock ceiling. An earlier run (6 hours, 0 real findings
    recorded) made the failure visible: the agent batched mentally and
    planned to record findings at the end of its sweep, but the 7200s
    ceiling fired first and the in-memory findings died with the
    subprocess. Recording immediately as each observation lands means
    partial findings reach disk even when the iteration is truncated.
    """
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

    # Prior-findings section (#2 — carry context across iteration boundaries).
    # Subagents are fresh subprocesses; without this they redo iter 1's
    # exploration on iter 2/3 (that run showed ~30% of each iteration spent
    # re-enumerating the same evidence). Exclude timeout-gap stubs — those
    # are confidence='unknown' disclosures of absence-of-work, not findings.
    prior_findings_section = ""
    if iter_num > 1:
        real_prior = [
            f for f in state.get("_findings", []) or []
            if not (f.get("finding_id", "") or "").startswith(_TIMEOUT_GAP_PREFIX)
        ]
        if real_prior:
            lines = ["=== PREVIOUSLY RECORDED FINDINGS (earlier iterations) ==="]
            for f in real_prior:
                fid = f.get("finding_id", "?")
                conf = f.get("confidence", "?")
                claim = (f.get("claim", "") or "").replace("\n", " ")[:240]
                lines.append(f"- [{fid}] (confidence={conf}) {claim}")
            lines.append("=== END PRIOR FINDINGS ===")
            lines.append("")
            lines.append(
                "Do not re-enumerate the evidence directory or re-discover artifacts "
                "already pinned above. Continue from gaps — investigate what those "
                "findings imply but did not yet record (cross-corroborating sources, "
                "related IOCs, persistence/network/lateral activity, anti-forensic "
                "erasure that may have hidden related events). Record each new "
                "observation via finding_record IMMEDIATELY as you make it."
            )
            lines.append("")
            prior_findings_section = "\n".join(lines)

    # ─── Hermes-style self-correction: inject prior-iteration verifier ──
    # ─── critiques as structured lessons the next pass must address by ──
    # ─── finding_id. Populated by verifier_pass on dissent re-route.    ──
    # ─── Empty on the first iteration (no prior verifier pass).         ──
    lessons = state.get("_dissent_lessons") or []
    lessons_section = ""
    if lessons:
        lesson_lines = []
        for L in lessons[:20]:  # cap lines for prompt-budget safety
            fid = L.get("finding_id", "?")
            verdict = L.get("verdict", "?")
            says = (L.get("verifier_says") or "")[:500]
            lesson_lines.append(
                f"- {fid} (verdict: {verdict}): {says}"
            )
        lessons_section = (
            "=== VERIFIER CRITIQUES FROM PRIOR ITERATION — YOU MUST ADDRESS ===\n"
            "A previous analyze pass produced findings. The independent "
            "Verifier subagent re-ran each finding's cited tool and "
            "disagreed on the items below. For each, EITHER:\n"
            "  (a) re-record the finding with the issue corrected (better pin, "
            "      clearer rationale, fixed confidence), or\n"
            "  (b) explicitly retract it by recording a new finding with "
            "      confidence='unknown' explaining why the prior claim couldn't "
            "      be substantiated.\n\n"
            "Do not silently re-emit the same claim — the Verifier will "
            "dissent again and we will burn another loop iteration.\n\n"
            "Critiques to address:\n"
            + "\n".join(lesson_lines) + "\n"
            "=== END VERIFIER CRITIQUES ===\n\n"
        )

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

    return (
        f"Case: {case_dir.name}\n"
        f"Detected OS: {detected_os}\n"
        f"Severity: {state.get('severity', 'unknown')}\n"
        f"Iteration: {iter_num}\n\n"
        f"Evidence files under {evidence_dir}/:\n{evidence_listing}\n\n"
        f"{case_brief_section}"
        f"{prior_findings_section}"
        f"{lessons_section}"
        f"{os_specific_directive}"
        "Analyze the evidence for root cause and IOCs. Use the per-OS "
        "MCP forensic tools available to you (e.g., mcp__protocol_sift__"
        "memory_volatility for memory dumps, mcp__protocol_sift__linux_"
        "history_parse for shell history, mcp__protocol_sift__win_* for "
        "Windows artifacts).\n\n"
        # NOTE: the Phase-1 "issue ONE tool call per turn, do NOT batch"
        # directive was deliberately REMOVED here. Its only error-prone
        # cascade trigger (Bash) is now subtracted at spawn via
        # providers.anthropic_cli.DISALLOWED_TOOLS, so the remaining toolset
        # (mcp__protocol_sift__*, Read, Glob, Grep) is reliable and
        # parallelizing it never cascades. Forbidding parallelism was pure
        # wall-time cost on the 7200s analyze ceiling; removing it restores
        # safe MCP/Read parallelism by subtraction. The record-as-you-go
        # "Recording discipline" below is a SEPARATE directive and stays — it
        # is the defense-in-depth that makes the residual MCP-parallel-cascade
        # risk acceptable. Re-add the tool-call directive only if a real
        # `Cancelled: parallel tool call mcp__protocol_sift__*` is observed.
        "**Recording discipline (READ — failure-mode prevention).** Call "
        "mcp__protocol_sift__finding_record IMMEDIATELY as each observation "
        "lands. Do NOT batch findings for an end-of-investigation reply. "
        "The analyze node enforces a wallclock ceiling per iteration; "
        "partial findings recorded before that ceiling are useful, findings "
        "held in working memory die with the subprocess when the ceiling "
        "fires. Each finding_record call must include: claim, confidence, "
        "confidence_rationale (one sentence in the form 'X because Y' "
        "justifying the chosen confidence), and >=1 pin. Tag MITRE ATT&CK "
        "techniques (T####) in the claim text where relevant.\n\n"
        "\n\n"
        "**Pin format — STRICT (Verifier re-runs your tools and compares "
        "byte-for-byte; sloppy pins → dissent → another loop iteration):**\n"
        "  • `artifact`: the evidence filename (e.g. `Rocba-Memory.raw`), "
        "    NOT a paraphrase or summary.\n"
        "  • `tool`: the exact MCP tool name that produced the row "
        "    (e.g. `windows.netscan`, `windows.pslist`).\n"
        "  • `locator`: a structured locator the Verifier can use to "
        "    re-fetch the same row — for Volatility plugins use "
        "    `{type: \"vol_row\", value: \"<plugin>:<row_key>\"}` where "
        "    row_key is PID, offset, or another unique field from the row.\n"
        "  • `raw_excerpt`: the FULL JSON row from the plugin output, "
        "    quoted VERBATIM (not a key=value summary). Example:\n"
        "      raw_excerpt: '{\"Created\":\"2020-11-16T02:36:14+00:00\","
        "\"ForeignAddr\":\"213.202.233.104\",\"ForeignPort\":13939,"
        "\"LocalAddr\":\"192.168.1.5\",\"LocalPort\":3389,\"PID\":1248,"
        "\"State\":\"ESTABLISHED\"}'\n"
        "  • `captured_at`: ISO-8601 timestamp of the row if the plugin "
        "    provides one, OR the time you ran the tool.\n\n"
        "**Do NOT reply DONE without first invoking the mandatory tool "
        "sequence above** — a reply of 'DONE' with zero finding_record "
        "calls is a doctrine violation. After the tool sequence completes, "
        "reply with one line summarizing: DONE (<N> findings recorded, "
        "<M> gaps acknowledged)."
    )


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

        # Use the team's extracted prompt-builder (see _build_analyze_prompt
        # below) so the case-brief / prior-findings / OS-directive composition
        # lives in one testable place. Hermes-style verifier-critique
        # injection (state["_dissent_lessons"]) and the strict pin-format
        # guidance were merged INTO _build_analyze_prompt during this merge.
        prompt = _build_analyze_prompt(state, case_dir, iter_num)
        result = invoke_subagent(
            subagent_name=subagent,
            prompt=prompt,
            headless=True,
        )
        if result.timed_out:
            # Graceful degradation: keep whatever the agent already recorded,
            # disclose the truncation as a confidence='unknown' gap finding,
            # and stop the RCA loop (a retry of a slow/hung call would just
            # time out again). The pipeline continues to session_finalize.
            findings_path = Path(state["_output_dir"]) / "findings.json"
            partial: list[dict] = []
            if findings_path.exists():
                try:
                    raw = json.loads(findings_path.read_text())
                    if isinstance(raw, list):
                        partial = raw
                    elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
                        partial = raw["findings"]
                except (json.JSONDecodeError, OSError):
                    partial = []
            _merge_findings(state, partial)

            gap = {
                "finding_id": f"analyze-timeout-gap-{iter_num}",
                "claim": (
                    f"Analysis truncated: the analyze node hit a "
                    f"{result.timeout_reason} timeout while dispatching {subagent} "
                    f"(iteration {iter_num}). Findings recorded before this point "
                    f"may be incomplete."
                ),
                "confidence": "unknown",
                "confidence_rationale": (
                    f"unknown because the specialist was terminated on a "
                    f"{result.timeout_reason} timeout before signalling completion, "
                    f"so analysis coverage cannot be asserted."
                ),
                "pins": [{
                    "artifact": "output/audit.jsonl",
                    "tool": "orchestrator",
                    "locator": {"type": "log_line", "value": "analyze_timeout"},
                    "raw_excerpt": f"analyze_timeout reason={result.timeout_reason} iter={iter_num}",
                    "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }],
                "mitre_attck": [],
                "related_findings": [],
            }
            _merge_findings(state, [gap])
            state["_analyze_timed_out"] = True
            emit_message(
                state, from_agent=subagent, to_agent="orchestrator",
                role="tool_failure",
                content=f"[timeout:{result.timeout_reason}] analyze iteration {iter_num} terminated",
                metadata={"timed_out": True, "reason": result.timeout_reason, "iter": iter_num},
            )
            record_audit(
                state, event="analyze_timeout",
                data={"subagent": subagent, "iter": iter_num,
                      "reason": result.timeout_reason,
                      "findings_count": len(state.get("_findings", []))},
            )
            break
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
