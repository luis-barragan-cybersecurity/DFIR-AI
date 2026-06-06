"""verifier_pass node — global Verifier pass after analyze loop terminates.

Iterates state['_findings'] and dispatches each to the Verifier subagent for
re-verification. Records per-finding decisions on state['_verifier_decisions']
and emits agent messages so agent_messages.jsonl carries the dissent trace
required by IR_FRAMEWORKS_REFERENCE §11.4.

Under MH_NO_CLAUDE=1 (always true in CI/tests), produces deterministic stub
decisions ('agree' for every finding) without invoking the real subagent.

Marks RS.AN-03 (Categorization: requires verification). Sets phase='analyze'
because verifier is part of analysis per §11.2.

Advisory-only — no system changes.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "verifier_pass"
SUBAGENT = "Verifier"

ALLOWED_TOOLS = [
    "mcp__protocol_sift__hash",
    "mcp__protocol_sift__finding_record",
    "Read", "Glob", "Grep",
]

STUB_RATIONALE = "MH_NO_CLAUDE stub: skipped re-verification"

# Markdown noise we strip before searching for the verdict token. Real
# subagent replies use ## headers, ** bold, ` backticks, and inline code.
import re as _re  # noqa: E402 — late import keeps top-of-file clean
_MARKDOWN_NOISE = _re.compile(r"[*_`#>]+")
# Verdict-extraction patterns, tried in order. Returning the FIRST match.
# Order matters: explicit "Verdict: X" wins over a bare X anywhere in the
# reply, which wins over a fallback word-boundary scan.
_VERDICT_PATTERNS = (
    _re.compile(r"verdict[:\s]+(agree|dissent|revise)", _re.IGNORECASE),
    _re.compile(r"final\s+verdict[:\s]+(agree|dissent|revise)", _re.IGNORECASE),
    _re.compile(r"\bdecision[:\s]+(agree|dissent|revise)", _re.IGNORECASE),
    _re.compile(r"^(agree|dissent|revise)\b", _re.IGNORECASE | _re.MULTILINE),
)


def _extract_verdict(raw: str) -> tuple[str, str]:
    """Pull (verdict, parse_confidence) from a subagent reply.

    Returns one of ``"agree"`` / ``"dissent"`` / ``"revise"`` / ``"unparseable"``.
    parse_confidence is "high" when an explicit "Verdict: X" pattern matched,
    "medium" when a bare verdict token was found near the start, "low" on
    fallback word-boundary scan, or "none" when no verdict signal was found.

    The pre-fix matcher was strict-equality against the lowercased reply,
    so any markdown formatting ("## Verdict: **agree**") flipped to
    parse_error → dissent. On rocba this turned 12 real agrees into 12
    false dissents.
    """
    if not raw:
        return "unparseable", "none"
    cleaned = _MARKDOWN_NOISE.sub(" ", raw)
    for i, pat in enumerate(_VERDICT_PATTERNS):
        m = pat.search(cleaned)
        if m:
            return m.group(1).lower(), ("high" if i < 3 else "medium")
    # Fallback: first occurrence of any verdict word in the first 500 chars
    head = cleaned[:500].lower()
    for token in ("agree", "revise", "dissent"):
        if _re.search(rf"\b{token}\b", head):
            return token, "low"
    return "unparseable", "none"


def _stub_decision(finding: dict[str, Any], iter_num: int) -> dict[str, Any]:
    """Deterministic stub decision used under MH_NO_CLAUDE=1."""
    return {
        "finding_id": finding.get("finding_id", ""),
        "decision": "agree",
        "rationale": STUB_RATIONALE,
        "verifier_iter": iter_num,
        "parse_confidence": "stub",
    }


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    case_dir = out.parent
    findings = state.get("_findings", []) or []

    # Defensive init for states deserialized from older snapshots.
    if "_verifier_decisions" not in state:
        state["_verifier_decisions"] = []

    # Current pass index. revision_count is 0 on the first verifier pass,
    # 1 after one re-route through analyze, etc. We tag each per-finding
    # decision with this so convergence math can isolate THIS-iteration
    # decisions from prior-iteration history.
    pass_iter = state.get("_verifier_revision_count", 0)

    if not findings:
        record_audit(
            state, event="verifier_pass_no_findings",
            data={"subagent": SUBAGENT, "reason": "no findings to verify"},
        )
        emit_message(
            state, from_agent=SUBAGENT, to_agent="orchestrator",
            role="response",
            content="verifier_pass: no findings to verify",
            metadata={
                "verifier_decision": "noop",
                "finding_id": None,
                "verifier_iter": 0,
                "rationale": "no findings produced this run",
            },
        )
    else:
        for idx, finding in enumerate(findings, start=1):
            fid = finding.get("finding_id", "")
            prompt = (
                "Re-verify the following finding by independently re-running "
                "the cited tool against the same evidence.\n\n"
                "Your reply MUST contain a line in exactly this format on its "
                "own (anywhere in your response):\n"
                "    Verdict: agree\n"
                "  OR\n"
                "    Verdict: dissent\n"
                "  OR\n"
                "    Verdict: revise\n\n"
                "Definitions:\n"
                "  agree   — re-run reproduced the cited excerpt; finding stands.\n"
                "  dissent — re-run contradicted the finding; claim is wrong.\n"
                "  revise  — re-run partially confirmed but pin/rationale/scope "
                "needs correction.\n\n"
                "You may include analysis, tables, and reasoning above or below "
                "the Verdict line. The parser tolerates markdown formatting "
                "around the verdict word (e.g. 'Verdict: **agree**' is fine), "
                "but the line MUST start with 'Verdict:' (case-insensitive) "
                "followed by exactly one of the three tokens.\n\n"
                f"FINDING: {json.dumps(finding, sort_keys=True)}"
            )

            emit_message(
                state, from_agent="orchestrator", to_agent=SUBAGENT,
                role="dispatch",
                content=f"verifier_pass: re-verify finding {fid}",
                metadata={"finding_id": fid, "verifier_iter": idx},
            )

            if should_stub(NODE_NAME):
                decision = _stub_decision(finding, pass_iter)
                record_audit(
                    state, event="verifier_pass_stub",
                    data={"subagent": SUBAGENT, "finding_id": fid,
                          "decision": decision["decision"], "iter": idx},
                )
            else:
                try:
                    result = invoke_subagent(
                        subagent_name=SUBAGENT,
                        prompt=prompt,
                        case_dir=case_dir,
                        allowed_tools=ALLOWED_TOOLS,
                        mcp_config_path=None,
                        headless=True,
                        timeout_sec=int(os.environ.get("MH_VERIFIER_TIMEOUT_SEC", "600")),
                    )
                except subprocess.TimeoutExpired:
                    # Verifier hang on one finding must not crash the whole
                    # pipeline. Record a dissent (NOT silent agreement —
                    # see Trust-contract fix #4) and continue with the next.
                    decision = {
                        "finding_id": fid, "decision": "dissent",
                        "rationale": "[verifier subagent timeout]",
                        "verifier_iter": pass_iter,
                        "finding_idx_in_pass": idx,
                    }
                    state["_verifier_decisions"].append(decision)
                    emit_message(
                        state, from_agent=SUBAGENT, to_agent="orchestrator",
                        role="tool_failure", content="[verifier timeout]",
                        metadata={"finding_id": fid, "verifier_iter": idx,
                                  "error": "TimeoutExpired"},
                    )
                    record_audit(
                        state, event="verifier_pass_timeout",
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "decision": "dissent", "iter": idx,
                              "note": "subagent did not return — recorded as dissent, NOT silent agree"},
                    )
                    continue
                # Trust-contract fix (#4): NEVER silently default to "agree".
                # But ALSO never default to "dissent" on a parseable reply
                # just because it's markdown-formatted. Pre-fix the matcher
                # was strict-equality against {agree,dissent,revise} which
                # meant every "## Verdict: **agree**" reply got recorded as
                # parse_error → dissent. On rocba-memory that turned 12 real
                # agrees into 12 fake dissents, and the dashboard showed
                # "20/20 dissent" for what was actually a 60%-pass run.
                #
                # New behavior: extract verdict via `_extract_verdict` which
                # is markdown-tolerant. Only fall back to "unparseable" when
                # the reply truly carries no verdict signal — and that case
                # routes back to analyze (not silent-agree).
                raw = (result.final_text or "").strip()
                verdict, parse_confidence = _extract_verdict(raw)
                rationale = raw if verdict in {"agree", "dissent", "revise"} else (
                    f"[unparseable_verdict] no verdict token found in subagent "
                    f"reply; raw='{raw[:200]}'; routed back to analyze"
                )
                decision = {
                    "finding_id": fid,
                    "decision": verdict,
                    "rationale": rationale,
                    "verifier_iter": pass_iter,  # per-iteration, not per-finding
                    "finding_idx_in_pass": idx,  # keep loop counter for debug
                    "parse_confidence": parse_confidence,
                }
                record_audit(
                    state,
                    event=(
                        "verifier_pass_unparseable" if verdict == "unparseable"
                        else "verifier_pass_complete"
                    ),
                    data={"subagent": SUBAGENT, "finding_id": fid,
                          "decision": verdict, "iter": idx,
                          "parse_confidence": parse_confidence,
                          "exit_code": result.exit_code,
                          "raw_reply": raw[:200]},
                )

            state["_verifier_decisions"].append(decision)

            emit_message(
                state, from_agent=SUBAGENT, to_agent="orchestrator",
                role="response",
                content=f"verifier decision: {decision['decision']} for {fid}",
                metadata={
                    "verifier_decision": decision["decision"],
                    "finding_id": fid,
                    "verifier_iter": idx,
                    "rationale": decision["rationale"],
                },
            )

    # ─── Convergence / loop-control decision ───────────────────────────
    #
    # Pre-fix this unconditionally set `_verifier_complete = True`, which
    # made route_after_verifier_pass effectively dead code — the dissent
    # re-route never fired. Now we compute the loop state explicitly:
    #
    #   complete = True  → route to correlate (no more learning iterations)
    #   complete = False → route back to analyze with structured lessons
    #                      so the next pass can address each non-agree
    #                      decision by finding_id.
    #
    # `MH_VERIFIER_MAX_REVISIONS` (default 3) caps the loop so it can't
    # run forever even on adversarial cases.
    max_revisions = int(os.environ.get("MH_VERIFIER_MAX_REVISIONS", "3"))
    # Only count THIS iteration's decisions, not cumulative across passes.
    this_iter_decisions = [
        d for d in state["_verifier_decisions"]
        if d.get("verifier_iter", 0) == pass_iter
    ]
    non_agree = [
        d for d in this_iter_decisions
        if d.get("decision") in {"dissent", "revise", "unparseable"}
    ]
    converged = len(non_agree) == 0
    cap_reached = pass_iter >= max_revisions

    if converged or cap_reached:
        state["_verifier_complete"] = True
        state["_dissent_lessons"] = []  # clear — no further iterations
    else:
        state["_verifier_complete"] = False
        state["_verifier_revision_count"] = pass_iter + 1
        # Build structured lessons for analyze to address next iteration.
        # Each lesson carries the finding id, the verdict, and what the
        # verifier said — fed into analyze.py's prompt builder so the
        # next pass can address the critique by finding.
        state["_dissent_lessons"] = [
            {
                "finding_id": d.get("finding_id"),
                "verdict": d.get("decision"),
                "verifier_says": (d.get("rationale") or "")[:1500],
                "iter": pass_iter,
            }
            for d in non_agree
        ]

    # NOTE: do NOT set state["phase"] here. The dissent re-route path
    # (route_after_verifier_pass → "analyze") will trigger analyze.run,
    # which sets phase="analyze" on entry. The non-routing path proceeds
    # through correlate → session_finalize, which sets phase="lessons".
    csf_tags.mark_satisfied(state, csf_tags.RS_AN_03)
    picerl.advance_iso27035(state, picerl.picerl_phase_for(NODE_NAME))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="verifier_pass_summary",
        data={"findings": len(findings),
              "decisions": len(state["_verifier_decisions"]),
              "this_iter_non_agree": len(non_agree),
              "verifier_revision_count": state.get("_verifier_revision_count", 0),
              "max_revisions": max_revisions,
              "converged": converged,
              "cap_reached": cap_reached,
              "next": "correlate" if state["_verifier_complete"] else "analyze",
              "advisory_only": True},
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
