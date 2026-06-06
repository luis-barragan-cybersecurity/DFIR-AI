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
import re
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "verifier_pass"
SUBAGENT = "Verifier"

# Tools the Verifier subagent is allowed to invoke when independently
# re-running each finding's cited tool. Mirrors triage.ALLOWED_TOOLS plus
# read-only Windows artifact tools so the Verifier can validate any pin
# the analyze node produced.
ALLOWED_TOOLS = [
    "mcp__protocol_sift__hash",
    "mcp__protocol_sift__os_detect",
    "mcp__protocol_sift__magic_check",
    "mcp__protocol_sift__memory_volatility",
    "mcp__protocol_sift__win_registry_get",
    "mcp__protocol_sift__win_evtx_query",
    "mcp__protocol_sift__win_prefetch_parse",
    "mcp__protocol_sift__win_lnk_parse",
    "mcp__protocol_sift__mac_plist_get",
    "mcp__protocol_sift__linux_history_parse",
    "Read", "Glob", "Grep",
]

STUB_RATIONALE = "MH_NO_CLAUDE stub: skipped re-verification"

# Verdicts the Verifier persona is contracted to emit (verifier.md §Verdict Schema).
# Team added tool_failure + excerpt_mismatch alongside the original agree/dissent;
# the markdown-fallback path additionally recognises "revise" for backward
# compatibility with subagent personas that still emit prose-form verdicts.
_VALID_VERDICTS = {"agree", "dissent", "tool_failure", "excerpt_mismatch"}
_VALID_PROSE_VERDICTS = {"agree", "dissent", "revise"}
# Verdicts that must route as dissent — the finding is suspect whether the
# Verifier disagreed (`dissent`), couldn't re-run the tool (`tool_failure`),
# or saw different bytes (`excerpt_mismatch`). Only `agree` survives as
# verified. The raw verdict is preserved on the decision record so the
# operator can see WHY.
_DISSENT_LIKE = {"dissent", "tool_failure", "excerpt_mismatch", "revise"}

# Find a ```json ... ``` fenced block (preferred — explicit verdict marker).
_FENCED_JSON_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)

# Markdown noise we strip before searching for prose verdict tokens.
_MARKDOWN_NOISE = re.compile(r"[*_`#>]+")
# Verdict-extraction patterns for the prose-fallback path. Tried in order;
# first match wins.
_VERDICT_PATTERNS = (
    re.compile(r"verdict[:\s]+(agree|dissent|revise)", re.IGNORECASE),
    re.compile(r"final\s+verdict[:\s]+(agree|dissent|revise)", re.IGNORECASE),
    re.compile(r"\bdecision[:\s]+(agree|dissent|revise)", re.IGNORECASE),
    re.compile(r"^(agree|dissent|revise)\b", re.IGNORECASE | re.MULTILINE),
)


def _parse_verifier_verdict(raw: str) -> dict[str, Any] | None:
    """Extract the JSON verdict object from a Verifier reply.

    PRIMARY path — the verifier persona is instructed to emit a final
    ```json``` fenced block containing ``verifier_decision`` plus
    rationale/evidence. We return that whole object so the caller can
    surface every field on the audit trail.

    Strategy:
      1. Prefer the LAST ```json fenced block (the persona is instructed to
         emit the verdict as the final fenced block).
      2. Fall back to the LAST naked JSON object in the text.
      3. Accept only if the parsed object has a `verifier_decision` key
         set to one of the contract enum values.

    Returns None on any failure — caller falls back to `_extract_verdict`
    (markdown-tolerant prose) to preserve the "no silent agree" trust
    contract.
    """
    if not raw:
        return None

    candidates: list[str] = []
    fenced = _FENCED_JSON_RE.findall(raw)
    if fenced:
        candidates.append(fenced[-1])

    # Fallback: scan for naked JSON objects (largest balanced {...} blocks).
    # Cheap heuristic: find every '{' and try to json.loads progressively
    # to the matching '}'. Good enough for typical replies; we explicitly
    # don't try to outsmart the persona contract.
    for m in re.finditer(r"\{", raw):
        depth = 0
        for i in range(m.start(), len(raw)):
            c = raw[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(raw[m.start():i + 1])
                    break

    # Try newest-first (fenced wins over inline; inner-most picked up by
    # the scan above is acceptable too).
    for cand in reversed(candidates):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        verdict = obj.get("verifier_decision")
        if isinstance(verdict, str) and verdict in _VALID_VERDICTS:
            return obj
    return None


def _extract_verdict(raw: str) -> tuple[str, str]:
    """Markdown-tolerant prose verdict extractor — FALLBACK path used when
    `_parse_verifier_verdict` finds no JSON block.

    Returns (verdict, parse_confidence). verdict is one of:
      "agree" | "dissent" | "revise" | "unparseable".

    parse_confidence:
      "high"   — explicit "Verdict: X" pattern matched
      "medium" — bare verdict token found near the start
      "low"    — fallback word-boundary scan
      "none"   — no verdict signal at all

    Pre-fix the matcher was strict-equality against the lowercased reply,
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
        if re.search(rf"\b{token}\b", head):
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
                # Team's invoke_subagent no longer takes case_dir / mcp_config
                # / timeout_sec — it resolves project root internally and uses
                # MH_SUBAGENT_* env vars for the liveness monitor. Timeouts
                # return result.timed_out=True (never raise).
                result = invoke_subagent(
                    subagent_name=SUBAGENT,
                    prompt=prompt,
                    allowed_tools=ALLOWED_TOOLS,
                    headless=True,
                )

                if getattr(result, "timed_out", False):
                    decision = {
                        "finding_id": fid,
                        "decision": "dissent",
                        "rationale": (
                            f"[timeout] re-verification of {fid} hit a "
                            f"{getattr(result, 'timeout_reason', 'unknown')} timeout before completing; "
                            f"treated as dissent to preserve the trust contract."
                        ),
                        "verifier_iter": pass_iter,
                        "finding_idx_in_pass": idx,
                        "parse_error": False,
                        "timed_out": True,
                    }
                    record_audit(
                        state, event="verifier_pass_timeout",
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "reason": getattr(result, 'timeout_reason', 'unknown'),
                              "iter": idx},
                    )
                    state["_verifier_decisions"].append(decision)
                    emit_message(
                        state, from_agent=SUBAGENT, to_agent="orchestrator",
                        role="tool_failure",
                        content=f"verifier decision: dissent for {fid} (timeout)",
                        metadata={"verifier_decision": "dissent", "finding_id": fid,
                                  "verifier_iter": pass_iter, "timed_out": True,
                                  "rationale": decision["rationale"]},
                    )
                    continue

                # Trust-contract fix (#4 / B2): try the persona's CONTRACTED
                # JSON verdict block FIRST. If absent, fall back to the
                # markdown-tolerant prose extractor. NEITHER side falls back
                # to silent-agree — that defeats the whole point of the
                # Verifier. The rocba run showed both shapes appearing in
                # the wild (some subagents emit JSON cleanly, others wrap
                # the verdict in ## Verdict: **X**), so both paths must
                # work.
                raw = (result.final_text or "").strip()
                verdict_obj = _parse_verifier_verdict(raw)

                if verdict_obj is not None:
                    raw_decision = verdict_obj["verifier_decision"]
                    routing_decision = (
                        "agree" if raw_decision == "agree" else "dissent"
                    )
                    decision = {
                        "finding_id": fid,
                        "decision": routing_decision,
                        "verifier_decision_raw": raw_decision,
                        "verifier_confidence": verdict_obj.get("verifier_confidence"),
                        "pins_reverified": verdict_obj.get("pins_reverified"),
                        "pins_failed": verdict_obj.get("pins_failed"),
                        "delta": verdict_obj.get("delta", ""),
                        "recommendation": verdict_obj.get("recommendation"),
                        "rationale": verdict_obj.get("delta") or raw_decision,
                        "verifier_iter": pass_iter,
                        "finding_idx_in_pass": idx,
                        "parse_error": False,
                        "parse_confidence": "high",
                    }
                    record_audit(
                        state, event="verifier_pass_complete",
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "decision": routing_decision,
                              "verifier_decision_raw": raw_decision,
                              "iter": idx, "exit_code": result.exit_code},
                    )
                else:
                    # Markdown-tolerant prose fallback. Pre-fix this path
                    # turned every "## Verdict: **agree**" into a false
                    # dissent (12 of 20 on rocba). The extractor recognises
                    # markdown wrapping; only truly unparseable replies
                    # become routed as dissent.
                    verdict, parse_confidence = _extract_verdict(raw)
                    rationale = raw if verdict in {"agree", "dissent", "revise"} else (
                        f"[unparseable_verdict] no JSON verdict block AND no "
                        f"prose verdict signal found; raw='{raw[:200]}'; "
                        f"routed back to analyze"
                    )
                    routing_decision = (
                        "agree" if verdict == "agree" else "dissent"
                    )
                    decision = {
                        "finding_id": fid,
                        "decision": routing_decision,
                        "verifier_decision_raw": verdict,
                        "rationale": rationale,
                        "verifier_iter": pass_iter,
                        "finding_idx_in_pass": idx,
                        "parse_confidence": parse_confidence,
                        "parse_error": verdict == "unparseable",
                    }
                    record_audit(
                        state,
                        event=(
                            "verifier_pass_unparseable" if verdict == "unparseable"
                            else "verifier_pass_complete"
                        ),
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "decision": routing_decision,
                              "verifier_decision_raw": verdict,
                              "iter": idx,
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
