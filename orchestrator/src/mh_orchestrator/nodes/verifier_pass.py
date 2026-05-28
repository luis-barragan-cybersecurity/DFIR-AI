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
import re
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "verifier_pass"
SUBAGENT = "Verifier"

STUB_RATIONALE = "MH_NO_CLAUDE stub: skipped re-verification"

# Verdicts the Verifier persona is contracted to emit (verifier.md §Verdict Schema).
_VALID_VERDICTS = {"agree", "dissent", "tool_failure", "excerpt_mismatch"}
# Verdicts that must route as dissent — the finding is suspect whether the
# Verifier disagreed (`dissent`), couldn't re-run the tool (`tool_failure`),
# or saw different bytes (`excerpt_mismatch`). Only `agree` survives as
# verified. The raw verdict is preserved on the decision record so the
# operator can see WHY.
_DISSENT_LIKE = {"dissent", "tool_failure", "excerpt_mismatch"}

# Find a ```json ... ``` fenced block (preferred — explicit verdict marker).
_FENCED_JSON_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)


def _parse_verifier_verdict(raw: str) -> dict[str, Any] | None:
    """Extract the JSON verdict object from a Verifier reply.

    Strategy:
      1. Prefer the LAST ```json fenced block (the persona is instructed to
         emit the verdict as the final fenced block).
      2. Fall back to the LAST naked JSON object in the text.
      3. Accept only if the parsed object has a `verifier_decision` key
         set to one of the contract enum values.

    Returns None on any failure — caller falls back to the bare-word path
    to preserve the "no silent agree" trust contract.
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


def _stub_decision(finding: dict[str, Any], iter_num: int) -> dict[str, Any]:
    """Deterministic stub decision used under MH_NO_CLAUDE=1."""
    return {
        "finding_id": finding.get("finding_id", ""),
        "decision": "agree",
        "rationale": STUB_RATIONALE,
        "verifier_iter": iter_num,
    }


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    findings = state.get("_findings", []) or []

    # Defensive init for states deserialized from older snapshots.
    if "_verifier_decisions" not in state:
        state["_verifier_decisions"] = []

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
                "the cited tool against the same evidence. Reply with one of: "
                "agree | dissent | revise.\n\n"
                f"FINDING: {json.dumps(finding, sort_keys=True)}"
            )

            emit_message(
                state, from_agent="orchestrator", to_agent=SUBAGENT,
                role="dispatch",
                content=f"verifier_pass: re-verify finding {fid}",
                metadata={"finding_id": fid, "verifier_iter": idx},
            )

            if should_stub(NODE_NAME):
                decision = _stub_decision(finding, idx)
                record_audit(
                    state, event="verifier_pass_stub",
                    data={"subagent": SUBAGENT, "finding_id": fid,
                          "decision": decision["decision"], "iter": idx},
                )
            else:
                result = invoke_subagent(
                    subagent_name=SUBAGENT,
                    prompt=prompt,
                    headless=True,
                )
                if result.timed_out:
                    decision = {
                        "finding_id": fid,
                        "decision": "dissent",
                        "rationale": (
                            f"[timeout] re-verification of {fid} hit a "
                            f"{result.timeout_reason} timeout before completing; "
                            f"treated as dissent to preserve the trust contract."
                        ),
                        "verifier_iter": idx,
                        "parse_error": False,
                        "timed_out": True,
                    }
                    record_audit(
                        state, event="verifier_pass_timeout",
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "reason": result.timeout_reason, "iter": idx},
                    )
                    state["_verifier_decisions"].append(decision)
                    emit_message(
                        state, from_agent=SUBAGENT, to_agent="orchestrator",
                        role="tool_failure",
                        content=f"verifier decision: dissent for {fid} (timeout)",
                        metadata={"verifier_decision": "dissent", "finding_id": fid,
                                  "verifier_iter": idx, "timed_out": True,
                                  "rationale": decision["rationale"]},
                    )
                    continue
                # Trust-contract fix (#4 / B2): the Verifier persona is
                # instructed to emit a JSON verdict object (verifier.md
                # §Verdict Schema). Pre-B2 we only matched a bare-word reply
                # against {agree, dissent, revise} — so EVERY JSON reply
                # parse-failed and was conservatively dissented (the
                # a prior case: 0 verifier-agreed, 12 dissent, all
                # parse_error). B2 tries JSON first, falls back to the
                # bare-word path so the trust contract ("no silent agree")
                # still holds for malformed replies.
                raw = (result.final_text or "").strip()
                verdict_obj = _parse_verifier_verdict(raw)

                if verdict_obj is not None:
                    raw_decision = verdict_obj["verifier_decision"]
                    # Normalize for routing — tool_failure / excerpt_mismatch
                    # both mean "this finding is NOT verified", preserve raw
                    # for honesty.
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
                        "verifier_iter": idx,
                        "parse_error": False,
                    }
                    record_audit(
                        state, event="verifier_pass_complete",
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "decision": routing_decision,
                              "verifier_decision_raw": raw_decision,
                              "iter": idx, "exit_code": result.exit_code},
                    )
                else:
                    # Fallback: bare-word path (unchanged trust-contract).
                    # Preserves "no silent agree" for malformed replies.
                    verdict = raw.lower()
                    parse_error = False
                    if verdict not in {"agree", "dissent", "revise"}:
                        parse_error = True
                        verdict = "dissent"
                    rationale = raw if not parse_error else (
                        f"[parse_error] subagent reply did not match the "
                        f"Verifier verdict schema (no JSON object with "
                        f"verifier_decision) AND did not match the bare-word "
                        f"enum {{agree, dissent, revise}}; raw='{raw[:200]}'; "
                        f"treated as dissent to preserve trust contract"
                    )
                    decision = {
                        "finding_id": fid,
                        "decision": verdict,
                        "rationale": rationale,
                        "verifier_iter": idx,
                        "parse_error": parse_error,
                    }
                    record_audit(
                        state,
                        event="verifier_pass_parse_error" if parse_error else "verifier_pass_complete",
                        data={"subagent": SUBAGENT, "finding_id": fid,
                              "decision": verdict, "iter": idx,
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

    state["_verifier_complete"] = True
    state["phase"] = "analyze"
    csf_tags.mark_satisfied(state, csf_tags.RS_AN_03)
    picerl.advance_iso27035(state, picerl.picerl_phase_for(NODE_NAME))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="verifier_pass_summary",
        data={"findings": len(findings),
              "decisions": len(state["_verifier_decisions"]),
              "advisory_only": True},
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
