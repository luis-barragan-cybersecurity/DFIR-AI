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
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..claude_node import invoke_subagent, should_stub
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "verifier_pass"
SUBAGENT = "Verifier"

STUB_RATIONALE = "MH_NO_CLAUDE stub: skipped re-verification"


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
                # Trust-contract fix (#4): NEVER silently default to "agree".
                # The previous code had two cascading defaults:
                #   verdict = (result.final_text or "agree").strip().lower()
                #   if verdict not in {agree,dissent,revise}: verdict = "agree"
                # An empty subagent reply or any unparseable token was therefore
                # interpreted as agreement — which defeats the whole point of
                # the Verifier (independent re-verification). The Verifier is
                # the centerpiece of the README's "Five Layers of No
                # Hallucinations" trust contract; silent-agree breaks it.
                #
                # New behavior: empty / unparseable verdicts become "dissent"
                # with a `parse_error: true` rationale. Dissent routes back to
                # analyze for one revision pass (route_after_verifier_pass —
                # capped by _verifier_revision_count, no infinite loop risk).
                raw = (result.final_text or "").strip()
                verdict = raw.lower()
                parse_error = False
                if verdict not in {"agree", "dissent", "revise"}:
                    parse_error = True
                    verdict = "dissent"
                rationale = raw if not parse_error else (
                    f"[parse_error] subagent reply did not match enum "
                    f"{{agree, dissent, revise}}; raw='{raw[:200]}'; "
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
