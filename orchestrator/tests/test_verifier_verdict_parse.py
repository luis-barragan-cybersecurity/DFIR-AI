"""Verifier JSON-verdict parsing (B2).

The Verifier persona (.claude/agents/verifier.md) is instructed to emit a
JSON verdict object:

  {
    "finding_id": "<id>",
    "verifier_decision": "agree | dissent | tool_failure | excerpt_mismatch",
    "verifier_confidence": "confirmed | inferred | uncertain | unknown",
    "pins_reverified": N,
    "pins_failed": N,
    "delta": "<short text>",
    "recommendation": "accept | revise | discard | escalate_human"
  }

Pre-B2, verifier_pass.run() compared `result.final_text` against the
bare-word enum {agree, dissent, revise} — so every JSON reply parse-failed
and every finding was conservatively dissented (0 verifier-agreed in the
a prior case). B2 makes the parser:

  1. Extract the JSON object from the reply (fenced ```json block or naked).
  2. Store the full verdict on state['_verifier_decisions'].
  3. Map verdict → routing decision:
       agree              → "agree"
       dissent            → "dissent"
       tool_failure       → "dissent"  (re-verification could not be performed)
       excerpt_mismatch   → "dissent"  (bytes differ → finding suspect)
     while preserving the raw verdict so the operator sees WHY.
  4. Fall back to the old bare-word path if JSON parse fails — preserves
     the trust-contract "no silent agree" behavior.
"""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.claude_node import SubagentResult
from mh_orchestrator.nodes import verifier_pass as vp
from mh_orchestrator.state import new_state


# ---------- _parse_verifier_verdict (pure function) ----------

def test_parse_verifier_verdict_extracts_fenced_block() -> None:
    reply = (
        "I re-ran win_evtx_query against Security.evtx and confirmed the EID.\n\n"
        "```json\n"
        '{"finding_id":"F-1","verifier_decision":"agree",'
        '"verifier_confidence":"confirmed","pins_reverified":1,"pins_failed":0,'
        '"delta":"","recommendation":"accept"}\n'
        "```\n"
    )
    v = vp._parse_verifier_verdict(reply)
    assert v is not None
    assert v["verifier_decision"] == "agree"
    assert v["verifier_confidence"] == "confirmed"
    assert v["pins_reverified"] == 1


def test_parse_verifier_verdict_extracts_naked_json() -> None:
    reply = (
        'Verdict:\n'
        '{"finding_id":"F-2","verifier_decision":"dissent",'
        '"verifier_confidence":"uncertain","pins_reverified":1,"pins_failed":1,'
        '"delta":"event_id mismatch: claim says 4624, observed 4625",'
        '"recommendation":"revise"}'
    )
    v = vp._parse_verifier_verdict(reply)
    assert v is not None
    assert v["verifier_decision"] == "dissent"
    assert "4625" in v["delta"]


def test_parse_verifier_verdict_returns_none_on_no_json() -> None:
    assert vp._parse_verifier_verdict("agree") is None
    assert vp._parse_verifier_verdict("") is None
    assert vp._parse_verifier_verdict("nothing structured here") is None


def test_parse_verifier_verdict_returns_none_when_decision_key_missing() -> None:
    """A JSON object without `verifier_decision` is not a verdict — fall back."""
    reply = '{"finding_id":"F-3","status":"ok"}'
    assert vp._parse_verifier_verdict(reply) is None


# ---------- verifier_pass.run with real-claude path, JSON verdicts ----------

def _patch_invoke(monkeypatch, replies: list[str]) -> None:
    """Replace invoke_subagent with a deterministic stub that returns the
    next reply from `replies` (one per finding, in order)."""
    it = iter(replies)

    def fake_invoke(**_kwargs) -> SubagentResult:
        return SubagentResult(
            exit_code=0,
            stdout="",
            stderr="",
            final_text=next(it),
        )

    monkeypatch.setenv("MH_NO_CLAUDE", "0")
    monkeypatch.setattr(vp, "invoke_subagent", fake_invoke)


def test_verifier_pass_agree_json_records_agree(tmp_path: Path, monkeypatch) -> None:
    _patch_invoke(monkeypatch, [
        json.dumps({
            "finding_id": "F-1", "verifier_decision": "agree",
            "verifier_confidence": "confirmed", "pins_reverified": 1,
            "pins_failed": 0, "delta": "", "recommendation": "accept",
        }),
    ])
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1", "claim": "x", "pins": []}]

    s = vp.run(s)
    d = s["_verifier_decisions"][0]
    assert d["decision"] == "agree"
    assert d["finding_id"] == "F-1"
    assert d.get("parse_error") is False
    assert d.get("verifier_confidence") == "confirmed"
    assert d.get("pins_reverified") == 1
    assert d.get("recommendation") == "accept"


def test_verifier_pass_dissent_json_records_dissent_with_delta(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_invoke(monkeypatch, [
        json.dumps({
            "finding_id": "F-1", "verifier_decision": "dissent",
            "verifier_confidence": "uncertain", "pins_reverified": 1,
            "pins_failed": 1, "delta": "claim says 4624, observed 4625",
            "recommendation": "revise",
        }),
    ])
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1", "claim": "x", "pins": []}]

    s = vp.run(s)
    d = s["_verifier_decisions"][0]
    assert d["decision"] == "dissent"
    assert d.get("parse_error") is False
    assert "4625" in d.get("delta", "")
    assert d.get("recommendation") == "revise"


def test_verifier_pass_tool_failure_normalized_to_dissent_preserves_raw(
    tmp_path: Path, monkeypatch,
) -> None:
    """tool_failure isn't a routing primitive — it must route as dissent,
    but the raw verdict 'tool_failure' must be preserved for honesty so
    the operator can see WHY the re-verification couldn't be done."""
    _patch_invoke(monkeypatch, [
        json.dumps({
            "finding_id": "F-1", "verifier_decision": "tool_failure",
            "verifier_confidence": "unknown", "pins_reverified": 0,
            "pins_failed": 1, "delta": "win_evtx_query raised IOError",
            "recommendation": "escalate_human",
        }),
    ])
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1", "claim": "x", "pins": []}]

    s = vp.run(s)
    d = s["_verifier_decisions"][0]
    assert d["decision"] == "dissent"
    assert d.get("verifier_decision_raw") == "tool_failure"
    assert d.get("parse_error") is False


def test_verifier_pass_excerpt_mismatch_normalized_to_dissent(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_invoke(monkeypatch, [
        json.dumps({
            "finding_id": "F-1", "verifier_decision": "excerpt_mismatch",
            "verifier_confidence": "inferred", "pins_reverified": 1,
            "pins_failed": 1, "delta": "bytes differ at offset 12",
            "recommendation": "discard",
        }),
    ])
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1", "claim": "x", "pins": []}]

    s = vp.run(s)
    d = s["_verifier_decisions"][0]
    assert d["decision"] == "dissent"
    assert d.get("verifier_decision_raw") == "excerpt_mismatch"


def test_verifier_pass_unparseable_reply_falls_back_to_parse_error_dissent(
    tmp_path: Path, monkeypatch,
) -> None:
    """Preserve the existing trust-contract behavior: when no JSON AND no
    bare-word match, conservatively dissent with parse_error=True."""
    _patch_invoke(monkeypatch, ["I don't know how to verify this."])
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1", "claim": "x", "pins": []}]

    s = vp.run(s)
    d = s["_verifier_decisions"][0]
    assert d["decision"] == "dissent"
    assert d.get("parse_error") is True


def test_verifier_pass_bare_word_still_works(tmp_path: Path, monkeypatch) -> None:
    """Backward-compat: a bare-word reply 'agree' (e.g., from a minimal
    verifier prompt) is still parsed correctly, no JSON required."""
    _patch_invoke(monkeypatch, ["agree"])
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [{"finding_id": "F-1", "claim": "x", "pins": []}]

    s = vp.run(s)
    d = s["_verifier_decisions"][0]
    assert d["decision"] == "agree"
    assert d.get("parse_error") is False
