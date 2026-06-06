"""Self-learning loop invariants — guards the Hermes-style critique-revise
feedback loop between verifier_pass and analyze.

The loop's contract:

  1. Verifier extracts verdicts leniently — markdown-wrapped 'Verdict: X'
     and bare verdict words both parse. ONLY genuinely unparseable replies
     become 'unparseable' (not silent-agree, not silent-dissent).
  2. `_verifier_complete = True` ONLY when every finding is 'agree' OR
     the revision cap is reached.
  3. Each non-agree decision becomes a structured lesson in
     `state["_dissent_lessons"]` that analyze.run reads on the next
     iteration.
  4. The loop is hard-capped by MH_VERIFIER_MAX_REVISIONS so it can't
     run forever even with adversarial dissent.
  5. session_finalize emits learning_trace.md with per-iteration deltas.

Each test pins one of these.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mh_orchestrator.nodes import verifier_pass
from mh_orchestrator.state import new_state


# ──────────────────────────────────────────────────────────────────────────
# Lenient verdict parser
# ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    ("agree", "agree"),
    ("AGREE", "agree"),
    ("  agree  ", "agree"),
    ("## Verdict: agree", "agree"),
    ("## Verdict: **agree**", "agree"),
    ("Verdict: dissent", "dissent"),
    ("Final verdict: revise", "revise"),
    ("Long preamble.\n\nVerdict: agree\n\nMore text after.", "agree"),
    ("Decision: dissent (re-run did not reproduce)", "dissent"),
    ("`revise`", "revise"),
    # Pre-fix these all became "dissent" via strict-equality.
    ("## Verdict: **AGREE**\n\nFull analysis below…", "agree"),
    ("**Verdict: agree** ✓", "agree"),
])
def test_extract_verdict_handles_markdown_formatting(raw: str, expected: str) -> None:
    """The pre-fix matcher returned 'dissent' for any markdown-wrapped
    reply. Pin the markdown-tolerant behavior."""
    verdict, _conf = verifier_pass._extract_verdict(raw)
    assert verdict == expected, f"raw={raw!r} → got {verdict!r}, want {expected!r}"


def test_extract_verdict_empty_reply_returns_unparseable() -> None:
    """Empty reply must NOT become silent-agree. Per Trust-contract fix #4."""
    verdict, conf = verifier_pass._extract_verdict("")
    assert verdict == "unparseable"
    assert conf == "none"


def test_extract_verdict_no_signal_returns_unparseable() -> None:
    """Reply with no verdict word must NOT default to either side."""
    verdict, _ = verifier_pass._extract_verdict(
        "I considered the finding but cannot reach a conclusion at this time."
    )
    assert verdict == "unparseable"


def test_extract_verdict_explicit_pattern_has_higher_confidence() -> None:
    """'Verdict: X' parses with 'high' confidence; bare word at start
    is 'medium'; fallback scan is 'low'."""
    _, high = verifier_pass._extract_verdict("Verdict: agree")
    _, med = verifier_pass._extract_verdict("agree — the re-run reproduced...")
    _, low = verifier_pass._extract_verdict(
        "After much deliberation and re-running the cited tool several times, "
        "I find myself in the position to agree with the original claim."
    )
    assert high == "high"
    # the second matches the "^(agree|dissent|revise)\b" MULTILINE start
    assert med in {"high", "medium"}
    assert low in {"low", "medium"}


# ──────────────────────────────────────────────────────────────────────────
# Convergence — _verifier_complete reflects loop state
# ──────────────────────────────────────────────────────────────────────────


def _state_with_findings(tmp_path: Path, n: int = 3):
    s = new_state("loop-test")
    s["_output_dir"] = str(tmp_path)
    s["_findings"] = [
        {"finding_id": f"F-{i:03d}", "claim": f"finding {i}",
         "confidence": "high", "pins": [{"artifact": "a", "tool": "b",
         "locator": {"type": "x", "value": "y"}, "raw_excerpt": "z",
         "captured_at": "2026-04-25T22:00:00Z"}]}
        for i in range(1, n + 1)
    ]
    return s


def test_verifier_complete_only_when_all_agree(tmp_path: Path, monkeypatch) -> None:
    """Stub mode emits 'agree' for every finding → verifier_complete True
    on first pass."""
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    s = _state_with_findings(tmp_path)
    out = verifier_pass.run(s)
    assert out["_verifier_complete"] is True
    assert out["_dissent_lessons"] == []


def test_verifier_complete_false_when_dissent_present_under_cap(tmp_path: Path,
                                                                monkeypatch) -> None:
    """Simulate a dissent: complete should be False and lessons populated."""
    monkeypatch.setenv("MH_NO_CLAUDE", "0")
    monkeypatch.setenv("MH_VERIFIER_MAX_REVISIONS", "3")
    s = _state_with_findings(tmp_path, n=2)
    # Mock invoke_subagent to return one 'agree' and one 'Verdict: dissent'
    replies = iter([
        MagicMock(final_text="Verdict: agree", exit_code=0),
        MagicMock(final_text="## Verdict: **dissent**\n\nRe-run differed.",
                  exit_code=0),
    ])
    with patch("mh_orchestrator.nodes.verifier_pass.invoke_subagent",
               side_effect=lambda **kw: next(replies)):
        out = verifier_pass.run(s)
    assert out["_verifier_complete"] is False
    assert out["_verifier_revision_count"] == 1
    assert len(out["_dissent_lessons"]) == 1
    assert out["_dissent_lessons"][0]["verdict"] == "dissent"
    assert out["_dissent_lessons"][0]["finding_id"] == "F-002"


def test_verifier_complete_true_when_cap_reached(tmp_path: Path,
                                                  monkeypatch) -> None:
    """When _verifier_revision_count is already at the cap and dissent
    persists, complete is True (loop terminated by cap, not convergence)."""
    monkeypatch.setenv("MH_NO_CLAUDE", "0")
    monkeypatch.setenv("MH_VERIFIER_MAX_REVISIONS", "2")
    s = _state_with_findings(tmp_path, n=1)
    s["_verifier_revision_count"] = 2  # AT the cap
    with patch("mh_orchestrator.nodes.verifier_pass.invoke_subagent",
               return_value=MagicMock(final_text="Verdict: dissent",
                                       exit_code=0)):
        out = verifier_pass.run(s)
    assert out["_verifier_complete"] is True
    assert out["_dissent_lessons"] == []


# ──────────────────────────────────────────────────────────────────────────
# Lessons feed forward into analyze
# ──────────────────────────────────────────────────────────────────────────


def test_analyze_prompt_includes_dissent_lessons_when_present(tmp_path: Path,
                                                              monkeypatch) -> None:
    """When state['_dissent_lessons'] is populated, analyze.run must
    include a VERIFIER CRITIQUES section in the subagent prompt."""
    monkeypatch.setenv("MH_NO_CLAUDE", "0")
    from mh_orchestrator.nodes import analyze
    (tmp_path / "input").mkdir()
    s = new_state("crit-test")
    s["_output_dir"] = str(tmp_path / "output")
    s["_input_dir"] = str(tmp_path / "input")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    s["_detected_os"] = "windows"
    s["_dissent_lessons"] = [
        {"finding_id": "F-007", "verdict": "dissent",
         "verifier_says": "Re-running windows.netscan did not reproduce the "
                          "claimed connection to 1.2.3.4. The pin is stale.",
         "iter": 1},
    ]
    captured: dict[str, str] = {}
    def _capture(*, prompt: str, **_):
        captured["prompt"] = prompt
        return MagicMock(final_text="DONE (0, 0)", exit_code=0)
    with patch("mh_orchestrator.nodes.analyze.invoke_subagent",
               side_effect=_capture):
        analyze.run(s)
    assert "VERIFIER CRITIQUES" in captured["prompt"]
    assert "F-007" in captured["prompt"]
    assert "Re-running windows.netscan" in captured["prompt"]


def test_analyze_prompt_omits_critiques_on_first_iteration(tmp_path: Path,
                                                            monkeypatch) -> None:
    """On the first analyze pass _dissent_lessons is empty → no critique
    section. Prevents the prompt from carrying a stale 'address these'
    block when there's nothing to address."""
    monkeypatch.setenv("MH_NO_CLAUDE", "0")
    from mh_orchestrator.nodes import analyze
    (tmp_path / "input").mkdir()
    s = new_state("no-crit")
    s["_output_dir"] = str(tmp_path / "output")
    s["_input_dir"] = str(tmp_path / "input")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    s["_detected_os"] = "windows"
    s["_dissent_lessons"] = []
    captured: dict[str, str] = {}
    with patch("mh_orchestrator.nodes.analyze.invoke_subagent",
               side_effect=lambda **kw: (captured.__setitem__("prompt", kw["prompt"]),
                                          MagicMock(final_text="DONE (0, 0)",
                                                    exit_code=0))[1]):
        analyze.run(s)
    assert "VERIFIER CRITIQUES" not in captured["prompt"]


# ──────────────────────────────────────────────────────────────────────────
# session_finalize emits learning_trace.md
# ──────────────────────────────────────────────────────────────────────────


def test_learning_trace_md_emitted_with_per_iteration_counts(tmp_path: Path) -> None:
    from mh_orchestrator.nodes import session_finalize
    s = new_state("trace-test")
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    s["_verifier_revision_count"] = 1
    s["_verifier_complete"] = True
    s["_verifier_decisions"] = [
        # iter 0
        {"finding_id": "F-1", "decision": "agree", "verifier_iter": 0,
         "parse_confidence": "high"},
        {"finding_id": "F-2", "decision": "dissent", "verifier_iter": 0,
         "parse_confidence": "high"},
        # iter 1 (after one re-route)
        {"finding_id": "F-1", "decision": "agree", "verifier_iter": 1,
         "parse_confidence": "high"},
        {"finding_id": "F-2", "decision": "agree", "verifier_iter": 1,
         "parse_confidence": "medium"},
    ]
    session_finalize.run(s)
    trace_file = tmp_path / "output" / "learning_trace.md"
    assert trace_file.exists()
    md = trace_file.read_text()
    assert "Self-Learning Trace" in md
    assert "Per-iteration verdict mix" in md
    assert "Convergence deltas" in md
    # Iter 0: 1 agree / 1 dissent → 50% non-agree
    assert "50%" in md
    # Iter 1: 2 agree → 0% non-agree
    assert "0%" in md
    # Delta line shows improvement
    assert "non-agree 1" in md and "0" in md


def test_learning_trace_md_handles_no_decisions(tmp_path: Path) -> None:
    from mh_orchestrator.nodes import session_finalize
    s = new_state("no-trace")
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    session_finalize.run(s)
    trace_file = tmp_path / "output" / "learning_trace.md"
    assert trace_file.exists()
    assert "No verifier decisions recorded" in trace_file.read_text()
