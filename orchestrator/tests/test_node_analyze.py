"""analyze node tests — per-OS dispatch + bounded RCA loop."""
from __future__ import annotations

import json
from pathlib import Path

from mh_orchestrator.nodes import analyze
from mh_orchestrator.state import new_state


def test_analyze_under_no_claude_marks_rca_complete(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    s = analyze.run(s)
    # Under MH_NO_CLAUDE=1 (autouse), one shot through, no findings → rca_complete
    assert s["_rca_complete"] is True
    assert s["_analyze_iter"] >= 1
    assert s["phase"] == "analyze"
    assert "RS.AN-01" in s["csf_subcategories_satisfied"]
    assert "analyze" in s["_node_history"]


def test_analyze_per_os_dispatch_macos(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "macos"
    analyze.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    assert msgs_path.exists()
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    # Verify MacOSAgent was the dispatch target
    has_macos_dispatch = any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "MacOSAgent"
        for p in parsed
    )
    assert has_macos_dispatch


def test_analyze_per_os_dispatch_linux(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "linux"
    analyze.run(s)
    msgs_path = tmp_path / "agent_messages.jsonl"
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    has_linux_dispatch = any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "LinuxAgent"
        for p in parsed
    )
    assert has_linux_dispatch


def test_analyze_unknown_os_fallback(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    # Force unknown by clearing the field
    s["_detected_os"] = "unknown"
    # Should not crash, should emit audit warning + fallback to WindowsAgent
    s = analyze.run(s)
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    audit_lines = [json.loads(line) for line in audit_path.read_text().strip().splitlines()]
    has_warning = any(e["event"] == "analyze_unknown_os_fallback" for e in audit_lines)
    assert has_warning
    msgs_path = tmp_path / "agent_messages.jsonl"
    parsed = [json.loads(line) for line in msgs_path.read_text().strip().splitlines()]
    has_windows_fallback = any(
        p["from_agent"] == "orchestrator" and p["to_agent"] == "WindowsAgent"
        for p in parsed
    )
    assert has_windows_fallback


def test_analyze_writes_checkpoint(tmp_path: Path) -> None:
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    analyze.run(s)
    assert (tmp_path / "state.json").exists()
    assert (tmp_path / "state.history.jsonl").exists()


def test_memory_dump_explicit_route_not_fallback(tmp_path: Path) -> None:
    """Regression: memory_dump used to land via FALLBACK_SUBAGENT and emit
    a misleading 'analyze_unknown_os_fallback' audit event (rocba 2026-05-21
    run). memory_dump must now be an explicit route — same target subagent
    (WindowsAgent) but is_fallback=False so the audit reads cleanly."""
    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "memory_dump"
    s = analyze.run(s)

    audit_lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().strip().splitlines()]
    has_fallback_event = any(e["event"] == "analyze_unknown_os_fallback" for e in audit_lines)
    assert not has_fallback_event, (
        "memory_dump should be an explicit route in OS_TO_SUBAGENT, "
        "not the unknown-OS fallback path"
    )

    # And it should still dispatch to WindowsAgent (which has memory_volatility)
    msgs = [json.loads(line) for line in (tmp_path / "agent_messages.jsonl").read_text().strip().splitlines()]
    assert any(
        m["from_agent"] == "orchestrator" and m["to_agent"] == "WindowsAgent"
        for m in msgs
    )


def test_os_to_subagent_includes_memory_dump():
    assert analyze.OS_TO_SUBAGENT.get("memory_dump") == "WindowsAgent", (
        "memory_dump must route explicitly to WindowsAgent so the analyze prompt "
        "can include the mandatory Volatility plugin sequence"
    )


def test_analyze_timeout_appends_gap_finding_and_continues(tmp_path, monkeypatch):
    """When invoke_subagent reports a timeout, analyze keeps partial findings,
    appends a confidence='unknown' gap finding, sets _analyze_timed_out, breaks
    the RCA loop, and does NOT raise."""
    from mh_orchestrator.claude_node import SubagentResult
    from mh_orchestrator.nodes import analyze
    from mh_orchestrator.state import new_state

    # Run analyze in real (non-stub) mode but stub the subprocess layer.
    monkeypatch.setenv("MH_NO_CLAUDE", "0")

    def fake_invoke(**kwargs):
        return SubagentResult(
            exit_code=-15, stdout="", stderr="",
            timed_out=True, timeout_reason="idle",
        )

    monkeypatch.setattr(analyze, "invoke_subagent", fake_invoke)

    s = new_state("c")
    s["_output_dir"] = str(tmp_path)
    s["_detected_os"] = "windows"
    (tmp_path.parent / "input").mkdir(parents=True, exist_ok=True)

    s = analyze.run(s)

    assert s["_analyze_timed_out"] is True
    gap = [f for f in s["_findings"] if f.get("confidence") == "unknown"
           and "truncated" in f.get("claim", "").lower()]
    assert gap, "expected a confidence='unknown' truncation gap finding"
    assert gap[0]["pins"], "gap finding must carry at least one pin"
    # RCA loop did not spin to the cap on a timeout
    assert s["_analyze_iter"] == 1


# ─── Prompt-construction tests (#1 record-as-you-go + #2 carry prior findings) ───
#
# An earlier run (6 hours, 0 real findings) made the failure mode visible:
# the agent discovers IOCs (its trace mentions SAMPLE-A.EXE, SAMPLE-B.EXE,
# SAMPLE-C.EXE, etc.) but never reaches the finding_record call before the
# 7200s ceiling fires, so findings.json contains only orchestrator-synthesized
# timeout-gap stubs. Two prompt-level mitigations:
#
#   #1 record-as-you-go — tell the agent to call finding_record IMMEDIATELY
#      as each observation lands, not in a batch at the end. Partial findings
#      recorded before a timeout are useful; findings held in working memory
#      die with the subprocess.
#
#   #2 carry prior-iteration context forward — when iter > 1 and state has
#      non-gap findings from earlier iterations, summarize them in the prompt
#      so iter N+1 doesn't redo iter N's evidence enumeration.

from pathlib import Path as _Path  # avoid shadowing existing module-level Path


def _make_state_with_evidence_dir(tmp_path: _Path, **state_overrides):
    """Helper: build a state pointing at an output dir under a case dir with an input/ sibling."""
    case_dir = tmp_path / "case"
    (case_dir / "input").mkdir(parents=True)
    out_dir = case_dir / "output"
    out_dir.mkdir()
    s = new_state("c")
    s["_output_dir"] = str(out_dir)
    s["_detected_os"] = "windows"
    s["severity"] = "high"
    s.update(state_overrides)
    return s, case_dir


def test_build_analyze_prompt_iter1_has_record_immediately_directive(tmp_path):
    """#1: the prompt MUST tell the agent to record findings as it observes
    them, not batch at the end. The current 'After the tool sequence completes,
    reply with one line summarizing: DONE' framing reads as 'record at the end'
    and causes the 'zero findings recorded before timeout' pattern."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=1)
    lowered = prompt.lower()
    # The directive must explicitly call out *when* to record — not just *that* to record.
    assert "immediately" in lowered or "as you observe" in lowered or "as soon as" in lowered, (
        "prompt must include a record-as-you-go directive (look for "
        "'immediately' / 'as you observe' / 'as soon as')"
    )
    # And it must reference finding_record so the agent knows the mechanism.
    assert "finding_record" in prompt


def test_build_analyze_prompt_iter1_no_prior_findings_section(tmp_path):
    """First iteration: no prior findings, so no 'previously recorded' section.
    The agent should not see a stub section that says 'previously recorded:
    (nothing)' — that's noise."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    assert s["_findings"] == []  # sanity
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=1)
    lowered = prompt.lower()
    assert "previously recorded" not in lowered
    assert "prior findings" not in lowered


def test_build_analyze_prompt_iter2_includes_prior_real_findings(tmp_path):
    """#2: when state._findings has real findings from iter 1, iter 2's prompt
    MUST include a summary so the subagent (fresh process, no memory) doesn't
    re-do iter 1's evidence enumeration."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    s["_findings"] = [
        {
            "finding_id": "PRIOR-W-001-masquerade",
            "claim": "SAMPLE-A.EXE executed from non-system path — classic masquerading binary.",
            "confidence": "confirmed",
        },
        {
            "finding_id": "PRIOR-W-002-uacbypass",
            "claim": "SAMPLE-B.EXE invoked with custom registry shell association — UAC bypass.",
            "confidence": "inferred",
        },
    ]
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=2)
    assert "PRIOR-W-001-masquerade" in prompt
    assert "PRIOR-W-002-uacbypass" in prompt
    assert "SAMPLE-A.EXE" in prompt
    # And the prompt must direct the agent NOT to redo enumeration of the same ground.
    lowered = prompt.lower()
    assert (
        "do not re-enumerate" in lowered
        or "do not redo" in lowered
        or "continue from" in lowered
        or "pick up" in lowered
    ), "iter>1 prompt must direct agent to continue from prior findings"


def test_build_analyze_prompt_iter2_excludes_timeout_gap_stubs_from_prior_summary(tmp_path):
    """Timeout-gap stubs (finding_id starts with 'analyze-timeout-gap-') are
    orchestrator-synthesized confidence='unknown' disclosures; they describe
    the absence of work, not work done. They must NOT appear in the
    'previously recorded' section — that would tell the agent 'here's what
    iter 1 found' when in reality iter 1 found nothing."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    s["_findings"] = [
        {
            "finding_id": "PRIOR-W-001-real-finding",
            "claim": "Prefetch of SAMPLE-E.EXE shows three executions.",
            "confidence": "confirmed",
        },
        {
            "finding_id": "analyze-timeout-gap-1",
            "claim": "Analysis truncated: the analyze node hit a ceiling timeout while dispatching WindowsAgent (iteration 1). Findings recorded before this point may be incomplete.",
            "confidence": "unknown",
        },
    ]
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=2)
    assert "PRIOR-W-001-real-finding" in prompt
    assert "analyze-timeout-gap-1" not in prompt
    assert "truncated" not in prompt.lower() or prompt.lower().count("truncated") == 0


def test_build_analyze_prompt_includes_iter_num_and_case_id(tmp_path):
    """Sanity: existing content (iter number, case name, detected OS) still flows through."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=2)
    assert "Iteration: 2" in prompt
    assert case_dir.name in prompt
    assert "windows" in prompt.lower()


def test_build_analyze_prompt_omits_anti_parallel_directive(tmp_path):
    """The analyze prompt must NOT carry the Phase-1 'issue ONE tool call per
    turn / do NOT batch' anti-parallel directive. With Bash subtracted at
    spawn via providers.anthropic_cli.DISALLOWED_TOOLS the remaining toolset
    (mcp__protocol_sift__*, Read, Glob, Grep) is reliable and parallelizing
    it never trips the harness fail-fast cascade. Forbidding parallelism is
    pure wall-time cost on the 7200s analyze ceiling.

    The signature 'one tool call' is unique to the deleted directive; the
    unrelated 'do not batch findings' clause in the surviving Recording
    discipline targets findings, not tool calls, and is keyed separately
    below — so removing the anti-parallel directive cannot clobber it."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=1)
    lowered = prompt.lower()
    assert "one tool call" not in lowered, (
        "analyze prompt still carries the deleted anti-parallel directive — "
        "with Bash denied at spawn the directive is pure wall-time cost on "
        "the 7200s ceiling. Re-add only on a fresh cascade observation."
    )


def test_build_analyze_prompt_retains_recording_discipline(tmp_path):
    """Removing the anti-parallel directive must NOT clobber the unrelated
    record-as-you-go Recording discipline. The two were adjacent in source
    but solve different problems: anti-parallel is gone because Bash is
    denied at spawn; record-as-you-go stays because partial findings
    written before the ceiling fire are useful, findings held in working
    memory die with the subprocess. Pin its survival explicitly."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=1)
    lowered = prompt.lower()
    assert "recording discipline" in lowered, (
        "analyze prompt lost the surviving Recording discipline directive — "
        "anti-parallel removal must not delete the unrelated record-as-you-go "
        "guidance keyed on finding_record + the wallclock ceiling."
    )
    assert "do not batch findings" in lowered, (
        "Recording discipline must retain the 'do not batch findings' "
        "clause — finding-level batching is the real failure mode the "
        "directive prevents, separate from tool-call batching."
    )


def test_build_analyze_prompt_omits_anti_parallel_on_iter2(tmp_path):
    """The omission is unconditional — iter 2 carries prior findings and is
    more context-loaded, so re-introducing the directive there would be the
    sneakiest cost regression. Pin its absence on iter 2 too."""
    s, case_dir = _make_state_with_evidence_dir(tmp_path)
    s["_findings"] = [
        {
            "finding_id": "PRIOR-W-001-anchor",
            "claim": "Anchor finding from iter 1.",
            "confidence": "confirmed",
        },
    ]
    prompt = analyze._build_analyze_prompt(s, case_dir, iter_num=2)
    lowered = prompt.lower()
    assert "one tool call" not in lowered
    assert "recording discipline" in lowered
