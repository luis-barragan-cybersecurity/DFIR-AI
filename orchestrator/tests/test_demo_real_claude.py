"""Real-Claude smoke test — opt-in via MH_RUN_REAL_CLAUDE=1.

Exercises the user-facing CLI path (`./bin/mh demo --real-claude`) end-to-end,
including flag parsing, env propagation, and the per-node opt-in
(`MH_NO_CLAUDE=1` + `MH_REAL_CLAUDE_NODES=triage`) introduced in T8.

Cost when opted in: ~1 short triage subagent call (~500-1500 tokens, ~$0.01).
Skipped by default so the regular suite stays free.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    os.environ.get("MH_RUN_REAL_CLAUDE") != "1",
    reason="real-Claude smoke is opt-in (set MH_RUN_REAL_CLAUDE=1)",
)


def test_demo_real_claude_invokes_triage() -> None:
    """`mh demo --real-claude` invokes a real triage subagent end-to-end.

    Asserts the output JSONL contains a non-stub per-OS agent response and a
    Verifier message (the verifier_pass node still runs, even if stubbed).
    Per-node opt-in keeps analyze + verifier_pass stubbed for cost control.
    """
    env = os.environ.copy()
    env["MH_DEMO_NONINTERACTIVE"] = "1"
    # bin/mh's _demo_real_claude sets MH_NO_CLAUDE=1 MH_REAL_CLAUDE_NODES=triage
    # inline before invoking cmd_orchestrate, so the autouse _no_claude fixture's
    # MH_NO_CLAUDE=1 in the parent env is fine — bin/mh re-asserts it.
    # ANTHROPIC_API_KEY (or ~/.claude) must be present in the parent environment.

    proc = subprocess.run(
        ["./bin/mh", "demo", "--real-claude"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"mh demo --real-claude exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )

    case_out = REPO_ROOT / "cases" / "_demo" / "output"
    assert case_out.exists(), f"expected {case_out} from real-Claude run"
    msgs_path = case_out / "agent_messages.jsonl"
    assert msgs_path.exists(), f"expected {msgs_path} to exist"

    msgs = [
        json.loads(line)
        for line in msgs_path.read_text().splitlines()
        if line.strip()
    ]
    assert msgs, "agent_messages.jsonl is empty"

    # At least one non-stub triage response from a per-OS agent.
    # Real triage entries have metadata={"exit_code":0}; stub entries have
    # metadata.stub=true. The discriminator is presence of metadata.stub.
    triage_real = [
        m
        for m in msgs
        if m.get("from_agent") in {"WindowsAgent", "MacOSAgent", "LinuxAgent"}
        and m.get("role") == "response"
        and not (m.get("metadata") or {}).get("stub")
        and (m.get("content") or "").strip()
    ]
    assert triage_real, (
        f"no real triage agent message found among {len(msgs)} entries; "
        f"agents seen: {sorted({m.get('from_agent') for m in msgs})}"
    )

    # Verifier pass ran (synthetic noop or per-finding — either is acceptable).
    verifier = [m for m in msgs if m.get("from_agent") == "Verifier"]
    assert verifier, "Verifier message missing — verifier_pass node didn't run"
