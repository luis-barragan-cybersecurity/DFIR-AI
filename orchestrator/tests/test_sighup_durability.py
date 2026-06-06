"""Tests for the SIGHUP-resistance of mh-orchestrate.

The rocba-memory run (2026-06-06) lost the F-017 verifier verdict ($1.08
of completed forensic work) when the parent terminal closed mid-run. The
Verifier subprocess returned cleanly, but the parent Python received
SIGHUP and died before recording the verdict to disk.

Two layers of protection now exist:

  1. `cli._make_orchestrator_durable` installs `SIG_IGN` handlers for
     SIGHUP + SIGPIPE so terminal close / SSH disconnect / laptop sleep
     don't kill the long-running orchestrator.
  2. `verifier_pass.run` checkpoints state to disk after EVERY decision,
     not just at end-of-loop. Even if something does kill the process,
     a kill loses ≤1 finding, not the whole verifier pass.

These tests pin each protection.
"""
from __future__ import annotations

import json
import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mh_orchestrator.cli import _make_orchestrator_durable


def test_make_orchestrator_durable_ignores_sighup() -> None:
    """SIGHUP must be ignored after the durability call."""
    # Snapshot prior so we don't pollute other tests.
    prior = signal.getsignal(signal.SIGHUP)
    try:
        _make_orchestrator_durable()
        assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, prior)


def test_make_orchestrator_durable_ignores_sigpipe() -> None:
    """SIGPIPE must be ignored — writing to a closed terminal-pipe
    should raise EPIPE we can absorb, not terminate the process."""
    prior = signal.getsignal(signal.SIGPIPE)
    try:
        _make_orchestrator_durable()
        assert signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGPIPE, prior)


def test_make_orchestrator_durable_preserves_sigint() -> None:
    """Operator MUST still be able to Ctrl+C. The fix only kills the
    silent-terminal-close path, not explicit cancellation."""
    prior = signal.getsignal(signal.SIGINT)
    try:
        _make_orchestrator_durable()
        # Default for SIGINT is Python's KeyboardInterrupt-raising handler.
        # We DON'T want SIG_IGN here.
        assert signal.getsignal(signal.SIGINT) != signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, prior)


def test_make_orchestrator_durable_preserves_sigterm() -> None:
    """Operator MUST still be able to `kill <pid>` if needed."""
    prior = signal.getsignal(signal.SIGTERM)
    try:
        _make_orchestrator_durable()
        assert signal.getsignal(signal.SIGTERM) != signal.SIG_IGN
    finally:
        signal.signal(signal.SIGTERM, prior)


def test_make_orchestrator_durable_idempotent() -> None:
    """Calling it twice must be a no-op, not raise."""
    prior_hup = signal.getsignal(signal.SIGHUP)
    try:
        _make_orchestrator_durable()
        _make_orchestrator_durable()
        assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, prior_hup)


# ──────────────────────────────────────────────────────────────────────────
# Per-decision checkpoint — kill loses ≤1 finding, never the loop
# ──────────────────────────────────────────────────────────────────────────


def test_verifier_pass_checkpoints_after_each_decision(tmp_path, monkeypatch) -> None:
    """Pre-fix verifier_pass only wrote state.json at end-of-loop. A SIGHUP
    between findings (rocba 2026-06-06) lost the whole _verifier_decisions
    list. Now every decision triggers a checkpoint write — verified by
    counting state.json writes per decision."""
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    from mh_orchestrator.nodes import verifier_pass
    from mh_orchestrator.state import new_state

    out_dir = tmp_path / "output"
    out_dir.mkdir()
    s = new_state("checkpoint-test")
    s["_output_dir"] = str(out_dir)
    s["_findings"] = [
        {"finding_id": f"F-{i:03d}", "claim": f"finding {i}",
         "confidence": "high",
         "pins": [{"artifact": "a", "tool": "b",
                   "locator": {"type": "x", "value": "y"},
                   "raw_excerpt": "z", "captured_at": "2026-04-25T22:00:00Z"}]}
        for i in range(1, 4)  # 3 findings
    ]

    # Count write_checkpoint calls — must be at least 1 per decision +
    # 1 at end-of-run. Pre-fix this would only be 1 (end-of-run).
    write_count = 0
    original_write = verifier_pass.write_checkpoint
    def counting_write(*a, **kw):
        nonlocal write_count
        write_count += 1
        return original_write(*a, **kw)
    monkeypatch.setattr(verifier_pass, "write_checkpoint", counting_write)

    verifier_pass.run(s)

    # 3 mid-loop + 1 end-of-loop = at least 4
    assert write_count >= 4, (
        f"checkpoint was written {write_count} times for 3 findings; "
        f"expected >=4 (one per decision + one at end-of-loop)"
    )


def test_verifier_pass_survives_checkpoint_ioerror(tmp_path, monkeypatch) -> None:
    """If checkpoint IO fails mid-loop (full disk, permission denied),
    the loop must continue rather than crash — losing per-decision
    durability is better than losing the in-flight verification."""
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
    from mh_orchestrator.nodes import verifier_pass
    from mh_orchestrator.state import new_state

    out_dir = tmp_path / "output"
    out_dir.mkdir()
    s = new_state("checkpoint-fail-test")
    s["_output_dir"] = str(out_dir)
    s["_findings"] = [
        {"finding_id": "F-001", "claim": "x", "confidence": "high",
         "pins": [{"artifact": "a", "tool": "b",
                   "locator": {"type": "x", "value": "y"},
                   "raw_excerpt": "z", "captured_at": "2026-04-25T22:00:00Z"}]},
        {"finding_id": "F-002", "claim": "y", "confidence": "high",
         "pins": [{"artifact": "a", "tool": "b",
                   "locator": {"type": "x", "value": "y"},
                   "raw_excerpt": "z", "captured_at": "2026-04-25T22:00:00Z"}]},
    ]

    # Make checkpoint fail on every call.
    def fail_write(*a, **kw):
        raise OSError("simulated disk full")
    monkeypatch.setattr(verifier_pass, "write_checkpoint", fail_write)

    # Must not raise — the OSError is absorbed.
    s = verifier_pass.run(s)
    # Both findings still got verdicts despite checkpoint failure.
    assert len(s["_verifier_decisions"]) == 2
