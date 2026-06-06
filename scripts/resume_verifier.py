#!/usr/bin/env python3
"""Salvage a verifier_pass that died mid-loop and finish the run.

Reads ``cases/<case>/output/audit.jsonl`` for completed verdicts, parses
any subagent _trace files for verdicts that the subagent EMITTED but the
parent Python died before recording, then dispatches the Verifier only
for findings that still have no verdict — finally walks the remainder of
the §11.2 graph (correlate → session_finalize) to emit the deliverables.

Why this exists:
  rocba-memory (2026-06-06) lost the F-017 Verifier verdict ($1.08 of
  forensic work) when the parent terminal closed mid-run. The F-017
  ``claude -p`` subprocess had already returned cleanly with a structured
  JSON verdict; the wrapper Python died receiving SIGHUP before it could
  write the decision to audit.jsonl or state.json. 16 prior decisions
  were intact in audit.jsonl but ``state["_verifier_decisions"]`` was
  empty because verifier_pass only checkpointed at end-of-loop.

  This script:
    1. Rebuilds ``_verifier_decisions`` from audit.jsonl + trace files.
    2. Calls ``invoke_subagent`` for any findings still unverified.
    3. Persists state.json + state.history.jsonl after each decision so
       another kill loses ≤1 decision, not the whole loop.
    4. Runs correlate + session_finalize so the case ends with the same
       §11.4 deliverables a clean run would have produced.

Usage:
    python3 scripts/resume_verifier.py <case-id> [--cases-dir DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Make orchestrator + mcp-server importable.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "orchestrator" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "mcp-server" / "src"))

from mh_orchestrator.cli import _make_orchestrator_durable  # noqa: E402
from mh_orchestrator.nodes import correlate, session_finalize, verifier_pass  # noqa: E402
from mh_orchestrator.persistence import write_checkpoint  # noqa: E402
from mh_orchestrator.state import deserialize_state, serialize_state  # noqa: E402

# Same fenced-JSON regex the verifier_pass parser uses.
_FENCED_JSON_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)
# Loose finding-id pattern (matches the same shape the orchestrator emits).
_FID_RE = re.compile(r"F-\d{3}[A-Za-z0-9_\-]+")


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stderr.isatty() else s


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if sys.stderr.isatty() else s


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m" if sys.stderr.isatty() else s


def _info(msg: str) -> None:
    print(f"{_bold('»')} {msg}", file=sys.stderr)


def _decisions_from_audit(audit_path: Path) -> dict[str, dict]:
    """Read every recorded verifier verdict from audit.jsonl. Returns
    {finding_id: decision_dict}. Last-write-wins per finding id."""
    out: dict[str, dict] = {}
    if not audit_path.exists():
        return out
    for line in audit_path.read_text().splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev = e.get("event") or ""
        if not ev.startswith("verifier_pass_") or "summary" in ev:
            continue
        data = e.get("data") or {}
        fid = data.get("finding_id")
        if not fid:
            continue
        decision = {
            "finding_id": fid,
            "decision": data.get("decision", "agree"),
            "verifier_decision_raw": data.get("verifier_decision_raw"),
            "rationale": data.get("raw_reply") or "[recovered from audit log]",
            "verifier_iter": data.get("iter", 0),
            "parse_error": False,
            "_recovered_from": "audit.jsonl",
        }
        out[fid] = decision
    return out


def _decisions_from_traces(trace_dir: Path) -> dict[str, dict]:
    """Parse verifier_*.stdout.jsonl trace files for verdicts that the
    subagent emitted but the orchestrator never recorded.

    Returns {finding_id: decision_dict}. Only includes findings whose
    trace contains a ``result:success`` event AND a fenced JSON verdict
    with ``verifier_decision``.
    """
    out: dict[str, dict] = {}
    if not trace_dir.exists():
        return out
    for trace in sorted(trace_dir.glob("verifier_*.stdout.jsonl")):
        verdict_obj: dict | None = None
        finding_id: str | None = None
        completed = False
        for line in trace.read_text().splitlines():
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = m.get("type")
            if t == "result" and m.get("subtype") == "success":
                completed = True
                result_text = m.get("result") or ""
                # Try fenced JSON first, then naked.
                for cand in _FENCED_JSON_RE.findall(result_text):
                    try:
                        obj = json.loads(cand)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict) and "verifier_decision" in obj:
                        verdict_obj = obj
                        finding_id = obj.get("finding_id")
                        break
            elif t == "assistant":
                # Catch verdicts emitted inline (some subagents skip fenced).
                content = (m.get("message") or {}).get("content") or []
                for block in content:
                    if block.get("type") != "text":
                        continue
                    text = block.get("text") or ""
                    for cand in _FENCED_JSON_RE.findall(text):
                        try:
                            obj = json.loads(cand)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(obj, dict) and "verifier_decision" in obj:
                            verdict_obj = obj
                            if not finding_id:
                                finding_id = obj.get("finding_id")
        if completed and verdict_obj and finding_id:
            raw_d = verdict_obj["verifier_decision"]
            routing = "agree" if raw_d == "agree" else "dissent"
            out[finding_id] = {
                "finding_id": finding_id,
                "decision": routing,
                "verifier_decision_raw": raw_d,
                "verifier_confidence": verdict_obj.get("verifier_confidence"),
                "pins_reverified": verdict_obj.get("pins_reverified"),
                "pins_failed": verdict_obj.get("pins_failed"),
                "delta": verdict_obj.get("delta", ""),
                "recommendation": verdict_obj.get("recommendation"),
                "rationale": verdict_obj.get("delta") or raw_d,
                "verifier_iter": 0,
                "parse_error": False,
                "_recovered_from": str(trace.name),
            }
    return out


def _load_state(output_dir: Path) -> dict:
    state_path = output_dir / "state.json"
    if not state_path.exists():
        raise SystemExit(f"error: no state.json at {state_path}")
    raw = json.loads(state_path.read_text())
    return deserialize_state(raw)


def _persist_state(state: dict, output_dir: Path) -> None:
    """Write state.json without going through the full LangGraph machinery."""
    write_checkpoint(state, output_dir)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="resume_verifier")
    p.add_argument("case_id")
    p.add_argument("--cases-dir", default=str(_REPO_ROOT / "cases"))
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be salvaged + verified but don't dispatch.",
    )
    args = p.parse_args(argv)

    _make_orchestrator_durable()

    case_dir = Path(args.cases_dir).expanduser().resolve() / args.case_id
    input_dir = case_dir / "input"
    output_dir = case_dir / "output"
    if not output_dir.exists():
        raise SystemExit(f"error: no output dir at {output_dir}")

    # Same env contract the orchestrator's CLI sets.
    os.environ.setdefault("MH_HOME", str(_REPO_ROOT))
    os.environ["EVIDENCE_PATH"] = str(input_dir)
    os.environ["OUTPUT_PATH"] = str(output_dir)
    os.environ["CASE_ID"] = args.case_id

    state = _load_state(output_dir)
    # Carry the dirs onto state since deserialize doesn't always restore them.
    state["_output_dir"] = str(output_dir)
    state["_input_dir"] = str(input_dir)

    findings = state.get("_findings") or []
    if not findings:
        # Findings might live in findings.json — load that and merge.
        fjson = output_dir / "findings.json"
        if fjson.exists():
            findings = json.loads(fjson.read_text())
            state["_findings"] = findings
    finding_ids = [f.get("finding_id") for f in findings if f.get("finding_id")]
    _info(f"case {args.case_id}: {len(finding_ids)} findings on record")

    # ── Recovery: audit log → state ────────────────────────────────────
    audit_decisions = _decisions_from_audit(output_dir / "audit.jsonl")
    trace_decisions = _decisions_from_traces(output_dir / "_trace")

    # Merge — audit wins where both have a value, trace fills gaps.
    recovered: dict[str, dict] = {}
    for fid, d in trace_decisions.items():
        recovered[fid] = d
    for fid, d in audit_decisions.items():
        recovered[fid] = d

    state["_verifier_decisions"] = list(recovered.values())
    _info(_green(f"recovered {len(recovered)} verdict(s)"))
    for fid, d in recovered.items():
        src = d.get("_recovered_from", "?")
        decision = d.get("verifier_decision_raw") or d.get("decision")
        print(f"  ✓ {fid:55s}  {decision:8s}  (from {src})", file=sys.stderr)

    missing = [fid for fid in finding_ids if fid not in recovered]
    _info(_yellow(f"{len(missing)} finding(s) still need verification"))
    for fid in missing:
        print(f"  • {fid}", file=sys.stderr)

    if args.dry_run:
        _info("dry-run: skipping subagent dispatch and finalize")
        return 0

    # ── Verify the remaining findings ──────────────────────────────────
    if missing:
        _info("dispatching Verifier subagent for missing findings…")
        # Set _verifier_revision_count so the convergence math treats this
        # as the first pass (matching what the orchestrator was doing).
        state.setdefault("_verifier_revision_count", 0)

        # Filter state["_findings"] to only the missing IDs so verifier_pass
        # doesn't re-verify the recovered ones. We restore the full list
        # after.
        full_findings = list(state["_findings"])
        state["_findings"] = [
            f for f in full_findings if f.get("finding_id") in missing
        ]
        try:
            state = verifier_pass.run(state)
        finally:
            state["_findings"] = full_findings
            _persist_state(state, output_dir)

    # Mark verifier complete unconditionally — we've recovered everything
    # we can and either dispatched or accounted for the rest.
    state["_verifier_complete"] = True
    state["_dissent_lessons"] = []

    # ── correlate + session_finalize → §11.4 deliverables ──────────────
    _info("running correlate…")
    state = correlate.run(state)
    _persist_state(state, output_dir)

    _info("running session_finalize…")
    state = session_finalize.run(state)
    _persist_state(state, output_dir)

    _info(_green(
        f"DONE — case {args.case_id} finalized. "
        f"Deliverables in {output_dir}/"
    ))
    deliverables = [
        "findings.json", "incident_summary.md", "compliance_map.json",
        "learning_trace.md", "remediation_plan.json", "lessons_learned.md",
        "containment_actions.jsonl", "recovery_verification.json",
        "agent_messages.jsonl", "audit.jsonl", "state.json",
        "state.history.jsonl",
    ]
    for f in deliverables:
        p = output_dir / f
        marker = "✓" if p.exists() else "✗"
        size = f"{p.stat().st_size:>9,d} B" if p.exists() else "         —"
        print(f"  {marker}  {size}  {f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
