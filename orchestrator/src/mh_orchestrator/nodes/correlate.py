"""correlate — Cross-finding contradiction + gap detector.

Sits between verifier_pass and session_finalize. Reads `state["_findings"]`
and surfaces three classes of cross-finding signal that the per-finding
verifier doesn't catch:

  1. Contradictions: two findings whose claims reference the same PID, host,
     or user but with mutually exclusive verbs (e.g. "process X exited at T"
     vs "process X still running at T+10m" with same PID).
  2. Tactic-sequence gaps: ATT&CK technique set skips an expected kill-chain
     phase (e.g. Execution + Impact present, Persistence + C&C missing).
     These often indicate evidence-collection gaps rather than attacker
     anti-forensics, but they should be visible to the reporter.
  3. Confidence mismatches: two linked findings (one's `related_findings`
     names the other) carry incompatible confidence levels (confirmed depends
     on inferred, or inferred depends on uncertain).

The result is written to `state["_correlation"]` and audit event
`correlation_complete` is emitted. The Reporter (session_finalize) picks
this up and surfaces it in narrative.md + exec-report.md.

This node is read-only on `_findings` — it does not drop or re-tag findings;
it only annotates. Removal/re-routing is the verifier's job.
"""
from __future__ import annotations

import re
from typing import Any

from ..attack_timeline import tactic_for
from ..state import IncidentState

# Tactics that, when one is present, suggest the others should also leave a
# trace. Used for the gap-detection heuristic. Order does NOT imply ordering;
# this is a co-occurrence expectation only.
_EXPECTED_NEIGHBORS: dict[str, set[str]] = {
    "Execution":        {"Persistence", "Defense Evasion"},
    "Persistence":      {"Execution"},
    "Credential Access": {"Lateral Movement", "Discovery"},
    "Lateral Movement": {"Credential Access", "Discovery"},
    "Command & Control": {"Execution", "Exfiltration"},
    "Exfiltration":     {"Command & Control", "Collection"},
    "Impact":           {"Execution", "Persistence"},
}


_PID_RE = re.compile(r"\bPID[=\s:]*?(\d{1,6})\b", re.IGNORECASE)
_HOST_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|[A-Z0-9-]{3,16})\b")
_USER_RE = re.compile(r"\b(?:user|username|account)[=\s:]*?([A-Za-z0-9_.\\-]+)\b", re.IGNORECASE)

# Verbs that, when paired, suggest a contradiction about the same subject.
_CONTRADICTORY_PAIRS: list[tuple[set[str], set[str]]] = [
    ({"exited", "terminated", "killed", "dead"}, {"running", "alive", "active", "live"}),
    ({"absent", "missing", "not found"}, {"present", "found", "exists"}),
    ({"failed", "denied", "rejected"}, {"succeeded", "accepted", "completed"}),
]


def _extract_subjects(claim: str) -> dict[str, list[str]]:
    return {
        "pids": _PID_RE.findall(claim),
        "users": [m.lower() for m in _USER_RE.findall(claim)],
    }


def _verbs_in(claim: str) -> set[str]:
    lc = claim.lower()
    return {tok for tok in re.findall(r"[a-z]+", lc) if len(tok) > 3}


def _detect_contradictions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    contradictions: list[dict[str, Any]] = []
    for i, fa in enumerate(findings):
        sa = _extract_subjects(fa.get("claim", ""))
        va = _verbs_in(fa.get("claim", ""))
        for fb in findings[i + 1:]:
            sb = _extract_subjects(fb.get("claim", ""))
            # Need a shared subject to even consider conflict.
            shared = (set(sa["pids"]) & set(sb["pids"])) | (set(sa["users"]) & set(sb["users"]))
            if not shared:
                continue
            vb = _verbs_in(fb.get("claim", ""))
            for neg, pos in _CONTRADICTORY_PAIRS:
                if (va & neg and vb & pos) or (va & pos and vb & neg):
                    contradictions.append({
                        "finding_a": fa.get("finding_id"),
                        "finding_b": fb.get("finding_id"),
                        "shared_subject": sorted(shared),
                        "verbs_a": sorted(va & (neg | pos)),
                        "verbs_b": sorted(vb & (neg | pos)),
                    })
                    break
    return contradictions


def _detect_tactic_gaps(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observed: set[str] = set()
    for f in findings:
        for tid in f.get("mitre_attck", []) or []:
            tac = tactic_for(tid)
            if tac:
                observed.add(tac)
    gaps: list[dict[str, Any]] = []
    for tac, expected_neighbors in _EXPECTED_NEIGHBORS.items():
        if tac not in observed:
            continue
        missing = expected_neighbors - observed
        if missing:
            gaps.append({
                "observed_tactic": tac,
                "missing_neighbors": sorted(missing),
            })
    return gaps


def _detect_confidence_mismatches(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {f.get("finding_id"): f for f in findings if f.get("finding_id")}
    rank = {"confirmed": 3, "inferred": 2, "uncertain": 1, "unknown": 0}
    mismatches: list[dict[str, Any]] = []
    for f in findings:
        my_conf = f.get("confidence", "unknown")
        for rid in f.get("related_findings", []) or []:
            r = by_id.get(rid)
            if not r:
                continue
            their_conf = r.get("confidence", "unknown")
            # Flag only the case where the more-confident claim cites the
            # less-confident one — that's the load-bearing direction.
            if rank.get(my_conf, 0) > rank.get(their_conf, 0):
                mismatches.append({
                    "claimant_id": f.get("finding_id"),
                    "claimant_confidence": my_conf,
                    "supporting_id": rid,
                    "supporting_confidence": their_conf,
                })
    return mismatches


def correlate_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure function — useful for tests and reuse outside the graph."""
    return {
        "finding_count": len(findings),
        "contradictions": _detect_contradictions(findings),
        "tactic_gaps": _detect_tactic_gaps(findings),
        "confidence_mismatches": _detect_confidence_mismatches(findings),
    }


def run(state: IncidentState) -> IncidentState:
    from . import record_audit  # local import avoids circular

    findings = list(state.get("_findings", []))
    report = correlate_findings(findings)

    # Stash on state so session_finalize can render it. Use a non-private
    # key (no underscore prefix) so it lands in serialize_state via the
    # generic catch-all path when added there; for now we keep it on the
    # mutable dict and let session_finalize pick it up directly.
    state_dict: dict[str, Any] = state  # type: ignore[assignment]
    state_dict["_correlation"] = report

    record_audit(
        state,
        event="correlation_complete",
        data={
            "contradictions": len(report["contradictions"]),
            "tactic_gaps": len(report["tactic_gaps"]),
            "confidence_mismatches": len(report["confidence_mismatches"]),
        },
    )
    state["_node_history"].append("correlate")
    return state
