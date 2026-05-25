"""detect node — fingerprints artifacts and sets _detected_os."""
from __future__ import annotations

import os
from pathlib import Path

from .. import csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState


def _detect_os_from_evidence(evidence_path: str) -> str:
    """Quick heuristic: scan filenames in evidence dir for OS markers.
    Real os_detect MCP tool is invoked by the LLM nodes; this is the
    deterministic stub used inline by the detect node and short-circuited
    cleanly under MH_NO_CLAUDE=1.

    Memory-dump branch is intentionally LAST so a case dir that contains
    BOTH a memory image AND OS-specific artifacts (e.g. .raw + .evtx hives)
    classifies as the OS — the OS-side artifacts are the higher-signal
    triage target. A memory-only case (just .raw) falls through to
    memory_dump → routed to WindowsAgent which has memory_volatility in
    its tool allowlist (see triage.OS_TO_SUBAGENT).

    Rocba case (2026-05) regressed because .raw was missing from this
    heuristic: a 19GB Rocba-Memory.raw with no sibling OS artifacts
    classified as 'unknown' → triage routed to WindowsAgent via the
    fallback default → WindowsAgent tried win_evtx_query / win_registry_get
    on raw bytes → 0 findings shipped to findings.json. The .raw / .mem /
    .dmp / .vmem / .lime / .aff branch closes that gap."""
    p = Path(evidence_path)
    if not p.exists():
        return "unknown"
    names = " ".join(f.name.lower() for f in p.rglob("*") if f.is_file())
    if any(m in names for m in ("ntuser.dat", ".evtx", "prefetch", ".pf")):
        return "windows"
    if any(m in names for m in (".plist", "knowledgec.db", "tracev3")):
        return "macos"
    if any(m in names for m in ("auth.log", "syslog", ".bash_history")):
        return "linux"
    if any(m in names for m in (".raw", ".mem", ".dmp", ".vmem", ".lime", ".aff")):
        return "memory_dump"
    return "unknown"


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    evidence = os.environ.get("EVIDENCE_PATH", "")
    detected = _detect_os_from_evidence(evidence) if evidence else "unknown"
    state["_detected_os"] = detected
    state["phase"] = "triage"
    state["_node_history"].append("detect")
    csf_tags.mark_satisfied(state, csf_tags.DE_AE_02)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("detect"))

    record_audit(state, event="detect_complete", data={"detected_os": detected})
    emit_message(state, from_agent="orchestrator", to_agent="orchestrator",
                 role="lifecycle", content=f"detect: os={detected}")
    write_checkpoint(state, out)
    append_history(state, out, node="detect")
    return state
