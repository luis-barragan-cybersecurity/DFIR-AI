"""attack_tag node — extract MITRE ATT&CK technique IDs from findings.

Pure-python: scans state['_findings'] for technique IDs in the `claim` text
and `mitre_attck` field. Dedupes and sorts. Marks RS.AN-03 (Categorization).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .. import csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "attack_tag"

# Matches T1059, T1059.001, etc. (4-digit technique, optional 3-digit subtechnique)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_from_value(value: Any) -> list[str]:
    """Extract technique IDs from a string or list-of-strings."""
    found: list[str] = []
    if isinstance(value, str):
        found.extend(TECHNIQUE_RE.findall(value))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                # If item itself is a bare technique ID, include it; else regex-scan
                m = TECHNIQUE_RE.findall(item)
                if m:
                    found.extend(m)
                elif TECHNIQUE_RE.fullmatch(item):
                    found.append(item)
    return found


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    findings = state.get("_findings", []) or []

    collected: set[str] = set(state.get("attack_techniques", []) or [])
    for f in findings:
        # Scan claim text
        claim = f.get("claim", "")
        for tid in _extract_from_value(claim):
            collected.add(tid)
        # Scan mitre_attck explicit field
        mitre = f.get("mitre_attck", [])
        for tid in _extract_from_value(mitre):
            collected.add(tid)

    state["attack_techniques"] = sorted(collected)
    state["phase"] = "analyze"
    csf_tags.mark_satisfied(state, csf_tags.RS_AN_03)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("attack_tag"))
    state["_node_history"].append(NODE_NAME)

    record_audit(
        state, event="attack_tag_complete",
        data={"techniques": list(state["attack_techniques"]),
              "findings_scanned": len(findings)},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"attack_tag: {len(state['attack_techniques'])} unique techniques",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
