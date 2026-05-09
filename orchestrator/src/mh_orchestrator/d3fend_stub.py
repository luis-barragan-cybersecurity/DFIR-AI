"""D3FEND knowledge-graph stub.

Sub-Plan 04 replaces this with real queries against the D3FEND OWL/JSON
knowledge graph (https://d3fend.mitre.org/). For Sub-Plan 03 every call
returns [] and emits a `d3fend_stub_used` audit warning so the deferral
is auditable in production logs.
"""
from __future__ import annotations

from pathlib import Path

from protocol_sift_mcp.tools.audit import audit_append

from .state import Countermeasure, IncidentState


def recommend(state: IncidentState, attack_techniques: list[str]) -> list[Countermeasure]:
    """Return D3FEND countermeasures for the given ATT&CK technique IDs.

    Stub: always returns []. Audit warning emitted on every call to flag the
    deferral. Sub-Plan 04 swaps the import to a live implementation.
    """
    audit_log = Path(state["_output_dir"]) / "audit.jsonl"
    audit_append(
        audit_log,
        event="d3fend_stub_used",
        data={
            "attack_techniques": list(attack_techniques),
            "sub_plan_04": "pending",
            "warning": "D3FEND knowledge graph not yet integrated; returning empty recommendations",
        },
    )
    return []
