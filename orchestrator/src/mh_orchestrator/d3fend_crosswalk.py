"""Static D3FEND v1.3.0 ATT&CK -> countermeasure crosswalk.

Replaces ``d3fend_stub``. Loaded once at import time from
``orchestrator/data/d3fend_crosswalk.json``.

The dataset is a curated, version-pinned snapshot of the D3FEND knowledge
graph (https://d3fend.mitre.org). Pinning the version here keeps audit
output reproducible across runs — Sub-Plan 04 explicitly trades live KG
queries for offline determinism.
"""
from __future__ import annotations

import json
from pathlib import Path

from .state import Countermeasure, IncidentState

_DATA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "d3fend_crosswalk.json"
)
_RAW: dict = json.loads(_DATA_PATH.read_text())

CROSSWALK: dict[str, list[dict]] = {
    tid: entry["countermeasures"]
    for tid, entry in _RAW.get("mappings", {}).items()
}
VERSION: str = _RAW.get("version", "unknown")


def lookup_all(state: IncidentState, attack_ids: list[str]) -> list[Countermeasure]:
    """Resolve ATT&CK IDs to D3FEND countermeasures.

    Dedupes by ``d3fend_id`` across the merged result. Emits one
    ``d3fend_crosswalk_miss`` audit event per unknown ATT&CK ID so
    coverage gaps in the curated dataset surface in the audit log.

    Argument shape mirrors :func:`d3fend_stub.recommend` (state plus a
    list of ATT&CK technique IDs) so the Task 3 swap is a one-line
    import change.
    """
    # Lazy import: nodes/__init__.py imports from this module via
    # d3fend_recommend, so a top-level import would close the cycle.
    from .nodes import record_audit

    seen_d3: set[str] = set()
    out: list[Countermeasure] = []
    for tid in attack_ids:
        recs = CROSSWALK.get(tid)
        if not recs:
            record_audit(
                state,
                event="d3fend_crosswalk_miss",
                data={"attack_id": tid, "version": VERSION},
            )
            continue
        for rec in recs:
            d3_id = rec["d3fend_id"]
            if d3_id in seen_d3:
                continue
            seen_d3.add(d3_id)
            out.append(
                Countermeasure(
                    d3fend_id=d3_id,
                    name=rec["name"],
                    tactic=rec["tactic"],
                    attack_id_satisfied=tid,
                    rationale=rec["rationale"],
                )
            )
    return out
