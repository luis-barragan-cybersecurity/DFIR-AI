"""finding_record — schema-enforced finding registration.

Rejects un-pinned claims at the API boundary. The whole trust stack collapses
without this gate. Also auto-derives the `tier` and `pin_count` decorations
so the correlator can flag declared-confidence vs evidence-strength mismatches
without re-counting pins.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..schema import Finding


def derive_evidence_tier(pin_count: int) -> str:
    """Map pin count → evidence tier.

    Two or more independent pins ⇒ `confirmed_by_evidence`. One pin ⇒
    `inferred_from_evidence`. The schema rejects zero pins outright (the
    agent is expected to file a `confidence='unknown'` gap finding instead),
    so we never see pin_count==0 here.

    NOTE: this is `evidence_tier`, not `confidence`. The agent's declared
    `confidence` field stays untouched — sometimes one strong pin justifies
    "confirmed" (a single sha256-matched malicious binary, say). The
    correlator surfaces mismatches between declared confidence and this
    derived tier in its report.
    """
    if pin_count >= 2:
        return "confirmed_by_evidence"
    return "inferred_from_evidence"


def finding_record(findings_path: Path, finding: dict) -> dict:
    """Validate against schema, append to findings.json (JSON array file)."""
    parsed = Finding.model_validate(finding)

    findings_path.parent.mkdir(parents=True, exist_ok=True)
    if findings_path.exists() and findings_path.stat().st_size > 0:
        existing = json.loads(findings_path.read_text())
        if not isinstance(existing, list):
            raise RuntimeError(f"{findings_path} is not a JSON array")
    else:
        existing = []

    record = parsed.model_dump(mode="json")
    record["recorded_at"] = datetime.now(UTC).isoformat()
    record["pin_count"] = len(parsed.pins)
    record["evidence_tier"] = derive_evidence_tier(record["pin_count"])
    existing.append(record)
    findings_path.write_text(json.dumps(existing, indent=2, default=str))
    return record


def list_findings(findings_path: Path) -> list[dict]:
    if not findings_path.exists():
        return []
    return json.loads(findings_path.read_text())
