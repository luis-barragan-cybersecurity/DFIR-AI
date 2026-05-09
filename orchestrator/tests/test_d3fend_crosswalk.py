"""Tests for D3FEND crosswalk loader.

Sub-Plan 04 Task 2 — replaces d3fend_stub with a curated, version-pinned
ATT&CK -> D3FEND countermeasure mapping loaded from
orchestrator/data/d3fend_crosswalk.json at module import time.
"""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator import d3fend_crosswalk
from mh_orchestrator.state import new_state


def test_loads_at_import() -> None:
    """JSON loaded at module import; CROSSWALK is non-empty."""
    assert isinstance(d3fend_crosswalk.CROSSWALK, dict)
    assert len(d3fend_crosswalk.CROSSWALK) >= 20  # 25 expected
    assert d3fend_crosswalk.VERSION == "1.3.0"


def test_lookup_known_returns_recs(tmp_path: Path) -> None:
    """Known ATT&CK ID returns >=1 Countermeasure with all fields populated."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    recs = d3fend_crosswalk.lookup_all(s, ["T1003.001"])
    assert len(recs) >= 1
    rec = recs[0]
    assert rec.d3fend_id.startswith("D3-")
    assert rec.attack_id_satisfied == "T1003.001"
    assert rec.tactic in {
        "Model", "Harden", "Detect", "Isolate",
        "Deceive", "Evict", "Restore",
    }
    assert rec.rationale  # non-empty
    assert rec.name  # non-empty


def test_lookup_unknown_emits_miss(tmp_path: Path) -> None:
    """Unknown ATT&CK ID returns empty AND writes a d3fend_crosswalk_miss audit event."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    recs = d3fend_crosswalk.lookup_all(s, ["T9999.999"])
    assert recs == []
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    text = audit_path.read_text()
    assert "d3fend_crosswalk_miss" in text
    assert "T9999.999" in text


def test_lookup_dedupe(tmp_path: Path) -> None:
    """Same d3fend_id from multiple ATT&CK IDs only appears once."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    # T1003.001 and T1059.001 both contain D3-PA (Process Analysis).
    recs = d3fend_crosswalk.lookup_all(s, ["T1003.001", "T1059.001"])
    d3_ids = [r.d3fend_id for r in recs]
    assert len(d3_ids) == len(set(d3_ids)), f"duplicates found: {d3_ids}"
    # Sanity: D3-PA shows up exactly once across the merged result.
    assert d3_ids.count("D3-PA") == 1


def test_lookup_empty_input(tmp_path: Path) -> None:
    """Empty input -> empty output, no audit event written."""
    s = new_state("c-test")
    s["_output_dir"] = str(tmp_path)
    recs = d3fend_crosswalk.lookup_all(s, [])
    assert recs == []
    audit_path = tmp_path / "audit.jsonl"
    # Either no audit file at all, or no miss events recorded.
    if audit_path.exists():
        assert "d3fend_crosswalk_miss" not in audit_path.read_text()
