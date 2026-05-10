"""csf_tags emitter tests — CSF 2.0 subcategory ID marking."""
from __future__ import annotations

from mh_orchestrator import csf_tags
from mh_orchestrator.state import new_state


def test_mark_satisfied_adds_ids() -> None:
    s = new_state("c")
    csf_tags.mark_satisfied(s, "RS.MA-01", "RS.MA-03")
    assert s["csf_subcategories_satisfied"] == {"RS.MA-01", "RS.MA-03"}


def test_mark_satisfied_is_idempotent() -> None:
    s = new_state("c")
    csf_tags.mark_satisfied(s, "RS.MA-01")
    csf_tags.mark_satisfied(s, "RS.MA-01")
    csf_tags.mark_satisfied(s, "RS.MA-01", "RS.AN-03")
    assert s["csf_subcategories_satisfied"] == {"RS.MA-01", "RS.AN-03"}


def test_module_exports_required_constants() -> None:
    # Constants used by Sub-Plan 03 nodes (must exist as module attributes).
    expected = [
        "RS_MA_01", "RS_MA_03",      # Incident Management
        "RS_AN_01", "RS_AN_03",      # Incident Analysis
        "RS_CO_02", "RS_CO_03",      # Communication
        "RS_MI_01", "RS_MI_02",      # Mitigation
        "RC_RP_01", "RC_CO_03",      # Recovery
        "GV_OV_01",                   # Governance / Oversight
        "DE_AE_02",                   # Detect / Adverse Event Analysis
    ]
    for name in expected:
        assert hasattr(csf_tags, name), f"missing {name}"
        # Values follow dotted CSF format
        val = getattr(csf_tags, name)
        assert "." in val and "-" in val, f"{name}={val!r} not in dotted CSF form"
