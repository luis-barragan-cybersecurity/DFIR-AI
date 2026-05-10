"""CSF 2.0 subcategory ID constants + state mutator.

Mirrors Plans/IR_FRAMEWORKS_REFERENCE.md §3.1 RESPOND categories, §3.2 RECOVER,
§3.3 Govern oversight, and §3 Detect categories used by Sub-Plan 03 nodes.
"""
from __future__ import annotations

from .state import IncidentState

# DETECT (DE) — Adverse Event Analysis
DE_AE_02 = "DE.AE-02"

# RESPOND (RS) — Incident Management
RS_MA_01 = "RS.MA-01"
RS_MA_03 = "RS.MA-03"

# RESPOND (RS) — Incident Analysis
RS_AN_01 = "RS.AN-01"
RS_AN_03 = "RS.AN-03"

# RESPOND (RS) — Communication
RS_CO_02 = "RS.CO-02"
RS_CO_03 = "RS.CO-03"

# RESPOND (RS) — Mitigation
RS_MI_01 = "RS.MI-01"
RS_MI_02 = "RS.MI-02"

# RECOVER (RC) — Recovery Plan + Communication
RC_RP_01 = "RC.RP-01"
RC_CO_03 = "RC.CO-03"

# GOVERN (GV) — Oversight
GV_OV_01 = "GV.OV-01"


def mark_satisfied(state: IncidentState, *ids: str) -> None:
    """Add one or more CSF subcategory IDs to state['csf_subcategories_satisfied']."""
    state["csf_subcategories_satisfied"].update(ids)
