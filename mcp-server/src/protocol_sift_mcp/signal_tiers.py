"""IR signal tiers for the MCP forensic toolset.

Operational IR triage spends 80% of its decision value on a small set of
high-signal artifacts: process tree + parent/child, outbound network
connections (especially to rare destinations), persistence mechanisms,
credential-access artifacts, and recent user activity. Lower-signal tools
(full prefetch dumps, every audit record) are still useful but should not
gate the early scoping/containment decisions.

This registry tags each MCP tool with an `ir_signal_tier` so:

- The agent's TodoWrite plan orders tier-1 work first.
- `mh tools --tier=N` filters the listing for prioritised triage.
- The exec report can show "we exhausted tier-1 surface, dropped to tier-2"
  as an explicit confidence signal for owners.

Tier semantics:

- **Tier 1** — high-signal, fast, decision-driving. Run these first. If you
  cannot answer a question with tier-1 alone, escalate to tier 2.
- **Tier 2** — confirmation-grade. Useful for corroboration and timeline
  reconstruction; less so for "what do I do in the next 4 hours".
- **Tier 3** — bulk/audit-grade. Used for completeness, accuracy reports,
  and rare-but-high-value patterns. Don't gate scoping on these.

The registry is a flat dict keyed by the bare MCP tool name (no prefix).
The `mcp__protocol_sift__` prefix is added at the boundary by callers that
need to match against the agent's allowedTools list.
"""

from __future__ import annotations

from typing import Literal

SignalTier = Literal[1, 2, 3]

# Single source of truth. Keep alphabetised within each tier for diff sanity.
SIGNAL_TIERS: dict[str, SignalTier] = {
    # ─── Tier 1 — process tree, network state, persistence, credentials ────
    "memory_volatility": 1,           # pslist/psscan/netscan/malfind/svcscan
    "win_evtx_query": 1,              # 4624/4625/4688/7045 = exec + auth + svc
    "win_registry_get": 1,            # Run/RunOnce/Services/AutoStart persistence
    # ─── Tier 2 — execution proof + recent-activity corroboration ──────────
    "linux_history_parse": 2,         # bash/zsh = recent user commands
    "mac_knowledgec_query": 2,        # macOS recent-app + focus state
    "win_lnk_parse": 2,               # ShellBag-adjacent recent-doc pivots
    "win_prefetch_parse": 2,          # execution proof, lower freshness
    # ─── Tier 3 — bulk/audit-grade primitives ──────────────────────────────
    "audit_append": 3,                # logging plumbing, not a finding source
    "hash": 3,                        # integrity, not signal
    "mac_plist_get": 3,               # bulk plist surface (most are config)
    "magic_check": 3,                 # routing primitive
    "os_detect": 3,                   # routing primitive
    "finding_record": 3,              # registration plumbing, not a probe
}


def tier_for(tool_name: str) -> SignalTier | None:
    """Return the IR signal tier for a tool, stripping any prefix.

    Accepts both bare names (`memory_volatility`) and prefixed names
    (`mcp__protocol_sift__memory_volatility`). Returns None if the tool
    is not registered (caller decides — block, warn, or default).
    """
    bare = tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name
    return SIGNAL_TIERS.get(bare)


def tools_at_tier(tier: SignalTier) -> list[str]:
    """All tool names at the given tier, sorted for deterministic output."""
    return sorted(name for name, t in SIGNAL_TIERS.items() if t == tier)


def tier_summary() -> dict[SignalTier, list[str]]:
    """Tier → list of tool names. Used by `mh tools` for the tiered listing."""
    return {t: tools_at_tier(t) for t in (1, 2, 3)}
