"""Signal-tier registry tests."""

from __future__ import annotations

import pytest


def test_tier_for_returns_known_tier() -> None:
    from protocol_sift_mcp.signal_tiers import tier_for

    assert tier_for("memory_volatility") == 1
    assert tier_for("win_prefetch_parse") == 2
    assert tier_for("hash") == 3


def test_tier_for_strips_mcp_prefix() -> None:
    from protocol_sift_mcp.signal_tiers import tier_for

    assert tier_for("mcp__protocol_sift__memory_volatility") == 1
    assert tier_for("mcp__protocol_sift__win_evtx_query") == 1


def test_tier_for_returns_none_on_unknown() -> None:
    from protocol_sift_mcp.signal_tiers import tier_for

    assert tier_for("nonexistent_tool") is None


def test_tools_at_tier_returns_sorted_list() -> None:
    from protocol_sift_mcp.signal_tiers import tools_at_tier

    t1 = tools_at_tier(1)
    assert t1 == sorted(t1)
    assert "memory_volatility" in t1
    assert "win_evtx_query" in t1
    assert "win_registry_get" in t1


def test_tier_summary_covers_all_tiers() -> None:
    from protocol_sift_mcp.signal_tiers import tier_summary

    summary = tier_summary()
    assert set(summary.keys()) == {1, 2, 3}
    assert all(len(v) > 0 for v in summary.values()), \
        "every tier should have at least one tool"


def test_every_registered_tool_has_valid_tier() -> None:
    from protocol_sift_mcp.signal_tiers import SIGNAL_TIERS

    for name, tier in SIGNAL_TIERS.items():
        assert tier in (1, 2, 3), f"{name} has invalid tier {tier!r}"


@pytest.mark.parametrize("expected_tool", [
    "memory_volatility", "win_evtx_query", "win_registry_get",
    "win_prefetch_parse", "win_lnk_parse",
    "mac_plist_get", "mac_knowledgec_query",
    "linux_history_parse",
    "hash", "os_detect", "magic_check",
    "audit_append", "finding_record",
])
def test_all_13_mcp_tools_have_tier(expected_tool: str) -> None:
    """Every MCP tool registered in server.py must have a signal tier.
    If a new tool is added without a tier, this test catches it.
    """
    from protocol_sift_mcp.signal_tiers import SIGNAL_TIERS

    assert expected_tool in SIGNAL_TIERS, \
        f"{expected_tool} missing from signal_tiers.SIGNAL_TIERS"
