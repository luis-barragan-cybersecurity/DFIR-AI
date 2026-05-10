"""Tests for the high-value handle-dump registry."""
from __future__ import annotations

import pytest

from mh_orchestrator import handle_dump_registry as hdr


def test_onedrive_in_registry() -> None:
    targets = hdr.targets_for_process("OneDrive.exe")
    assert len(targets) == 1
    aodl_match = any(".aodl" in p for p in targets[0].artifact_patterns)
    downloads3_match = any("downloads3.txt" in p for p in targets[0].artifact_patterns)
    assert aodl_match, "OneDrive entry MUST list .aodl — Rocba case anchor"
    assert downloads3_match, "OneDrive entry MUST list downloads3.txt"


def test_match_case_insensitive() -> None:
    a = hdr.targets_for_process("OneDrive.exe")
    b = hdr.targets_for_process("ONEDRIVE.EXE")
    c = hdr.targets_for_process("onedrive.exe")
    assert a == b == c


def test_volatility_truncated_name_matches() -> None:
    """Volatility 14-char truncation: googledrivesync.exe → googledrivesy."""
    truncated = hdr.targets_for_process("googledrivesy")
    assert any(t.process_name_lc == "googledrivesync.exe" for t in truncated)


def test_unknown_process_returns_empty() -> None:
    assert hdr.targets_for_process("notepad.exe") == ()
    assert hdr.targets_for_process("System") == ()


@pytest.mark.parametrize("name", [
    "onedrive.exe",
    "googledrivefs.exe",
    "googledrivesync.exe",
    "dropbox.exe",
    "slack.exe",
    "teams.exe",
    "outlook.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
])
def test_known_high_value_processes_registered(name: str) -> None:
    """Anchor: every cloud/messaging/browser client we expect must be present.
    If a future refactor drops one, this test fails loudly.
    """
    assert name in hdr.all_registered_processes()


def test_coverage_summary_is_diagnosable() -> None:
    summary = hdr.coverage_summary()
    assert "onedrive.exe" in summary
    assert len(summary["onedrive.exe"]) >= 4
    # Every pattern list is non-empty + alphabetised
    for proc, patterns in summary.items():
        assert patterns, f"{proc} has no patterns"
        assert patterns == sorted(set(patterns))


def test_every_entry_has_minimum_plugin() -> None:
    """Each entry should default to windows.dumpfiles. If a future entry
    needs a different plugin (e.g. mac.* equivalent), set it explicitly.
    """
    for e in hdr.REGISTRY:
        assert e.minimum_volatility_plugin, e.process_name_lc


def test_why_it_matters_is_present_and_meaningful() -> None:
    for e in hdr.REGISTRY:
        assert e.why_it_matters, f"{e.process_name_lc} missing rationale"
        assert len(e.why_it_matters) >= 30, \
            f"{e.process_name_lc} rationale too short — owners need actionable why"
