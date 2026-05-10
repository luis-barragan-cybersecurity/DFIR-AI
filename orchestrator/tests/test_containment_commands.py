"""Tests for the ATT&CK -> runnable containment translator.

These are pure-Python tests against the static crosswalk JSON; no LLM calls,
no host execution. The JSON is the source of truth for which techniques have
coverage.
"""
from __future__ import annotations

import pytest

from mh_orchestrator import containment_commands as cc


def test_default_action_isolate_host_windows() -> None:
    cmd = cc.commands_for_default_action("isolate_host", detected_os="windows")
    assert cmd is not None
    assert cmd["platform"] == "windows"
    assert "New-NetFirewallRule" in cmd["command"]
    assert cmd["reversibility"] == "high"


def test_default_action_isolate_host_linux() -> None:
    cmd = cc.commands_for_default_action("isolate_host", detected_os="linux")
    assert cmd is not None
    assert cmd["platform"] == "linux"
    assert "iptables" in cmd["command"]


def test_default_action_isolate_host_macos() -> None:
    cmd = cc.commands_for_default_action("isolate_host", detected_os="macos")
    assert cmd is not None
    assert "pfctl" in cmd["command"]


def test_default_action_unknown_os_returns_none() -> None:
    cmd = cc.commands_for_default_action("isolate_host", detected_os="unknown")
    assert cmd is None, "unknown OS has no platform key; must not fabricate"


def test_default_action_unknown_verb_returns_none() -> None:
    cmd = cc.commands_for_default_action("nonsense_verb", detected_os="windows")
    assert cmd is None


def test_techniques_resolve_per_platform() -> None:
    cmds = cc.commands_for_techniques(["T1059.001"], detected_os="windows")
    assert len(cmds) >= 1
    assert all(c["platform"] == "windows" for c in cmds)
    assert any("powershell" in c["command"].lower() or "pwsh" in c["command"].lower()
               for c in cmds)


def test_techniques_skip_when_platform_has_no_command() -> None:
    """T1547.001 (Registry Run Keys) is Windows-only; on Linux it should
    return zero commands rather than fabricate.
    """
    cmds = cc.commands_for_techniques(["T1547.001"], detected_os="linux")
    assert cmds == []


def test_techniques_unknown_id_skipped_silently() -> None:
    cmds = cc.commands_for_techniques(["T9999.999"], detected_os="windows")
    assert cmds == []


def test_techniques_preserve_order() -> None:
    cmds = cc.commands_for_techniques(
        ["T1059.001", "T1547.001"], detected_os="windows",
    )
    technique_ids = [c["technique_id"] for c in cmds]
    # Each input technique should appear before the next, even if multiple
    # actions per technique are emitted.
    if "T1547.001" in technique_ids:
        assert technique_ids.index("T1059.001") < technique_ids.index("T1547.001")


def test_coverage_for_returns_per_technique_bool() -> None:
    cov = cc.coverage_for(["T1059.001", "T9999.999"])
    assert cov["T1059.001"] is True
    assert cov["T9999.999"] is False


def test_placeholder_hints_extracted() -> None:
    cmds = cc.commands_for_techniques(["T1059.001"], detected_os="windows")
    kill_cmd = next(c for c in cmds if c["verb"] == "kill_pwsh_process")
    assert "<PID_LIST>" in kill_cmd["placeholder_hints"]


@pytest.mark.parametrize("tid", [
    "T1003.001", "T1059.001", "T1059.003", "T1547.001", "T1543.001",
    "T1543.002", "T1543.003", "T1053.005", "T1053.003", "T1071.001",
    "T1078", "T1027",
])
def test_known_technique_has_at_least_one_action(tid: str) -> None:
    """Anchor test: if any of the 12 baseline techniques disappears from
    the JSON, this fails loudly. Add new IDs here as the crosswalk grows.
    """
    assert tid in cc.all_known_technique_ids()


def test_version_string_present() -> None:
    assert cc.VERSION
    assert cc.VERSION != "unknown"


def test_contain_node_emits_runnable_command_for_windows(tmp_path) -> None:
    """End-to-end smoke: contain.run() against a Windows state should
    decorate at least one of the three default recs with `runnable_command`.
    """
    from mh_orchestrator.nodes import contain
    from mh_orchestrator.state import new_state

    state = new_state("smoke-001")
    state["_detected_os"] = "windows"
    state["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)

    result = contain.run(state)
    recs = result["containment_actions"]
    decorated = [r for r in recs if "runnable_command" in r]
    assert decorated, "at least one rec should have runnable_command on Windows"
    assert any(r["runnable_command"]["platform"] == "windows" for r in decorated)
