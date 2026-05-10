"""ATT&CK technique → runnable containment one-liners.

The contain node currently emits high-level advisory recommendations
("Isolate affected host from network"). Owners need executable text — the
single thing they can paste into a terminal. This module loads a static
crosswalk JSON (versioned, audit-pinned) and resolves a recommendation +
detected_os into a `{powershell, bash, reversibility}` payload.

Every command stays advisory: MemoryHound NEVER executes containment.
The JSON intentionally biases toward reversible verbs (block, isolate,
suspend, mask) over destructive (delete, wipe).

Usage:

    from mh_orchestrator.containment_commands import (
        commands_for_default_action,
        commands_for_techniques,
    )

    actions = commands_for_techniques(["T1059.001", "T1547.001"], detected_os="windows")
    isolate = commands_for_default_action("isolate_host", detected_os="linux")
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, TypedDict

DetectedOS = Literal["windows", "linux", "macos", "unknown"]

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "containment_commands.json"
_RAW: dict = json.loads(_DATA_PATH.read_text())

VERSION: str = _RAW.get("version", "unknown")


class ContainmentCommand(TypedDict, total=False):
    """A single runnable containment one-liner for a specific platform."""

    technique_id: str          # ATT&CK ID this applies to ("" for default actions)
    verb: str                  # Stable identifier ("kill_pwsh_process")
    description: str           # One-line human description
    platform: DetectedOS       # which OS this command targets
    command: str               # The actual shell-runnable string
    reversibility: str         # "high" | "medium" | "low"
    placeholder_hints: list[str]   # Substrings the operator must replace


_PLACEHOLDER_TOKENS = ("<USER>", "<PID_LIST>", "<HOST>", "<C2_IP>", "<TASK_NAME>",
                       "<PATH>", "<UNIT>", "<SVC>", "<VALUE_NAME>", "<CRON_PATTERN>",
                       "<PATH_TO_PLIST>", "<ADMIN>")


def _placeholders(cmd: str | None) -> list[str]:
    if not cmd:
        return []
    return [tok for tok in _PLACEHOLDER_TOKENS if tok in cmd]


def _platform_key(detected_os: DetectedOS) -> str | None:
    """Map detected_os to the JSON key that holds its command text."""
    return {
        "windows": "windows_powershell",
        "linux": "linux_bash",
        "macos": "macos_bash",
        "unknown": None,
    }.get(detected_os)


def _build_command(
    *, technique_id: str, action: dict, detected_os: DetectedOS,
) -> ContainmentCommand | None:
    """Build a ContainmentCommand for the specified platform; return None if
    the action has no command for that platform (e.g., a Linux-only verb on
    a Windows host).
    """
    key = _platform_key(detected_os)
    cmd_text = action.get(key) if key else None
    if not cmd_text:
        return None
    return ContainmentCommand(
        technique_id=technique_id,
        verb=action.get("verb", action.get("description", "unknown")),
        description=action.get("description", ""),
        platform=detected_os,
        command=cmd_text,
        reversibility=action.get("reversibility", "unknown"),
        placeholder_hints=_placeholders(cmd_text),
    )


def commands_for_techniques(
    attack_ids: list[str], *, detected_os: DetectedOS,
) -> list[ContainmentCommand]:
    """Resolve a list of ATT&CK technique IDs to platform-specific commands.

    Unknown techniques are skipped silently — callers should compare the
    output length to the input to surface coverage gaps in their report.
    Order is preserved from the input; duplicate verbs across techniques
    are NOT deduped (some are platform-specific corrections of each other).
    """
    techniques = _RAW.get("techniques", {})
    out: list[ContainmentCommand] = []
    for tid in attack_ids:
        entry = techniques.get(tid)
        if not entry:
            continue
        for action in entry.get("actions", []):
            cmd = _build_command(
                technique_id=tid, action=action, detected_os=detected_os,
            )
            if cmd is not None:
                out.append(cmd)
    return out


def commands_for_default_action(
    action_name: str, *, detected_os: DetectedOS,
) -> ContainmentCommand | None:
    """Look up one of the framework default actions (`isolate_host`,
    `rotate_credentials`, `snapshot_evidence`) for a specific platform.
    """
    defaults = _RAW.get("default_actions", {})
    action = defaults.get(action_name)
    if not action:
        return None
    return _build_command(
        technique_id="", action={**action, "verb": action_name},
        detected_os=detected_os,
    )


def coverage_for(attack_ids: list[str]) -> dict[str, bool]:
    """Return {technique_id: True if we have any command for it} regardless
    of platform. Used by the exec report to show "we covered N of M
    observed techniques".
    """
    techniques = _RAW.get("techniques", {})
    return {tid: tid in techniques for tid in attack_ids}


def all_known_technique_ids() -> list[str]:
    """For tests + diagnostics."""
    return sorted(_RAW.get("techniques", {}).keys())
