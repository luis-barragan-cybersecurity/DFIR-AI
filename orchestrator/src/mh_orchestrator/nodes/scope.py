"""scope node — enumerate the operational footprint of the incident.

Sits between `triage` and `declare_incident` (when triage doesn't suppress).
The contain/eradicate/recover stack is only as good as the scope it works
against; this node forces an explicit, structured answer to the four
questions every IR lead asks first:

    1. Which hosts are touched?
    2. Which user accounts are touched?
    3. Which services / processes / persistence vectors are involved?
    4. Which data classes (paths) are at stake?

Pure Python — no LLM. Reads `state["_findings"]` (list of finding dicts
each with `claim` + `pins[]`) and the artifact metadata in
`state["forensic_artifacts"]`. Mutates state in place by setting
`affected_hosts`, `affected_users`, `affected_services`, and
`affected_data` (sorted lists for deterministic output).

The node is intentionally cheap so it can fire on every incident without
gating on subagent results. It's a structural extractor, not an analyst.
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import csf_tags
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "scope"

# ──────────────────────────────────────────────────────────────────────────
# Patterns — kept conservative to avoid false attribution. Each pattern
# extracts an entity the contain/eradicate stack will need a name for.
# ──────────────────────────────────────────────────────────────────────────

# user — accept Windows DOMAIN\user, plain usernames after "user " or "USER:",
# or unix-style /home/<user> / /Users/<user> paths.
_USER_PATTERNS = [
    # DOMAIN\user — capture only the user; first part is non-capturing.
    re.compile(r"\b(?:[A-Za-z][A-Za-z0-9_.-]{0,30})\\([A-Za-z0-9_.-]{1,32})\b"),
    re.compile(r"(?:^|\s)user[:= ]\s*([A-Za-z][A-Za-z0-9_.-]{1,32})", re.IGNORECASE),
    re.compile(r"(?:^|/)Users/([A-Za-z0-9_.-]{1,32})/"),
    re.compile(r"(?:^|/)home/([a-z0-9_-]{1,32})/"),
    re.compile(r"\bSessionId[ =]?(\d+)", re.IGNORECASE),
]

# host — IPv4, IPv6 link-local, or Windows COMPUTERNAME-style tokens.
_HOST_PATTERNS = [
    re.compile(r"\b(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)\b"),
    re.compile(r"\b(?:fe80|fd[0-9a-f]{2})::[0-9a-f:]+\b", re.IGNORECASE),
]

# service / process — Windows .exe, systemd .service unit, LaunchAgent
# bundle id (com.<vendor>.<svc>).
_SERVICE_PATTERNS = [
    re.compile(r"\b([A-Za-z0-9_.\-]{1,40}\.exe)\b"),
    re.compile(r"\b([a-z0-9_.\-]{1,40}\.service)\b"),
    re.compile(r"\b(com(?:\.[A-Za-z0-9_-]+){1,5})\b"),
]

# data path — explicit /path/like or C:\path\like surfaces.
_DATA_PATH_PATTERNS = [
    re.compile(r"(?:^|\s)((?:/[A-Za-z0-9_.\-]+){2,}/?)"),
    re.compile(r"\b([A-Za-z]:\\(?:[A-Za-z0-9 _.\-]+\\?)+)"),
]


def _scan(text: str, patterns: list[re.Pattern]) -> set[str]:
    """Apply each pattern to text, return a flat set of group(1) hits."""
    out: set[str] = set()
    for pat in patterns:
        for m in pat.finditer(text):
            # If the pattern has groups, prefer group(1); otherwise use full match.
            try:
                hit = m.group(1)
            except IndexError:
                hit = m.group(0)
            if hit:
                out.add(hit.strip())
    return out


def _extract_from_finding(finding: dict) -> dict[str, set[str]]:
    """Pull entity hits from a single finding (claim + every pin's
    raw_excerpt + locator value).
    """
    text_parts: list[str] = [finding.get("claim", "") or ""]
    for pin in finding.get("pins", []) or []:
        text_parts.append(pin.get("raw_excerpt", "") or "")
        loc = pin.get("locator") or {}
        text_parts.append(str(loc.get("value", "") or ""))
        text_parts.append(pin.get("artifact", "") or "")
    blob = "\n".join(text_parts)
    return {
        "users": _scan(blob, _USER_PATTERNS),
        "hosts": _scan(blob, _HOST_PATTERNS),
        "services": _scan(blob, _SERVICE_PATTERNS),
        "data": _scan(blob, _DATA_PATH_PATTERNS),
    }


def _normalize_user(raw: str) -> str:
    """DOMAIN\\user → user; bare digits are session-id markers we keep
    prefixed so they don't collide with usernames."""
    raw = raw.strip()
    if not raw:
        return raw
    if "\\" in raw:
        return raw.split("\\", 1)[1]
    if raw.isdigit():
        return f"sessionid:{raw}"
    return raw


def compute_scope(state: IncidentState) -> dict[str, list[str]]:
    """Return the four scope buckets without mutating state.

    Exposed so tests + the exec report can compute scope from any state
    snapshot, including post-hoc against a finished case.
    """
    users: set[str] = set()
    hosts: set[str] = set()
    services: set[str] = set()
    data: set[str] = set()

    for f in state.get("_findings", []) or []:
        hits = _extract_from_finding(f)
        users.update(_normalize_user(u) for u in hits["users"])
        hosts.update(hits["hosts"])
        services.update(hits["services"])
        data.update(hits["data"])

    # Forensic artifacts contribute additional data paths.
    for art in state.get("forensic_artifacts", []) or []:
        # Artifact may be a dataclass or a serialized dict.
        path = getattr(art, "path", None) or (
            art.get("path") if isinstance(art, dict) else None
        )
        if path:
            data.add(str(path))

    return {
        "affected_hosts": sorted(h for h in hosts if h),
        "affected_users": sorted(u for u in users if u),
        "affected_services": sorted(s for s in services if s),
        "affected_data": sorted(d for d in data if d),
    }


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    scope = compute_scope(state)

    # Mutate state with the four scope fields. They live alongside the
    # existing public IncidentState entries and are preserved across
    # serialize/deserialize.
    state["affected_hosts"] = scope["affected_hosts"]
    state["affected_users"] = scope["affected_users"]
    state["affected_services"] = scope["affected_services"]
    state["affected_data"] = scope["affected_data"]

    # CSF subcategory: scoping satisfies RS.AN-01 (Notifications from detection
    # systems are investigated to determine the source and impact).
    csf_tags.mark_satisfied(state, csf_tags.RS_AN_01)

    state["_node_history"].append(NODE_NAME)

    # Visibility fix (#8): when there are findings but scope extracted zero
    # entities across all four buckets, the regex extraction missed
    # everything — likely because the findings used a non-standard phrasing
    # the patterns don't recognize. Surface that explicitly so the operator
    # can spot it before contain.py builds blast-radius scores against an
    # empty scope (which would silently pass the human_in_loop gate even on
    # high-severity cases).
    finding_n = len(state.get("_findings", []) or [])
    total_entities = (
        len(scope["affected_hosts"]) + len(scope["affected_users"])
        + len(scope["affected_services"]) + len(scope["affected_data"])
    )
    if finding_n > 0 and total_entities == 0:
        record_audit(
            state, event="scope_empty_despite_findings",
            data={"findings": finding_n,
                  "note": "scope regex extracted zero entities — blast-radius scoring will use defaults"},
        )

    record_audit(
        state, event="scope_complete",
        data={
            "hosts": len(scope["affected_hosts"]),
            "users": len(scope["affected_users"]),
            "services": len(scope["affected_services"]),
            "data": len(scope["affected_data"]),
            "findings_scanned": finding_n,
        },
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=(
            f"scope: {len(scope['affected_hosts'])} hosts, "
            f"{len(scope['affected_users'])} users, "
            f"{len(scope['affected_services'])} services, "
            f"{len(scope['affected_data'])} data paths"
        ),
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
