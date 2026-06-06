#!/usr/bin/env python3
"""Generate an executive incident report from a finished case.

Reads `cases/<id>/output/findings.json` + `state.json` (when present) and
emits a single Markdown file aimed at incident owners — the people who
have to decide *what to do in the next 4 hours*.

Output layout (always in this order):

    1. One-page Executive Summary
       - Severity, scope counts, top-3 actions for the next 4 hours
       - Plain-English "what broke", "how bad", "what we must do"
    2. Attack Timeline (Mermaid kill-chain)
    3. Risk Reduction Score (D3FEND coverage / observed techniques)
    4. Technical Appendix
       - Per-finding table with confidence rationale
       - Containment commands grouped by host platform
       - Audit log digest (event counts)
    5. Forensic Evidence Pins (every claim's pin block)

Deterministic — no LLM call. Reuses the project's pure-Python building
blocks: containment_commands, attack_timeline, scope.compute_scope.

Usage:
    python3 scripts/exec-report.py <case-dir>
    # writes <case-dir>/output/exec-report.md
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

# Make orchestrator importable when run from repo root via venv python.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "orchestrator" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "mcp-server" / "src"))

from mh_orchestrator import attack_timeline as at  # noqa: E402
from mh_orchestrator import containment_commands as cc  # noqa: E402
from mh_orchestrator.nodes import scope as scope_mod  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return default


def _audit_event_counts(audit_path: Path) -> Counter:
    counts: Counter = Counter()
    if not audit_path.exists():
        return counts
    for line in audit_path.read_text().splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        e = ev.get("event")
        if e:
            counts[e] += 1
    return counts


def _compute_risk_reduction(findings: list[dict], state: dict) -> dict:
    """Risk-reduction score = covered_techniques / observed_techniques.

    "Covered" = we have at least one platform-specific containment command
    in containment_commands.json keyed to the technique. The score is the
    fraction of observed techniques for which we've translated *something*
    runnable. Owners read this as "you're closing N% of the entry points
    we saw."
    """
    observed: set[str] = set()
    for f in findings:
        for tid in f.get("mitre_attck", []) or []:
            observed.add(tid)
    # Also pull from state's attack_techniques if present.
    for tid in state.get("attack_techniques") or []:
        observed.add(tid)

    if not observed:
        return {
            "observed_techniques": 0,
            "covered_techniques": 0,
            "uncovered_techniques": [],
            "score_percent": None,
            "note": "no MITRE ATT&CK techniques observed in findings",
        }

    coverage = cc.coverage_for(sorted(observed))
    covered = sum(1 for v in coverage.values() if v)
    uncovered = sorted(tid for tid, ok in coverage.items() if not ok)
    return {
        "observed_techniques": len(observed),
        "covered_techniques": covered,
        "uncovered_techniques": uncovered,
        "score_percent": round(100 * covered / len(observed), 1),
        "note": (
            f"{covered}/{len(observed)} observed ATT&CK techniques have at "
            "least one runnable containment command staged"
        ),
    }


def _top_actions_next_4h(state: dict, findings: list[dict]) -> list[dict]:
    """The three highest-priority actions an owner should execute in the
    first four hours. Blends scope (must-isolate hosts) + per-technique
    commands when available + default isolate/snapshot/rotate.
    """
    detected_os = state.get("_detected_os") or "unknown"
    actions: list[dict] = []

    # 1. Snapshot evidence first — read-only, never destructive.
    snap = cc.commands_for_default_action("snapshot_evidence", detected_os=detected_os)
    if snap:
        actions.append({
            "rank": 1,
            "verb": snap["verb"],
            "description": snap["description"],
            "platform": snap["platform"],
            "command": snap["command"],
            "reversibility": snap["reversibility"],
        })

    # 2. Isolate the affected hosts (or the host this evidence came from).
    iso = cc.commands_for_default_action("isolate_host", detected_os=detected_os)
    if iso:
        affected = state.get("affected_hosts") or []
        actions.append({
            "rank": 2,
            "verb": iso["verb"],
            "description": (
                iso["description"] +
                (f" — affected hosts: {', '.join(affected)}" if affected else "")
            ),
            "platform": iso["platform"],
            "command": iso["command"],
            "reversibility": iso["reversibility"],
        })

    # 3. Rotate credentials if there are affected users.
    rot = cc.commands_for_default_action("rotate_credentials", detected_os=detected_os)
    if rot:
        affected_users = state.get("affected_users") or []
        actions.append({
            "rank": 3,
            "verb": rot["verb"],
            "description": (
                rot["description"] +
                (f" — affected users: {', '.join(affected_users)}"
                 if affected_users else "")
            ),
            "platform": rot["platform"],
            "command": rot["command"],
            "reversibility": rot["reversibility"],
        })

    return actions


def _per_finding_table_row(f: dict) -> str:
    fid = f.get("finding_id", "?")
    confidence = f.get("confidence", "?")
    rationale = (f.get("confidence_rationale") or "(legacy finding — no rationale)")
    if len(rationale) > 140:
        rationale = rationale[:137] + "..."
    claim = f.get("claim") or ""
    if len(claim) > 200:
        claim = claim[:197] + "..."
    techniques = ", ".join(f.get("mitre_attck", []) or []) or "—"
    return f"| {fid} | {confidence} | {claim} | {techniques} | {rationale} |"


# ──────────────────────────────────────────────────────────────────────────
# Executive Summary — leadership-facing, deterministic
# ──────────────────────────────────────────────────────────────────────────
#
# Audience: CEO, COO, CFO, CISO, CLO/General Counsel, CMO, CHRO, board
# directors, and the corresponding D-level (VP-Eng, VP-Legal, VP-Comms,
# Head of HR). They do not read forensic narrative; they read decisions
# and risks. This section gives each role one paragraph in plain English.
#
# We map MITRE ATT&CK technique IDs to the leadership *concern* each
# raises, so the per-role text is grounded in the actual findings rather
# than boilerplate. Mapping is intentionally over-inclusive: techniques
# touch multiple roles (e.g. credential dumping touches CISO + CLO + CHRO).

# concern_id → human-readable concern label
_CONCERNS: dict[str, str] = {
    "credential_compromise":  "compromised user credentials",
    "data_exfil_cloud":       "data exfiltration via cloud sync",
    "data_exfil_web":         "data exfiltration via webmail / file-share upload",
    "data_exfil_physical":    "data exfiltration via USB / removable media",
    "internet_exposed":       "internet-exposed remote-access service",
    "valid_account_abuse":    "unauthorized use of a valid employee account",
    "remote_access_intrusion":"hands-on remote access by an external party",
    "ransomware_destruction": "destructive ransomware / wiper activity",
    "lateral_movement":       "lateral movement across multiple systems",
    "ip_collection":          "collection of intellectual-property documents",
    "persistence_implant":    "implanted persistence so attacker can return",
    "command_and_control":    "active command-and-control communication",
}

# ATT&CK technique → concerns. Sub-techniques inherit their parent's
# concerns; the matcher tries the full ID first, then the bare T#### .
_TECHNIQUE_CONCERNS: dict[str, tuple[str, ...]] = {
    "T1003":   ("credential_compromise",),
    "T1003.001": ("credential_compromise",),
    "T1078":   ("valid_account_abuse",),
    "T1133":   ("internet_exposed", "remote_access_intrusion"),
    "T1021":   ("lateral_movement", "remote_access_intrusion"),
    "T1021.001": ("lateral_movement", "remote_access_intrusion"),
    "T1021.002": ("lateral_movement",),
    "T1021.004": ("lateral_movement",),
    "T1567":   ("data_exfil_cloud",),
    "T1567.002": ("data_exfil_cloud",),
    "T1041":   ("command_and_control", "data_exfil_cloud"),
    "T1052":   ("data_exfil_physical",),
    "T1052.001": ("data_exfil_physical",),
    "T1530":   ("data_exfil_cloud", "ip_collection"),
    "T1213":   ("ip_collection",),
    "T1213.002": ("ip_collection",),
    "T1486":   ("ransomware_destruction",),
    "T1485":   ("ransomware_destruction",),
    "T1490":   ("ransomware_destruction",),
    "T1547":   ("persistence_implant",),
    "T1547.001": ("persistence_implant",),
    "T1543":   ("persistence_implant",),
    "T1543.001": ("persistence_implant",),
    "T1543.002": ("persistence_implant",),
    "T1543.003": ("persistence_implant",),
    "T1053":   ("persistence_implant",),
    "T1053.003": ("persistence_implant",),
    "T1053.005": ("persistence_implant",),
    "T1071":   ("command_and_control",),
    "T1071.001": ("command_and_control",),
}

# Role → concerns it cares about. This is the matrix that makes the
# per-role takeaway sections meaningful.
_ROLE_CONCERNS: dict[str, set[str]] = {
    "CEO": {
        "remote_access_intrusion", "ip_collection", "data_exfil_cloud",
        "data_exfil_web", "ransomware_destruction",
    },
    "COO": {
        "ransomware_destruction", "remote_access_intrusion",
        "lateral_movement", "persistence_implant",
    },
    "CFO": {
        "data_exfil_cloud", "data_exfil_web", "ransomware_destruction",
        "ip_collection",
    },
    "CISO": {
        "credential_compromise", "internet_exposed", "valid_account_abuse",
        "lateral_movement", "persistence_implant", "command_and_control",
        "remote_access_intrusion",
    },
    "Legal / General Counsel": {
        "data_exfil_cloud", "data_exfil_web", "data_exfil_physical",
        "credential_compromise", "ip_collection", "remote_access_intrusion",
    },
    "CMO / Comms": {
        "data_exfil_cloud", "data_exfil_web", "ransomware_destruction",
        "credential_compromise",
    },
    "CHRO / HR": {
        "valid_account_abuse", "credential_compromise",
    },
}

# Per-role one-sentence takeaway templates per concern. Keys: (role, concern).
# Format strings receive the named scope counts via .format(...).
_ROLE_TAKEAWAYS: dict[tuple[str, str], str] = {
    # CEO
    ("CEO", "remote_access_intrusion"): "An external party operated our system hands-on; treat this as a confirmed breach until eradication is verified.",
    ("CEO", "ip_collection"): "{ip_count} intellectual-property document(s) were exposed{projects_clause}; this is the asset at risk, not a hypothetical.",
    ("CEO", "data_exfil_cloud"): "Data left the perimeter via cloud sync; assume the attacker has copies regardless of what we do now.",
    ("CEO", "ransomware_destruction"): "Operational continuity is at stake; align with COO on recovery posture.",

    # COO
    ("COO", "remote_access_intrusion"): "Affected host(s) must be isolated immediately; expect 4-12 hours per host to rebuild from clean image.",
    ("COO", "lateral_movement"): "Treat any system the affected account touched as suspect; widen the isolation perimeter.",
    ("COO", "persistence_implant"): "Rebuilding without removing the persistence vector returns us to compromise; do not skip the eradication step.",
    ("COO", "ransomware_destruction"): "Validate backups before any restore; restore-then-reinfect is the worst outcome.",

    # CFO
    ("CFO", "ip_collection"): "Financial exposure is keyed to the value of the exposed IP, not just incident response cost; engage Legal on disclosure obligations.",
    ("CFO", "data_exfil_cloud"): "Anticipate regulatory filing costs (GDPR/CCPA/SEC depending on data class) on top of IR cost.",
    ("CFO", "data_exfil_web"): "Plan for incident-response retainer plus possible regulatory penalties; ballpark IR alone runs $200k-$500k for an event of this scale.",
    ("CFO", "ransomware_destruction"): "Cyber-insurance carrier must be notified within hours, not days; failure to notify can void coverage.",

    # CISO
    ("CISO", "credential_compromise"): "Rotate all credentials touched by the affected account, including service accounts the user could reach.",
    ("CISO", "internet_exposed"): "The exposed service was internet-reachable; close the surface and audit every other internet-reachable service for the same misconfiguration.",
    ("CISO", "valid_account_abuse"): "MFA / conditional-access policy gaps allowed the account to be used; review and harden.",
    ("CISO", "lateral_movement"): "Network segmentation gaps need urgent review; assume east-west movement was possible to anywhere the account could authenticate.",
    ("CISO", "persistence_implant"): "Endpoint detection must hunt for persistence artifacts named in the technical appendix before host return-to-service.",
    ("CISO", "command_and_control"): "Block the named C2 destinations at egress and submit IOC to threat-intel sharing partners.",
    ("CISO", "remote_access_intrusion"): "This was hands-on-keyboard, not automated; assume the attacker tailored their playbook to our environment.",

    # Legal
    ("Legal / General Counsel", "data_exfil_cloud"): "Probable data-disclosure event; evaluate breach-notification triggers under GDPR (Art. 33), HIPAA (45 CFR 164.408), CCPA (Civ. Code §1798.82), and SEC Reg S-K Item 1.05 if material.",
    ("Legal / General Counsel", "data_exfil_web"): "Webmail/file-share upload presumes personal-cloud transfer; engage privilege early on the breach-counsel decision.",
    ("Legal / General Counsel", "data_exfil_physical"): "USB/removable-media exfil raises insider-threat concerns; preserve chain-of-custody on the affected host now.",
    ("Legal / General Counsel", "credential_compromise"): "Account-hijack obligations vary by jurisdiction and data class; pull the data inventory before drafting notice.",
    ("Legal / General Counsel", "ip_collection"): "If the exposed IP includes trade secrets, document the misappropriation timeline now to preserve future remedies (DTSA / state UTSA).",
    ("Legal / General Counsel", "remote_access_intrusion"): "Law-enforcement referral decision (FBI IC3 / local) should be made within 24-48 hours; once made, it limits some downstream choices.",

    # CMO
    ("CMO / Comms", "data_exfil_cloud"): "Prepare a customer-comms holding statement; do not commit to numbers until the data inventory is final.",
    ("CMO / Comms", "data_exfil_web"): "If exposed data includes customer information, regulatory clock starts on first reasonable belief, not on completion of investigation.",
    ("CMO / Comms", "ransomware_destruction"): "Operational impact may surface publicly via service outages before we choose to disclose; pre-position the comms.",
    ("CMO / Comms", "credential_compromise"): "If passwords are reset broadly, prepare an internal explanation; staff will assume the worst absent guidance.",

    # CHRO
    ("CHRO / HR", "valid_account_abuse"): "Affected employee is a witness, not a suspect, until proven otherwise; coordinate with Legal on interview posture.",
    ("CHRO / HR", "credential_compromise"): "Any employee whose credentials are rotated as part of containment needs explicit, non-blaming communication from HR within 24 hours.",
}

# What we're asking of each role this week — concrete, actionable.
_ROLE_ASKS: dict[str, str] = {
    "CEO": "Approve the containment posture and decide on customer-disclosure timing.",
    "COO": "Authorize host isolation and confirm acceptable downtime budget for rebuild.",
    "CFO": "Notify cyber-insurance carrier; pre-approve IR retainer ceiling.",
    "CISO": "Drive the technical containment + hunt; close the exposed service today.",
    "Legal / General Counsel": "Run the privileged-counsel decision and the breach-notification analysis.",
    "CMO / Comms": "Pre-position internal + customer holding statements; do not publish without Legal sign-off.",
    "CHRO / HR": "Coordinate with Legal on employee comms; ensure affected employee is supported, not isolated.",
}


def _concerns_from_techniques(attack_ids: list[str]) -> set[str]:
    """Map observed ATT&CK IDs to the deduped set of leadership concerns."""
    seen: set[str] = set()
    for tid in attack_ids:
        for cid in _TECHNIQUE_CONCERNS.get(tid, ()):
            seen.add(cid)
        # Sub-technique fallback to parent T####
        if "." in tid:
            parent = tid.split(".", 1)[0]
            for cid in _TECHNIQUE_CONCERNS.get(parent, ()):
                seen.add(cid)
    return seen


def _executive_paragraph(state: dict, scope: dict, concerns: set[str]) -> str:
    """One paragraph in plain English. No MITRE codes, no PIDs."""
    severity = state.get("severity") or "unknown"
    detected_os = state.get("_detected_os") or "unknown"
    hosts = len(scope.get("affected_hosts") or [])
    users = len(scope.get("affected_users") or [])
    data = len(scope.get("affected_data") or [])

    severity_phrase = {
        "high": "a HIGH-severity",
        "critical": "a CRITICAL-severity",
        "medium": "a medium-severity",
        "low": "a low-severity",
    }.get(severity.lower(), "an")

    # Lead with what happened in plain English.
    what = []
    if "remote_access_intrusion" in concerns:
        what.append("an external party operated one of our systems hands-on")
    if "data_exfil_cloud" in concerns or "data_exfil_web" in concerns:
        what.append("data left the perimeter through cloud / web channels")
    if "ip_collection" in concerns:
        what.append("intellectual-property documents were collected for exfiltration")
    if "credential_compromise" in concerns:
        what.append("user credentials were exposed")
    if "ransomware_destruction" in concerns:
        what.append("destructive activity was attempted")
    if "persistence_implant" in concerns:
        what.append("persistence was implanted so the attacker can return")
    if not what:
        what.append("suspicious activity was identified")
    summary = " · ".join(what)

    return (
        f"This is {severity_phrase} incident on {detected_os} affecting "
        f"{hosts} host(s), {users} user account(s), and {data} data location(s). "
        f"In plain terms: {summary}. The technical appendix below documents every "
        "claim with a tool and an evidence excerpt; this section translates "
        "those findings into the decisions each leader needs to make in the next "
        "24-48 hours."
    )


def _role_takeaway(role: str, role_concerns: set[str]) -> str:
    """Concatenate the per-(role, concern) takeaway sentences that apply."""
    lines: list[str] = []
    # Stable order: by concern key
    for concern in sorted(role_concerns):
        text = _ROLE_TAKEAWAYS.get((role, concern))
        if text:
            lines.append(text)
    if not lines:
        return "No role-specific actions identified for this incident class."
    return " ".join(lines)


def _render_executive_summary(state: dict, findings: list[dict], scope: dict) -> list[str]:
    """Return Markdown lines for the Executive Summary section.

    Deterministic — no LLM call. Reads attack_techniques from state +
    findings, maps to leadership concerns, emits one paragraph + a
    per-role table. Designed to be the FIRST thing C/D-level readers
    see when they open the report or click the Exec tab.
    """
    techniques = sorted(set(state.get("attack_techniques") or []) |
                        {t for f in findings for t in (f.get("mitre_attck") or [])})
    concerns = _concerns_from_techniques(techniques)
    # Augment with derived signals not always present as ATT&CK IDs.
    services = state.get("affected_services") or []
    if any("OneDrive" in s or "GoogleDrive" in s or "Dropbox" in s or "iCloud" in s
           for s in services):
        concerns.add("data_exfil_cloud")
    if scope.get("affected_data"):
        concerns.add("ip_collection")

    project_count = sum(
        1 for d in (scope.get("affected_data") or [])
        if "Projects" in d or "Project" in d or "Research" in d
    )
    ip_count = len(scope.get("affected_data") or [])
    # Only mention "across N projects" if we actually identified projects.
    # Saying "across 0 projects" reads as a template bug to leadership.
    projects_clause = f" across {project_count} project(s)" if project_count else ""

    lines: list[str] = []
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        "_Plain English. No MITRE codes, no PIDs, no jargon. Aimed at C/D-level "
        "leadership: CEO, COO, CFO, CISO, Legal/General Counsel, CMO/Comms, "
        "CHRO/HR, and the board. The technical detail starts in the next section._"
    )
    lines.append("")
    lines.append(_executive_paragraph(state, scope, concerns))
    lines.append("")

    if not concerns:
        lines.append("_No leadership-actionable concerns triggered by the observed evidence._")
        lines.append("")
        return lines

    lines.append("### What this means for each leader")
    lines.append("")
    lines.append("| Role | What you need to know | What we're asking of you |")
    lines.append("|---|---|---|")
    for role, role_cares in _ROLE_CONCERNS.items():
        relevant = concerns & role_cares
        if not relevant:
            continue
        takeaway = _role_takeaway(role, relevant).format(
            ip_count=ip_count,
            project_count=project_count,
            projects_clause=projects_clause,
        )
        ask = _ROLE_ASKS.get(role, "")
        # Markdown table cells can't contain raw newlines — use <br> if needed.
        lines.append(f"| **{role}** | {takeaway} | {ask} |")
    lines.append("")

    # Top-3 things the entire leadership team should agree on. Header
    # counts what we actually render, not a hardcoded "three" — readers
    # noticed when the body had 2 items under a "three calls" header.
    calls: list[str] = []
    if "remote_access_intrusion" in concerns or "lateral_movement" in concerns:
        calls.append("**Containment posture** — isolate now vs. observe to learn the attacker's intent (CISO + COO).")
    if "data_exfil_cloud" in concerns or "data_exfil_web" in concerns or "ip_collection" in concerns:
        calls.append("**Disclosure timing** — when and to whom (Legal + CMO + CEO).")
    if "credential_compromise" in concerns or "valid_account_abuse" in concerns:
        calls.append("**Credential reset scope** — single account vs. broad rotation (CISO + CHRO).")
    if "ransomware_destruction" in concerns:
        calls.append("**Restore-vs-rebuild** — restore from backup vs. clean rebuild (COO + CFO).")
    if "persistence_implant" in concerns:
        calls.append("**Eradication threshold** — how confident must we be before declaring the attacker out (CISO + COO).")
    if not calls:
        calls.append("**Containment + comms posture** — alignment between technical containment and public stance.")
    rendered_calls = calls[:3]
    n_word = {1: "one", 2: "two", 3: "three"}.get(len(rendered_calls), str(len(rendered_calls)))
    lines.append(f"### The {n_word} call{'s' if len(rendered_calls) != 1 else ''} leadership has to make this week")
    lines.append("")
    for i, c in enumerate(rendered_calls, start=1):
        lines.append(f"{i}. {c}")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


_SCOPE_FIELDS = (
    "affected_hosts", "affected_users", "affected_services",
    "affected_data", "egress_destinations",
)


def _scope_summary(state: dict, findings: list[dict]) -> dict:
    """Prefer the orchestrator's recorded scope. Synthesize only when
    scope was *never computed* (every bucket is None), not when scope ran
    and produced empty lists.

    The distinction matters: `affected_hosts = None` means "scope node
    didn't run" → safe to regex-synthesize. `affected_hosts = []` means
    "scope ran and found nothing" → we MUST NOT invent hosts from
    free-text scans, because doing so put a non-existent IP
    ('192.168.151.1') into a C-suite report.
    """
    # If *any* scope field is explicitly populated (not None), trust state
    # entirely for *all* fields. Mixing recorded + synthesized leaks
    # regex artifacts back into a case the orchestrator already scoped.
    if any(state.get(k) is not None for k in _SCOPE_FIELDS):
        out = {k: list(state.get(k) or []) for k in _SCOPE_FIELDS}
        out["_source"] = "orchestrator"
        return out

    # Synthesize from findings using the same extractor the scope node uses.
    synthetic_state = {"_findings": findings, "forensic_artifacts": []}
    out = scope_mod.compute_scope(synthetic_state)  # type: ignore[arg-type]
    out["_source"] = "synthesized"
    return out


# ──────────────────────────────────────────────────────────────────────────
# Renderer
# ──────────────────────────────────────────────────────────────────────────


def render(case_dir: Path) -> str:
    findings = _load_json(case_dir / "output" / "findings.json", [])
    state = _load_json(case_dir / "output" / "state.json", {})
    audit_counts = _audit_event_counts(case_dir / "output" / "audit.jsonl")
    case_id = case_dir.name
    detected_os = state.get("_detected_os") or "unknown"
    severity = state.get("severity") or "unknown"
    scope_data = _scope_summary(state, findings)
    risk = _compute_risk_reduction(findings, state)
    techniques = sorted(set(state.get("attack_techniques") or []) |
                        {t for f in findings for t in (f.get("mitre_attck") or [])})
    actions = _top_actions_next_4h(state, findings)

    lines: list[str] = []

    # ─── Header ──────────────────────────────────────────────────────────
    lines.append(f"# Executive Incident Report — `{case_id}`")
    lines.append("")
    lines.append(
        f"_Generated {datetime.now(UTC).isoformat(timespec='seconds')} — no LLM, "
        "no tokens. Reads `findings.json` + `state.json` + `audit.jsonl`._"
    )
    lines.append("")

    # ─── 0. Executive Summary (C/D-level, plain English) ─────────────────
    lines.extend(_render_executive_summary(state, findings, scope_data))

    # ─── 1. At a Glance (numeric snapshot for the responder) ─────────────
    lines.append("## At a Glance")
    lines.append("")
    lines.append(f"- **Severity**: {severity}")
    lines.append(f"- **Detected OS**: {detected_os}")
    lines.append(f"- **Findings**: {len(findings)} pinned · "
                 f"{sum(1 for f in findings if f.get('confidence') == 'confirmed')} confirmed · "
                 f"{sum(1 for f in findings if f.get('confidence') == 'unknown')} explicit gaps")
    lines.append(f"- **Affected hosts**: "
                 f"{len(scope_data['affected_hosts'])} ({', '.join(scope_data['affected_hosts'][:5]) or '—'})")
    lines.append(f"- **Affected users**: "
                 f"{len(scope_data['affected_users'])} ({', '.join(scope_data['affected_users'][:5]) or '—'})")
    lines.append(f"- **Affected services / processes**: "
                 f"{len(scope_data['affected_services'])}")
    egress = scope_data.get("egress_destinations") or []
    if egress:
        lines.append(f"- **Egress destinations** (where data went / C2 called): "
                     f"{len(egress)} ({', '.join(egress[:5])})")
    # ATT&CK: show all techniques up to 12, otherwise disclose the truncation
    # so readers don't assume the displayed 6 are the full set.
    if len(techniques) <= 12:
        attck_render = ", ".join(techniques) or "—"
        lines.append(f"- **ATT&CK techniques observed**: {len(techniques)} ({attck_render})")
    else:
        attck_render = ", ".join(techniques[:6])
        lines.append(f"- **ATT&CK techniques observed**: {len(techniques)} "
                     f"(showing 6 of {len(techniques)}: {attck_render}; full list in Technical Appendix)")
    # When scope was synthesized from regex rather than read from the
    # orchestrator, label it so leadership doesn't treat fuzzy regex hits
    # as forensic-grade attribution.
    if scope_data.get("_source") == "synthesized":
        lines.append("- _Scope numbers regex-inferred from findings text — "
                     "the scope node didn't run on this case. Treat host/data "
                     "counts as indicative, not authoritative._")
    if risk["score_percent"] is not None:
        lines.append(f"- **Risk reduction score**: {risk['score_percent']}% "
                     f"({risk['note']})")
    else:
        lines.append(f"- **Risk reduction score**: n/a — {risk['note']}")
    lines.append("")

    # ─── 2. Top-3 Actions Next 4 Hours ───────────────────────────────────
    lines.append("## What To Do in the Next 4 Hours")
    lines.append("")
    if not actions:
        lines.append(f"_(no platform-specific commands available for `{detected_os}`)_")
        lines.append("")
    else:
        for a in actions:
            lines.append(f"### {a['rank']}. {a['verb']} ({a['platform']})")
            lines.append("")
            lines.append(f"_{a['description']}_")
            lines.append("")
            lines.append("```")
            lines.append(a["command"])
            lines.append("```")
            lines.append(f"_Reversibility: **{a['reversibility']}**. "
                         "All commands are advisory — operator must review before execution._")
            lines.append("")

    # ─── 3. Attack Timeline ──────────────────────────────────────────────
    lines.append("## Attack Timeline")
    lines.append("")
    lines.append("### Kill-chain flow")
    lines.append("")
    lines.append(at.render_mermaid(techniques))

    # Time-anchored Gantt — driven by ISO-8601 stamps inside finding claims.
    # This is the chart owners want most: wall-clock x-axis with every
    # observed incident event placed in real time order.
    anchors = at.extract_time_anchors(findings)
    if anchors:
        lines.append("### Timeline (wall-clock from finding claims)")
        lines.append("")
        lines.append(at.render_gantt(
            anchors,
            title=f"{state.get('incident_id') or case_dir.name} — Incident Timeline",
        ))

    # ─── 4. Risk Reduction Detail ────────────────────────────────────────
    lines.append("## Risk Reduction Detail")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| ATT&CK techniques observed | {risk['observed_techniques']} |")
    lines.append(f"| Techniques with runnable containment | {risk['covered_techniques']} |")
    lines.append(f"| Techniques without runnable containment | "
                 f"{len(risk['uncovered_techniques'])} "
                 f"({', '.join(risk['uncovered_techniques']) if risk['uncovered_techniques'] else '—'}) |")
    if risk["score_percent"] is not None:
        lines.append(f"| **Risk reduction score** | **{risk['score_percent']}%** |")
    lines.append("")

    # ─── 5. Technical Appendix ───────────────────────────────────────────
    lines.append("## Technical Appendix")
    lines.append("")

    lines.append("### Findings (pinned)")
    lines.append("")
    if not findings:
        lines.append("_(no findings recorded)_")
    else:
        lines.append("| ID | Confidence | Claim | ATT&CK | Rationale |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            lines.append(_per_finding_table_row(f))
    lines.append("")

    # Per-technique containment commands by platform
    lines.append("### Per-Technique Containment Commands")
    lines.append("")
    if not techniques:
        lines.append("_(no techniques observed; nothing to map)_")
    else:
        cmds = cc.commands_for_techniques(techniques, detected_os=detected_os)
        if not cmds:
            lines.append(f"_(no `{detected_os}`-specific commands available "
                         f"for the {len(techniques)} observed techniques)_")
        else:
            lines.append(f"Platform: **{detected_os}**")
            lines.append("")
            for c in cmds:
                lines.append(f"#### {c['technique_id']} — {c['verb']}")
                lines.append("")
                lines.append(f"_{c['description']}_")
                lines.append("")
                lines.append("```")
                lines.append(c["command"])
                lines.append("```")
                if c["placeholder_hints"]:
                    lines.append("Operator must replace: "
                                 f"`{', '.join(c['placeholder_hints'])}`")
                lines.append(f"Reversibility: **{c['reversibility']}**")
                lines.append("")

    # Audit log digest
    lines.append("### Audit Log Digest")
    lines.append("")
    if not audit_counts:
        lines.append("_(no audit events found)_")
    else:
        lines.append("| Event | Count |")
        lines.append("|---|---|")
        for event, n in audit_counts.most_common():
            lines.append(f"| `{event}` | {n} |")
    lines.append("")

    # ─── Footer ──────────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append("_This report is administrative-only. MemoryHound never executes "
                 "containment or remediation actions — every command above is "
                 "advisory and must be reviewed by an operator before execution._")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: exec-report.py <case-dir>", file=sys.stderr)
        return 2
    case_dir = Path(argv[1])
    if not case_dir.exists():
        print(f"Case not found: {case_dir}", file=sys.stderr)
        return 1
    out = render(case_dir)
    out_path = case_dir / "output" / "exec-report.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(out)
    print(f"Wrote {out_path} ({len(out)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
