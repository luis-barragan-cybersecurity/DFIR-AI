"""Render an investigator-grade ATT&CK kill-chain timeline as Mermaid.

The orchestrator already classifies observed ATT&CK techniques and the max
kill-chain stage reached. Owners want to see the path: initial access →
execution → persistence → C2 → impact, not a flat list of T-IDs. This
module turns `state["attack_techniques"]` (with optional finding-pin
timestamps from `_findings`) into a Mermaid `flowchart LR` block that
renders inline on GitHub and inside any Markdown-to-PDF pipeline.

The renderer is fully deterministic (no LLM) so it can be unit-tested.
"""

from __future__ import annotations

import re
from typing import TypedDict

# ──────────────────────────────────────────────────────────────────────────
# Tactic ordering — Mermaid lays out left-to-right in the order we list.
# This is the Lockheed Martin Cyber Kill Chain superset of MITRE tactics.
# ──────────────────────────────────────────────────────────────────────────

KILL_CHAIN_ORDER: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact",
]


# ──────────────────────────────────────────────────────────────────────────
# ATT&CK technique → tactic. Keep ASCII-tight; the agent emits IDs in claim
# text and we receive them via state["attack_techniques"]. Sub-techniques
# (T####.NNN) inherit their parent's tactic when the parent is registered;
# the resolver tries the full ID first, then the bare T####.
# ──────────────────────────────────────────────────────────────────────────

TECHNIQUE_TO_TACTIC: dict[str, str] = {
    # Initial Access
    "T1078": "Initial Access",            # Valid Accounts
    "T1190": "Initial Access",            # Exploit Public-Facing App
    "T1133": "Initial Access",            # External Remote Services
    "T1566": "Initial Access",            # Phishing
    "T1091": "Initial Access",            # Replication Through Removable Media
    # Execution
    "T1059": "Execution",                 # Cmd/Scripting interpreter (parent)
    "T1059.001": "Execution",             # PowerShell
    "T1059.003": "Execution",             # Windows cmd
    "T1059.004": "Execution",             # Unix shell
    "T1204": "Execution",                 # User Execution
    "T1106": "Execution",                 # Native API
    # Persistence
    "T1547": "Persistence",
    "T1547.001": "Persistence",           # Run keys
    "T1543": "Persistence",
    "T1543.001": "Persistence",           # LaunchAgent
    "T1543.002": "Persistence",           # systemd
    "T1543.003": "Persistence",           # Windows service
    "T1053": "Persistence",
    "T1053.005": "Persistence",           # Scheduled Task
    "T1053.003": "Persistence",           # cron
    "T1037": "Persistence",               # Boot/Logon Init Scripts
    # Privilege Escalation
    "T1068": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    # Defense Evasion
    "T1027": "Defense Evasion",           # Obfuscated Files
    "T1070": "Defense Evasion",           # Indicator Removal
    "T1140": "Defense Evasion",           # Decode/Decrypt
    "T1112": "Defense Evasion",           # Modify Registry
    # Credential Access
    "T1003": "Credential Access",
    "T1003.001": "Credential Access",     # LSASS
    "T1110": "Credential Access",         # Brute Force
    "T1555": "Credential Access",         # Password store
    # Discovery
    "T1083": "Discovery",                 # File/dir discovery
    "T1057": "Discovery",                 # Process discovery
    "T1018": "Discovery",                 # Remote system discovery
    "T1082": "Discovery",                 # System info
    # Lateral Movement
    "T1021": "Lateral Movement",          # Remote services
    "T1021.001": "Lateral Movement",      # RDP
    "T1021.002": "Lateral Movement",      # SMB
    "T1021.004": "Lateral Movement",      # SSH
    # Collection
    "T1005": "Collection",                # Local data
    "T1056": "Collection",                # Input capture
    # Command & Control
    "T1071": "Command & Control",
    "T1071.001": "Command & Control",     # Web protocols
    "T1095": "Command & Control",         # Non-app layer
    "T1573": "Command & Control",         # Encrypted channel
    # Exfiltration
    "T1041": "Exfiltration",              # Over C2
    "T1567": "Exfiltration",              # Over web service
    # Impact
    "T1486": "Impact",                    # Data encrypted (ransomware)
    "T1490": "Impact",                    # Inhibit recovery
    "T1485": "Impact",                    # Data destruction
}


class TimelineEntry(TypedDict, total=False):
    technique_id: str
    tactic: str
    label: str  # display label for the Mermaid node


def tactic_for(technique_id: str) -> str | None:
    """Resolve a technique to its tactic. Tries full ID, then parent T####."""
    if technique_id in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[technique_id]
    parent = technique_id.split(".", 1)[0]
    return TECHNIQUE_TO_TACTIC.get(parent)


def order_techniques(technique_ids: list[str]) -> list[TimelineEntry]:
    """Group techniques by their tactic and return them in kill-chain order.

    Unknown techniques (not in TECHNIQUE_TO_TACTIC) land in a synthetic
    "Unmapped" tactic at the end so they're visible to the operator.
    """
    by_tactic: dict[str, list[str]] = {}
    for tid in technique_ids:
        tac = tactic_for(tid) or "Unmapped"
        by_tactic.setdefault(tac, []).append(tid)

    entries: list[TimelineEntry] = []
    for tactic in KILL_CHAIN_ORDER:
        for tid in by_tactic.get(tactic, []):
            entries.append({
                "technique_id": tid,
                "tactic": tactic,
                "label": f"{tactic}<br/>{tid}",
            })
    # Append unmapped at end if present.
    for tid in by_tactic.get("Unmapped", []):
        entries.append({
            "technique_id": tid,
            "tactic": "Unmapped",
            "label": f"Unmapped<br/>{tid}",
        })
    return entries


_ISO_RX = re.compile(r"\b(20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b")

# finding_id → section mapping. Keep small and readable; "Other" catches
# anything we haven't classified yet (no silent loss).
_SECTION_RULES: tuple[tuple[str, str], ...] = (
    ("rdp",          "RDP exposure"),
    ("listener",     "RDP exposure"),
    ("logon",        "Intrusion"),
    ("interactive",  "Intrusion"),
    ("burst",        "Intrusion"),
    ("device",       "Intrusion"),
    ("onedrive",     "Exfiltration surface"),
    ("cloud",        "Exfiltration surface"),
    ("projects",     "Exfiltration surface"),
    ("downloads",    "Exfiltration surface"),
    ("sharepoint",   "Exfiltration surface"),
    ("mrc",          "Acquisition"),
    ("capture",      "Acquisition"),
    ("os",           "Pre-incident"),
    ("gap",          "Gaps"),
    ("injection",    "Sanity"),
    ("shells",       "Sanity"),
)


# Known-acronym set — preserved in uppercase when humanizing finding IDs
# so labels like "RDP listener" don't degrade to "Rdp listener".
_ACRONYMS: frozenset[str] = frozenset({
    "rdp", "srl", "os", "ir", "mrc", "est", "edt", "utc", "pst", "pdt",
    "tcp", "udp", "smb", "rpc", "lan", "vpn", "rdp", "ssh", "ftp", "http",
    "https", "dns", "dhcp", "tls", "ssl", "api", "url", "uri", "vm",
    "iam", "att&ck", "lsass", "ntlm", "evtx", "lnk", "pf",
    "kitt",   # case-specific acronym we want kept uppercase
})


def humanize_finding_id(finding_id: str) -> str:
    """F-007-interactive-logon-marker → "Interactive logon marker".

    Strips the `F-NNN-` prefix, converts dashes to spaces, capitalises the
    first letter, and upper-cases recognised acronyms. Returns the raw
    `finding_id` if the shape doesn't match.
    """
    if not finding_id:
        return "(unnamed)"
    parts = finding_id.split("-", 2)
    if len(parts) == 3 and parts[0].upper() == "F" and parts[1].isdigit():
        words = parts[2].replace("-", " ").strip().split()
        if not words:
            return finding_id
        out_words: list[str] = []
        for i, w in enumerate(words):
            if w.lower() in _ACRONYMS:
                out_words.append(w.upper())
            elif i == 0:
                out_words.append(w[:1].upper() + w[1:])
            else:
                out_words.append(w)
        return " ".join(out_words)
    return finding_id


def section_for_finding(finding_id: str) -> str:
    """Bucket a finding into a coarse incident-phase section based on
    keyword match in its id. The label set is fixed so all callers stay
    consistent across the report and tests.
    """
    fid_lc = (finding_id or "").lower()
    for keyword, section in _SECTION_RULES:
        if keyword in fid_lc:
            return section
    return "Other"


def extract_time_anchors(findings: list[dict]) -> list[tuple[str, str, str, str]]:
    """Pull `(start_iso, end_iso_or_blank, finding_id, section)` tuples.

    For each finding:
      - Scan `claim` for ISO-8601 UTC stamps.
      - First stamp = start; second (if present) = end. Subsequent stamps
        are dropped — Gantt tasks are start+end, not arbitrary multi-point.
      - Use the humanized `finding_id` (NOT surrounding text) as the
        label so the chart is readable instead of looking like a torn page.
      - Section is derived from the finding_id keyword bucket.

    Sorted ascending by start time; ties broken by finding_id.
    """
    out: list[tuple[str, str, str, str]] = []
    for f in findings:
        claim = f.get("claim") or ""
        fid = f.get("finding_id") or "F-?"
        stamps = [m.group(1) for m in _ISO_RX.finditer(claim)]
        if not stamps:
            continue
        start = stamps[0]
        end = stamps[1] if len(stamps) > 1 else ""
        out.append((start, end, fid, section_for_finding(fid)))
    out.sort(key=lambda t: (t[0], t[2]))
    return out


def render_gantt(
    anchors: list[tuple[str, str, str, str]],
    *,
    title: str = "Incident Timeline",
    default_duration_min: int = 1,
) -> str:
    """Build a Mermaid `gantt` block from time anchors.

    Each anchor renders as one task. If the anchor carries an `end_iso`,
    the task spans `start..end`; otherwise it gets `default_duration_min`
    minutes so the bar is visible on the axis. Tasks are grouped under
    their section header in fixed phase order so the chart reads
    Pre-incident → RDP → Intrusion → Exfil → Acquisition top-down.

    Backwards-compat: if anchors are 3-tuples (legacy form before sections
    were added), each is upgraded to a 4-tuple with section "Events".
    """
    if not anchors:
        return (
            "```mermaid\n"
            "gantt\n"
            f"    title {title}\n"
            "    dateFormat YYYY-MM-DDTHH:mm:ssZ\n"
            "    section Events\n"
            "    No timestamped events found :placeholder, 2020-01-01T00:00:00Z, 1m\n"
            "```\n"
        )

    # Upgrade legacy 3-tuples for back-compat.
    upgraded: list[tuple[str, str, str, str]] = []
    for a in anchors:
        if len(a) == 3:
            ts, _label_unused, fid = a
            upgraded.append((ts, "", fid, section_for_finding(fid)))
        else:
            upgraded.append(a)

    # Stable section order — phases that don't appear are skipped.
    phase_order = (
        "Pre-incident", "RDP exposure", "Intrusion",
        "Exfiltration surface", "Acquisition", "Gaps", "Sanity", "Other",
    )

    lines = [
        "```mermaid",
        "gantt",
        f"    title {title}",
        "    dateFormat YYYY-MM-DDTHH:mm:ssZ",
        "    axisFormat %m-%d %H:%M",
    ]

    by_section: dict[str, list[tuple[str, str, str, str]]] = {}
    for ts, end, fid, section in upgraded:
        by_section.setdefault(section, []).append((ts, end, fid, section))

    for phase in phase_order:
        rows = by_section.get(phase, [])
        if not rows:
            continue
        lines.append(f"    section {phase}")
        for ts, end, fid, _section in rows:
            label = humanize_finding_id(fid)
            # Mermaid uses `:` as the task separator, so any colon inside
            # the label breaks the parser; rewrite to en-dash.
            label = label.replace(":", "–")
            stable_id = fid.replace(" ", "_")
            if end and end > ts:
                lines.append(f"    {label} :{stable_id}, {ts}, {end}")
            else:
                lines.append(
                    f"    {label} :{stable_id}, {ts}, {default_duration_min}m",
                )

    lines.append("```")
    return "\n".join(lines) + "\n"


def render_mermaid(technique_ids: list[str]) -> str:
    """Build a `flowchart LR` Mermaid block from a list of ATT&CK IDs.

    Returns a self-contained block including the fenced ```mermaid wrapper.
    Renders inline on GitHub markdown and inside Mermaid-aware PDF
    pipelines; for environments without Mermaid support the raw text is
    still readable.

    Empty input returns an explicit "(no techniques observed)" placeholder
    so the report never silently swallows a degenerate case.
    """
    entries = order_techniques(technique_ids)
    if not entries:
        return (
            "```mermaid\n"
            "flowchart LR\n"
            "    NONE[\"No ATT&amp;CK techniques observed\"]\n"
            "```\n"
        )

    lines: list[str] = ["```mermaid", "flowchart LR"]
    # Node declarations (use `id["label"]` for Mermaid-safe escaping).
    for idx, e in enumerate(entries):
        node_id = f"N{idx}"
        # Escape any double-quotes inside label.
        safe = e["label"].replace('"', '&quot;')
        lines.append(f'    {node_id}["{safe}"]')
    # Edges in observation order.
    for idx in range(len(entries) - 1):
        lines.append(f"    N{idx} --> N{idx + 1}")
    lines.append("```")
    return "\n".join(lines) + "\n"
