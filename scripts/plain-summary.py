#!/usr/bin/env python3
"""Generate a plain-English summary from a case's findings.json + chain log.

Deterministic. No LLM call. No tokens. Reads structured findings and writes
a non-jargon summary aimed at a non-forensic-analyst reader (CEO, manager,
end user). Companion to the technical narrative.md that Claude produces.

Usage:
    python3 scripts/plain-summary.py <case-dir>
    # writes <case-dir>/output/summary.md
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


CONFIDENCE_PLAIN = {
    "confirmed": "the tool is sure",
    "inferred": "probably true",
    "uncertain": "not sure",
    "unknown": "we don't know",
}


def severity_word(findings: list[dict]) -> str:
    confidences = {f.get("confidence") for f in findings}
    if any(("malicious" in (f.get("claim") or "").lower()) for f in findings):
        return "Concerning"
    if "confirmed" in confidences and not findings:
        return "Clean"
    if findings and {"inferred", "uncertain", "unknown"} >= confidences:
        return "Informational only — nothing requires action"
    return "Mostly informational"


def humanize_artifact(path: str) -> str:
    p = Path(path).name
    plain_map = {
        "com.apple.dock.plist": "Dock preferences (which apps are pinned)",
        ".GlobalPreferences.plist": "Global system preferences (locale, language)",
        "com.apple.finder.plist": "Finder preferences (recent folders, sidebar)",
        "com.apple.recentitems.plist": "Recently opened files",
        "com.apple.LaunchServices.plist": "File-to-app associations",
        "host_zsh_history": "Shell command history (zsh)",
        "host_bash_history": "Shell command history (bash)",
        "host_sw_vers.txt": "macOS version info",
        "host_os-release": "Linux distro info",
        "host_hostname": "Computer hostname",
        "host_crontab.txt": "Scheduled tasks (cron)",
        "host_ssh_known_hosts": "SSH server fingerprint cache (no keys)",
    }
    if p in plain_map:
        return plain_map[p]
    if p.endswith(".plist") and "LaunchAgents" in path:
        return f"Auto-start program ({p.replace('.plist','')})"
    if p.endswith(".plist"):
        return f"Apple settings file ({p})"
    if p.endswith(".evtx"):
        return f"Windows event log ({p})"
    if p.endswith(".pf"):
        return f"Windows execution record ({p})"
    if p.endswith(".lnk"):
        return f"Windows shortcut ({p})"
    if p.endswith(".dat"):
        return f"Windows registry hive ({p})"
    return p


def humanize_claim(claim: str) -> str:
    """Strip jargon, MITRE codes, finding IDs from the technical claim."""
    out = claim
    for tag in ["MITRE T", "T1543", "T1055", "T1027", "T1059"]:
        idx = out.find(tag)
        if idx > 0:
            out = out[:idx].rstrip(" .,—")
    out = out.replace("MITRE ATT&CK", "")
    if " — " in out:
        head = out.split(" — ", 1)[0]
        if len(head) < 140:
            out = head
    if len(out) > 200:
        out = out[:197] + "..."
    return out.strip()


def action_word(finding: dict) -> str:
    claim_lower = (finding.get("claim") or "").lower()
    confidence = finding.get("confidence", "")
    if "malicious" in claim_lower or "compromise" in claim_lower:
        return "Investigate now"
    if "stub" in claim_lower or "placeholder" in claim_lower or "non-functional" in claim_lower:
        return "No action — placeholder"
    if "vendor" in claim_lower or "developer-installed" in claim_lower or "benign" in claim_lower:
        return "No action — known good"
    if confidence == "uncertain":
        return "Worth a closer look"
    if "persistence" in claim_lower:
        return "Confirm this is intentional"
    return "Note for the record"


def summarize(case_dir: Path) -> str:
    findings_path = case_dir / "output" / "findings.json"
    audit_path = case_dir / "output" / "audit.jsonl"
    if not findings_path.exists():
        return "# No findings yet\n\nThis case has not been triaged.\n"

    findings = json.loads(findings_path.read_text())
    artifacts: dict[str, dict] = {}
    if audit_path.exists():
        for line in audit_path.read_text().splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event") == "evidence_ingest":
                a = e["data"]["artifact"]
                artifacts[Path(a).name] = e["data"]

    case_id = case_dir.name
    when = datetime.now(timezone.utc).isoformat()
    severity = severity_word(findings)

    out: list[str] = []
    out.append(f"# Plain-English Summary — Case `{case_id}`\n")
    out.append(f"_Generated {when} — no AI, no tokens. Reads `findings.json` + "
               f"`audit.jsonl` and translates to plain English._\n")

    out.append("## Quick Read\n")
    out.append(f"- **Files we looked at:** {len(artifacts)}")
    out.append(f"- **Things we noticed:** {len(findings)}")
    out.append(f"- **Overall:** {severity}\n")

    out.append("## What Each File Means\n")
    out.append("| File on disk | What it actually is |")
    out.append("|---|---|")
    for name in sorted(artifacts.keys()):
        out.append(f"| `{name}` | {humanize_artifact(name)} |")
    out.append("")

    out.append("## What We Found (Plain English)\n")
    out.append("| ID | What we found | Where | How sure | What to do |")
    out.append("|---|---|---|---|---|")
    for f in findings:
        fid = f.get("finding_id", "?")
        claim = humanize_claim(f.get("claim") or "")
        pin0 = (f.get("pins") or [{}])[0]
        artifact = pin0.get("artifact", "?")
        artifact_short = humanize_artifact(artifact)
        if len(artifact_short) > 50:
            artifact_short = artifact_short[:47] + "..."
        confidence_plain = CONFIDENCE_PLAIN.get(f.get("confidence", ""), "?")
        action = action_word(f)
        out.append(f"| {fid} | {claim} | {artifact_short} | {confidence_plain} | {action} |")
    out.append("")

    confirmed = sum(1 for f in findings if f.get("confidence") == "confirmed")
    inferred = sum(1 for f in findings if f.get("confidence") == "inferred")
    uncertain = sum(1 for f in findings if f.get("confidence") == "uncertain")
    unknown = sum(1 for f in findings if f.get("confidence") == "unknown")
    out.append("## How To Read \"How Sure\"\n")
    out.append(f"- **the tool is sure** ({confirmed}) — multiple independent pieces "
               f"of evidence agree. Treat as fact.")
    out.append(f"- **probably true** ({inferred}) — one solid piece of evidence "
               f"with well-understood meaning. Treat as likely.")
    out.append(f"- **not sure** ({uncertain}) — the evidence hints at something but "
               f"doesn't prove it. Worth a follow-up.")
    out.append(f"- **we don't know** ({unknown}) — gap acknowledged honestly. "
               f"More evidence needed to decide.\n")

    out.append("## Where The Detailed Reports Are\n")
    out.append(f"- **Full technical narrative** (with MITRE ATT&CK codes, "
               f"finding IDs, MACB timestamps): `narrative.md`")
    out.append(f"- **Honest accuracy scoring** (true positives, false positives, "
               f"missed items, hallucinations caught): `accuracy-report.md`")
    out.append(f"- **Plain audit log of every step the agent took**: `audit.jsonl`")
    out.append(f"- **Structured findings** (machine-readable, every claim pinned "
               f"to specific bytes in evidence): `findings.json`\n")

    return "\n".join(out)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: plain-summary.py <case-dir>", file=sys.stderr)
        return 2
    case_dir = Path(sys.argv[1])
    if not case_dir.exists():
        print(f"Case not found: {case_dir}", file=sys.stderr)
        return 1
    summary = summarize(case_dir)
    out_path = case_dir / "output" / "summary.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(summary)
    print(f"Wrote {out_path} ({len(summary)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
