---
name: ir-narrative
description: Convert structured verified findings into investigative prose suitable for an IR analyst report. Output is a structured narrative, not a raw execution log — required by hackathon rules.
---

# IR Narrative

Hackathon rules require: "output is presented as a structured investigative narrative, not a raw execution log."

## Actor Attribution Rule — READ FIRST (MANDATORY)

**Before writing the Executive Summary or Threat Actor Behavior section, check `/output/audit.jsonl` for the `threat_model` event written by `triage-orchestrator`.** That event names the actor and the victim. Use it.

If the event is present, follow this attribution table:

| `threat_model.shape` | Actor in narrative | Victim in narrative |
|---|---|---|
| `external-physical` | "the intruder" or "unauthorized physical actor" — never the local user account name | The local user account; explicitly state they are the **victim** |
| `external-remote` | "the threat actor" / named malware family / "the compromised credentials operator" | The local user account; explicitly state credentials were compromised |
| `insider-threat` | The local user account name (e.g. "Fred Rocba") | The organization / co-workers / data owners |

If the `threat_model` event is **absent**, the narrative MUST default to neutral framing: "the active session under user account X performed Y" — NOT "X (the user) performed Y". Without explicit threat model the agent has not earned the right to attribute intent.

### Forbidden framings (categorical failures)

Each of these has shipped a misattributed report before and is now an automatic-reject:

| ❌ Forbidden in `external-*` cases | ✅ Correct |
|---|---|
| "This is a textbook insider-threat exfil scenario" | "The 2020-11-13 evening EDT break-in window shows intruder activity through Fred Rocba's logged-in session" |
| "Fred pulled files from co-worker OneDrive folders" | "The intruder, operating through Fred's session, accessed co-worker OneDrive folders" |
| "Disable [victim user]'s tenant account" | "Rotate [victim user]'s session tokens; revoke share links from the compromise window; physical-security review" |
| "Trusted user pulling intellectual-property documents" | "Files accessed via [user]'s session during the compromise window; user was [in Florida / phished / not present] per case brief" |

### Timing correlation in attribution

When the `threat_model.compromise_window` is set, every activity claim in the Threat Actor Behavior section MUST be bracketed against it: "X events occurred inside the compromise window (intruder-attributed) and Y outside (legitimate user activity)." If you cannot recover per-event timestamps for an artifact, say so — do NOT assume "captured in this image = happened during compromise window."

## Required Structure

The report has TWO audiences and MUST serve both:

1. **Plain-English Summary** — for someone who is NOT a forensic analyst.
   No MITRE codes. No filename jargon. No acronyms without spelling out.
   3-6 sentences. What happened, who/what was affected, how bad, what action.
2. **Technical Body** — for the IR analyst. MITRE ATT&CK, finding IDs,
   confidence enums, MACB timestamps, the works.

```markdown
# Incident Report — Case <CASE_ID>

## What This Means In Plain English

3-6 sentences. NO jargon. NO acronyms (or always spell out on first use).
Think: explaining to the CEO at 2am. "We looked at X. We found Y. Z is
concerning / Z is fine. Do this next."

Then a small table:

| What we looked at | What we found | How sure | What to do |
|---|---|---|---|
| (artifact in plain English) | (1-line plain English claim) | confirmed/probably/unsure | "no action" / "investigate" / "isolate now" |

## Executive Summary

2-3 sentences. Technical-tinged but still readable. What happened,
severity, key actors/targets.

## Timeline of Events
Reverse chronological. Each entry:
- **<timestamp UTC>** — <plain language description> [pin: <finding_id>]

## Threat Actor Behavior
What did they do, in narrative form. Group findings by attacker phase:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command & Control
- Exfiltration
- Impact

(MITRE ATT&CK alignment — only assert TTPs that pin to specific findings.)

## Indicators of Compromise (IOCs)
- File hashes
- IPs / domains
- Process names + cmdlines
- Persistence locations

## Confidence Map
For each section, how certain we are and why.

## Gaps + Recommendations
What we don't know, and what evidence would resolve it.
```

## Discipline

- Every assertion in prose MUST link back to a `finding_id` in brackets — `[F-042]`
- Use plain language; assume reader is a senior IR analyst not a debugger
- Refer to confidence enum without quoting it: "execution is confirmed by Prefetch and BAM" not "confirmed: yes"
- Do NOT invent intent. "Process X connected to Y" is a fact. "Attacker exfiltrated data via X" is an interpretation; only state it if evidence supports it.

## Length

Aim 1-3 pages. Long-form prose loses judges. Tight, evidenced, structured wins.
