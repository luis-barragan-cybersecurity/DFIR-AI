---
name: exec-report
description: Generate an executive incident report (one-page exec summary + next-4h actions + technical appendix with platform-specific containment commands + risk-reduction score). Deterministic — no LLM call. Use as the final step of triage when an owner-grade report is required.
---

# Executive Report

You produce the **`exec-report.md`** deliverable: the report the incident owner reads when they need to decide what to do in the next four hours.

## Trigger

Call this after every triage where:

- `findings.json` has at least one finding, OR
- `state.json` records `affected_hosts` / `affected_users` / `affected_services` / `affected_data`.

Skip when the case is suppressed (false positive) — the regular `mh status` summary is enough.

## How

The work is deterministic Python (no LLM call). Invoke it via `Bash` or via the `Read` tool to confirm the script exists:

```bash
python3 scripts/exec-report.py cases/<case-id>
```

Output: `cases/<case-id>/output/exec-report.md`. The script reads `findings.json` + `state.json` + `audit.jsonl` and emits five sections in this order:

1. **At a Glance** — severity, scope counts (hosts / users / services / data), ATT&CK techniques, risk-reduction score
2. **What To Do in the Next 4 Hours** — top-3 owner-runnable actions: snapshot evidence (read-only), isolate host, rotate credentials. Each carries a platform-specific PowerShell or Bash one-liner with placeholder hints (`<USER>`, `<C2_IP>`, `<PID_LIST>`, etc.)
3. **Attack Timeline** — Mermaid kill-chain rendered from observed ATT&CK technique IDs
4. **Risk Reduction Detail** — covered-vs-uncovered ATT&CK techniques with the score formula
5. **Technical Appendix** — finding table (id / confidence / claim / ATT&CK / rationale), per-technique containment commands, audit log digest

## Discipline

- **Every command stays advisory.** MemoryHound never executes containment or remediation. The exec report says so explicitly in its footer; preserve that footer.
- **Confidence rationale is mandatory.** The finding table renders `confidence_rationale` for every entry; if a finding lacks it (legacy data) the table prints `(legacy finding — no rationale)` so the gap is visible to the reader.
- **Risk-reduction score is honest.** It's covered-techniques over observed-techniques where "covered" means "we have at least one runnable command keyed to that T-id in `containment_commands.json`." Do not inflate the denominator by including sub-techniques twice.

## When NOT to use

- For the plain-English non-technical summary, use `scripts/plain-summary.py` (or `mh report` without `--exec`).
- For the structured §11.4 deliverables (`incident_summary.md`, `lessons_learned.md`, `compliance_map.json`), the orchestrator's `session_finalize` node already emits them — do not duplicate.
