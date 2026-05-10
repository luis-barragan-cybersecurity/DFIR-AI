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


def _scope_summary(state: dict, findings: list[dict]) -> dict:
    """Use the orchestrator's scope.compute_scope so the exec report works
    even if the case predates the scope node (computes from findings).
    """
    if any(state.get(k) for k in ("affected_hosts", "affected_users",
                                  "affected_services", "affected_data")):
        return {
            "affected_hosts": list(state.get("affected_hosts") or []),
            "affected_users": list(state.get("affected_users") or []),
            "affected_services": list(state.get("affected_services") or []),
            "affected_data": list(state.get("affected_data") or []),
        }
    # Synthesize from findings using the same extractor the scope node uses.
    synthetic_state = {"_findings": findings, "forensic_artifacts": []}
    return scope_mod.compute_scope(synthetic_state)  # type: ignore[arg-type]


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

    # ─── 1. Executive Summary ────────────────────────────────────────────
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
    lines.append(f"- **ATT&CK techniques observed**: "
                 f"{len(techniques)} ({', '.join(techniques[:6]) or '—'})")
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
    lines.append(at.render_mermaid(techniques))

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
