"""session_finalize — final state.json + §11.4 deliverables.

In addition to the existing wrap-up duties (final state.json snapshot, audit
exit event, lifecycle agent message, history append), this node emits the
two terminal §11.4 deliverables:

1. compliance_map.json — CSF 2.0 subcategories satisfied + ISO 27035 phase
   + PICERL phase + framework version pins (Plans/IR_FRAMEWORKS_REFERENCE.md
   §11.4 item 9: "Multi-framework compliance map").
2. incident_summary.md — investigator-readable narrative bundling severity,
   detected OS, finding/verifier counts, ATT&CK techniques, kill-chain stage,
   per-phase advisory recommendation counts, and the deliverable manifest.

Both files are administrative-only / advisory; this node never executes
containment or remediation.
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import attack_timeline, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState

NODE_NAME = "session_finalize"


def _verifier_counts(state: IncidentState) -> tuple[int, int, int]:
    decisions = state.get("_verifier_decisions", []) or []
    agree = sum(1 for d in decisions if d.get("decision") == "agree")
    dissent = sum(1 for d in decisions if d.get("decision") == "dissent")
    revise = sum(1 for d in decisions if d.get("decision") == "revise")
    return agree, dissent, revise


def _build_compliance_map(state: IncidentState) -> dict:
    return {
        "case_id": state["incident_id"],
        "csf_subcategories_satisfied": sorted(
            state.get("csf_subcategories_satisfied", []) or []
        ),
        "iso27035_phase": state.get("iso27035_phase", "unknown"),
        "phase": state.get("phase", "unknown"),
        "picerl_phase": picerl.picerl_phase_for(NODE_NAME),
        "attack_techniques": sorted(state.get("attack_techniques", []) or []),
        "kill_chain_stage": state.get("kill_chain_stage", 0),
        "frameworks": {
            "nist_csf_version": "2.0",
            "nist_sp_800_61": "Rev. 3 (April 2025)",
            "iso_27035": "27035-1:2023",
            "mitre_attck": "v18",
            "mitre_d3fend": "v1.3.0 (stub — Sub-Plan 04)",
            "lockheed_kill_chain": "7-stage",
            "sans_picerl": "6-phase",
        },
    }


def _render_incident_summary(state: IncidentState) -> str:
    case_id = state["incident_id"]
    severity = state.get("severity", "unknown")
    detected_os = state.get("_detected_os") or "unknown"
    findings_n = len(state.get("_findings", []) or [])
    agree, dissent, revise = _verifier_counts(state)
    techniques = sorted(state.get("attack_techniques", []) or [])
    techniques_str = ", ".join(techniques) if techniques else "(none)"
    kc_stage = state.get("kill_chain_stage", 0)
    phase = state.get("phase", "unknown")
    iso = state.get("iso27035_phase", "unknown")
    picerl_phase = picerl.picerl_phase_for(NODE_NAME)
    csf_satisfied = sorted(state.get("csf_subcategories_satisfied", []) or [])
    csf_str = ", ".join(csf_satisfied) if csf_satisfied else "(none)"

    contain_n = len(state.get("containment_actions", []) or [])
    eradicate_n = len(state.get("eradication_actions", []) or [])
    recover_n = len(state.get("recovery_actions", []) or [])
    remediation_n = len(state.get("remediation_plan", []) or [])

    verifier_complete = state.get("_verifier_complete", False)
    human_approval = state.get("human_approval_required", False)

    return (
        f"# Incident Summary — {case_id}\n"
        "\n"
        "## At a Glance\n"
        "\n"
        f"- **Severity**: {severity}\n"
        f"- **Detected OS**: {detected_os}\n"
        f"- **Findings**: {findings_n} ({agree} verifier-agreed, {dissent} dissent, {revise} revise)\n"
        f"- **ATT&CK Techniques**: {techniques_str}\n"
        f"- **Max Kill-Chain Stage Reached**: {kc_stage}/7\n"
        f"- **Phase**: {phase} ({iso})\n"
        "\n"
        "## Attack Timeline (MITRE ATT&CK kill chain)\n"
        "\n"
        f"{attack_timeline.render_mermaid(techniques)}"
        "\n"
        "## Multi-Framework Alignment\n"
        "\n"
        f"- **NIST CSF 2.0 subcategories satisfied**: {csf_str}\n"
        f"- **ISO/IEC 27035-1:2023 phase**: {iso}\n"
        f"- **SANS PICERL phase**: {picerl_phase}\n"
        "\n"
        "## Advisory Recommendations Emitted\n"
        "\n"
        f"- Containment actions: {contain_n}\n"
        f"- Eradication actions: {eradicate_n}\n"
        f"- Recovery actions: {recover_n}\n"
        f"- Remediation controls: {remediation_n}\n"
        "\n"
        "## Trust Discipline\n"
        "\n"
        f"- Verifier complete: {verifier_complete}\n"
        f"- Human approval required: {human_approval}\n"
        "\n"
        "## Deliverables Emitted Per §11.4\n"
        "\n"
        "- `state.json` (final IncidentState snapshot)\n"
        "- `state.history.jsonl` (per-node snapshots)\n"
        "- `audit.jsonl` (append-only event log)\n"
        "- `agent_messages.jsonl` (inter-agent + Verifier dissent trace)\n"
        "- `containment_actions.jsonl`\n"
        "- `recovery_verification.json`\n"
        "- `lessons_learned.md`\n"
        "- `remediation_plan.json`\n"
        "- `compliance_map.json`\n"
        "- `incident_summary.md`\n"
        "\n"
        "---\n"
        "\n"
        "*This investigation was administrative-only and intended for "
        "internal blue-team use.*\n"
        "*All mitigations are advisory; MemoryHound never executes "
        "containment or remediation actions.*\n"
    )


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit

    out = Path(state["_output_dir"])
    out.mkdir(parents=True, exist_ok=True)

    state["phase"] = "lessons"
    state["_node_history"].append(NODE_NAME)

    # Canonical consolidated findings.json — write the deduped list from
    # state["_findings"] so accuracy-report tooling (scripts/diff_findings.py)
    # has a single authoritative artifact regardless of which subagent
    # produced individual entries via finding_record.
    findings = list(state.get("_findings", []) or [])
    findings_path = out / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2, sort_keys=True))
    record_audit(
        state, event="findings_consolidated",
        data={"path": findings_path.name, "count": len(findings)},
    )

    # §11.4 item 9 — Multi-framework compliance map
    compliance_map = _build_compliance_map(state)
    cm_path = out / "compliance_map.json"
    cm_path.write_text(json.dumps(compliance_map, indent=2, sort_keys=True))
    record_audit(
        state, event="compliance_map_written",
        data={
            "path": cm_path.name,
            "csf_count": len(compliance_map["csf_subcategories_satisfied"]),
            "attack_techniques_count": len(compliance_map["attack_techniques"]),
            "iso27035_phase": compliance_map["iso27035_phase"],
            "picerl_phase": compliance_map["picerl_phase"],
        },
    )

    # Investigator-readable narrative summary
    summary_md = _render_incident_summary(state)
    summary_path = out / "incident_summary.md"
    summary_path.write_text(summary_md)
    record_audit(
        state, event="incident_summary_written",
        data={"path": summary_path.name, "chars": len(summary_md)},
    )

    record_audit(
        state, event="session_complete",
        data={"node_history": state["_node_history"]},
    )
    emit_message(
        state, from_agent="orchestrator", to_agent="orchestrator",
        role="lifecycle",
        content=f"session_finalize — {len(state['_node_history'])} nodes ran",
    )
    write_checkpoint(state, out)
    append_history(state, out, node=NODE_NAME)
    return state
