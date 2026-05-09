"""IncidentState — mirrors IR_FRAMEWORKS_REFERENCE.md §11.1.

Carried verbatim from the framework reference so audit reviewers can do a
direct schema-to-spec diff.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal, TypedDict, cast

import networkx as nx

Severity = Literal["low", "medium", "high", "critical"]
Phase = Literal[
    "detect", "triage", "analyze", "contain",
    "eradicate", "recover", "lessons",
]


@dataclass
class IOC:
    type: str           # ip | domain | hash | filepath | registry_key
    value: str
    first_seen: str = ""
    confidence: str = "uncertain"


@dataclass
class Artifact:
    path: str
    sha256: str = ""
    sha1: str = ""
    size: int = 0
    label: str = ""


@dataclass
class Countermeasure:
    d3fend_id: str
    name: str
    tactic: str         # Isolate | Evict | Restore | Harden | Detect | Deceive | Model
    attack_id_satisfied: str = ""
    rationale: str = ""


@dataclass
class Control:
    framework: str      # SP-800-53 | CSF | ISO-27035
    control_id: str
    title: str = ""
    rationale: str = ""


@dataclass
class HashChainEntry:
    """Plain hash-only entry — no chain linking (Sub-Plan 01 removed cryptographic chaining)."""
    artifact_path: str
    sha256: str
    ts: str


class IncidentState(TypedDict, total=False):
    incident_id: str
    severity: Severity
    phase: Phase
    kill_chain_stage: int
    attack_techniques: list[str]
    diamond_graph: nx.DiGraph
    iocs: list[IOC]
    forensic_artifacts: list[Artifact]
    csf_subcategories_satisfied: set[str]
    iso27035_phase: str
    d3fend_recommendations: list[Countermeasure]
    remediation_plan: list[dict[str, Any]]
    containment_actions: list[dict[str, Any]]
    eradication_actions: list[dict[str, Any]]
    recovery_actions: list[dict[str, Any]]
    evidence_chain: list[HashChainEntry]
    # Internal — not in §11.1 but needed for plumbing
    _node_history: list[str]
    _output_dir: str
    _detected_os: Literal["windows", "macos", "linux", "unknown"]
    _analyze_iter: int
    _rca_complete: bool
    _reinfection_detected: bool
    _post_restore_alarms: bool
    _verifier_complete: bool
    _findings: list[dict[str, Any]]
    _max_blast_score: int


def new_state(incident_id: str) -> IncidentState:
    return cast(IncidentState, {
        "incident_id": incident_id,
        "severity": "low",
        "phase": "detect",
        "kill_chain_stage": 0,
        "attack_techniques": [],
        "diamond_graph": nx.DiGraph(),
        "iocs": [],
        "forensic_artifacts": [],
        "csf_subcategories_satisfied": set(),
        "iso27035_phase": "detection_and_reporting",
        "d3fend_recommendations": [],
        "remediation_plan": [],
        "containment_actions": [],
        "eradication_actions": [],
        "recovery_actions": [],
        "evidence_chain": [],
        "_node_history": [],
        "_output_dir": "",
        "_detected_os": "unknown",
        "_analyze_iter": 0,
        "_rca_complete": False,
        "_reinfection_detected": False,
        "_post_restore_alarms": False,
        "_verifier_complete": False,
        "_findings": [],
        "_max_blast_score": 0,
    })


def serialize_state(s: IncidentState) -> dict[str, Any]:
    return {
        "incident_id": s["incident_id"],
        "severity": s["severity"],
        "phase": s["phase"],
        "kill_chain_stage": s["kill_chain_stage"],
        "attack_techniques": list(s["attack_techniques"]),
        "diamond_graph": nx.node_link_data(s["diamond_graph"], edges="edges"),
        "iocs": [asdict(i) for i in s["iocs"]],
        "forensic_artifacts": [asdict(a) for a in s["forensic_artifacts"]],
        "csf_subcategories_satisfied": sorted(s["csf_subcategories_satisfied"]),
        "iso27035_phase": s["iso27035_phase"],
        "d3fend_recommendations": [asdict(c) for c in s["d3fend_recommendations"]],
        "remediation_plan": list(s.get("remediation_plan", [])),
        "containment_actions": list(s.get("containment_actions", [])),
        "eradication_actions": list(s.get("eradication_actions", [])),
        "recovery_actions": list(s.get("recovery_actions", [])),
        "evidence_chain": [asdict(h) for h in s["evidence_chain"]],
        "_node_history": list(s.get("_node_history", [])),
        "_output_dir": s.get("_output_dir", ""),
        "_detected_os": s.get("_detected_os", "unknown"),
        "_analyze_iter": s.get("_analyze_iter", 0),
        "_rca_complete": s.get("_rca_complete", False),
        "_reinfection_detected": s.get("_reinfection_detected", False),
        "_post_restore_alarms": s.get("_post_restore_alarms", False),
        "_verifier_complete": s.get("_verifier_complete", False),
        "_findings": list(s.get("_findings", [])),
        "_max_blast_score": s.get("_max_blast_score", 0),
    }


def deserialize_state(d: dict[str, Any]) -> IncidentState:
    s = new_state(d["incident_id"])
    s["severity"] = d["severity"]
    s["phase"] = d["phase"]
    s["kill_chain_stage"] = d["kill_chain_stage"]
    s["attack_techniques"] = list(d["attack_techniques"])
    s["diamond_graph"] = nx.node_link_graph(d["diamond_graph"], edges="edges")
    s["iocs"] = [IOC(**i) for i in d["iocs"]]
    s["forensic_artifacts"] = [Artifact(**a) for a in d["forensic_artifacts"]]
    s["csf_subcategories_satisfied"] = set(d["csf_subcategories_satisfied"])
    s["iso27035_phase"] = d["iso27035_phase"]
    s["d3fend_recommendations"] = [Countermeasure(**c) for c in d["d3fend_recommendations"]]
    s["remediation_plan"] = list(d.get("remediation_plan", []))
    s["containment_actions"] = list(d.get("containment_actions", []))
    s["eradication_actions"] = list(d.get("eradication_actions", []))
    s["recovery_actions"] = list(d.get("recovery_actions", []))
    s["evidence_chain"] = [HashChainEntry(**h) for h in d["evidence_chain"]]
    s["_node_history"] = list(d.get("_node_history", []))
    s["_output_dir"] = d.get("_output_dir", "")
    s["_detected_os"] = d.get("_detected_os", "unknown")
    s["_analyze_iter"] = d.get("_analyze_iter", 0)
    s["_rca_complete"] = d.get("_rca_complete", False)
    s["_reinfection_detected"] = d.get("_reinfection_detected", False)
    s["_post_restore_alarms"] = d.get("_post_restore_alarms", False)
    s["_verifier_complete"] = d.get("_verifier_complete", False)
    s["_findings"] = list(d.get("_findings", []))
    s["_max_blast_score"] = d.get("_max_blast_score", 0)
    return s
