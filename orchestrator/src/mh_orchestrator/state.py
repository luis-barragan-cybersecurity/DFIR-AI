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
    remediation_plan: list[Control]
    evidence_chain: list[HashChainEntry]
    # Internal — not in §11.1 but needed for plumbing
    _node_history: list[str]
    _output_dir: str


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
        "evidence_chain": [],
        "_node_history": [],
        "_output_dir": "",
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
        "remediation_plan": [asdict(c) for c in s["remediation_plan"]],
        "evidence_chain": [asdict(h) for h in s["evidence_chain"]],
        "_node_history": list(s.get("_node_history", [])),
        "_output_dir": s.get("_output_dir", ""),
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
    s["remediation_plan"] = [Control(**c) for c in d["remediation_plan"]]
    s["evidence_chain"] = [HashChainEntry(**h) for h in d["evidence_chain"]]
    s["_node_history"] = list(d.get("_node_history", []))
    s["_output_dir"] = d.get("_output_dir", "")
    return s
