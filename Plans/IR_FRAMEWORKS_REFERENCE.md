# IR Frameworks Reference for LangGraph-Orchestrated Autonomous DFIR Agent

**Purpose:** Canonical technical reference for a LangGraph state machine performing Triage, Containment recommendation, Hunting/threat-intel correlation, and Remediation planning. All claims are cited; no fabrication.

**Audience:** The orchestrator agent (and its sub-agents) that will execute IR workflows. Treat each section as a directly addressable knowledge node.

---

## 1. NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations

- **Source:** https://csrc.nist.gov/pubs/sp/800/61/r3/final ; PDF: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
- **Version / Date:** Revision 3, published April 2025. Rev. 2 was formally **withdrawn April 2025** ([NIST news](https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations)).
- **Title (full):** *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile.*

### 1.1 Core Process Model
Rev. 3 **abandoned** the prior 4-phase lifecycle (Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-Incident Activity from Rev. 2 §3) and **re-anchored IR onto the six CSF 2.0 Functions** ([Industrial Cyber](https://industrialcyber.co/nist/nist-publishes-sp-800-61-rev-3-overhauling-incident-response-guidance-for-csf-2-0/)):

| Function | Role in IR |
|---|---|
| **Govern (GV)** | Roles, policy, supply-chain risk |
| **Identify (ID)** | Asset, vulnerability, risk awareness |
| **Protect (PR)** | Hardening that *reduces* incidents |
| **Detect (DE)** | Discovery and triage of events |
| **Respond (RS)** | Manage, analyze, communicate, mitigate |
| **Recover (RC)** | Restore operations and communicate |

GV/ID/PR are *pre-incident*; DE/RS/RC are *during/post-incident* (NIST SP 800-61r3 §2).

### 1.2 Decision Points an Agent Must Handle
1. *Is this an event or an incident?* (DE → RS gate)
2. *Severity classification* (drives notification thresholds, RS.MA-03)
3. *Containment posture* — short-term vs long-term (RS.MI-01)
4. *Eradication readiness* — root cause confirmed? (RS.AN-03)
5. *Recovery trigger* — eradication verified? (RS → RC gate)
6. *Lessons-learned trigger* — within defined SLA after recovery (GV.OV)

### 1.3 Required Outputs Per Phase
- **Detect:** Alert triage record + incident declaration artifact
- **Respond/Analyze:** Forensic timeline, scope, IOCs, ATT&CK tags
- **Respond/Mitigate:** Containment action log, blast-radius assessment
- **Recover:** Restoration plan + post-restoration verification
- **Govern:** After-action report + control improvement backlog

### 1.4 LangGraph Encoding
```
Nodes: detect_triage → declare_incident → analyze → mitigate → eradicate → recover → lessons_learned
Conditional edges:
  detect_triage --(is_incident?)--> declare_incident | suppress
  analyze --(rca_complete?)--> mitigate | analyze (loop, max N)
  mitigate --(contained?)--> eradicate | escalate_human
  eradicate --(clean?)--> recover | analyze
  recover --(stable?)--> lessons_learned | recover (loop)
```
Persist `incident_state` (CSF subcategory IDs satisfied) on every node exit.

---

## 2. NIST SP 800-86 — Forensic Techniques in IR

- **Source:** https://csrc.nist.gov/pubs/sp/800/86/final ; PDF: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf
- **Version / Date:** Final, August 2006 (still current; not superseded as of May 2026).

### 2.1 Four-Step Forensic Process (§3)
1. **Collection** — identify, label, record, acquire data; preserve integrity; prioritize order-of-volatility.
2. **Examination** — automated + manual extraction while preserving integrity.
3. **Analysis** — derive findings using documented, repeatable methods.
4. **Reporting** — describe actions, findings, and tool output for stakeholders.

### 2.2 Evidence Handling Mandates (§4)
- Maintain **chain of custody** documentation; ensure **admissibility** in legal proceedings ([NIST SP 800-86 §4.2](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf)).
- Capture **volatile data first** (registers, RAM, network state) before non-volatile (disk).
- Preserve **integrity of tools and equipment**; use write-blockers where applicable.

### 2.3 Tool Selection Criteria (§3.1.2)
- Validated against known datasets
- Reproducible output
- Forensically sound (no target modification)
- Auditable logging

### 2.4 LangGraph Encoding
A `forensic_collector` sub-graph invoked by `analyze`:
```
collect_volatile → collect_nonvolatile → hash_and_seal → examine → analyze → report
Each node writes to a tamper-evident chain-of-custody log (sha256 hash chain).
```

---

## 3. NIST CSF 2.0 — RESPOND Function Mapping

- **Source:** https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf ; reference tool: https://csf.tools/reference/nist-cybersecurity-framework/v2-0/
- **Version / Date:** CSF 2.0, published **26 February 2024**. 6 Functions, 22 Categories, 106 Subcategories ([NIST CSWP 29](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)).

### 3.1 RESPOND (RS) Categories ([CSF Tools RS reference](https://csf.tools/reference/nist-cybersecurity-framework/v2-0/rs/))

| Category | Outcome | Agent Action |
|---|---|---|
| **RS.MA — Incident Management** | "Responses to detected cybersecurity incidents are managed" | `declare_incident`, assign severity, coordinate playbook |
| **RS.AN — Incident Analysis** | "Investigations are conducted to ensure effective response and support forensics and recovery activities" | Forensic collection, ATT&CK tagging, scope determination |
| **RS.CO — Incident Response Reporting and Communication** | "Response activities are coordinated with internal and external stakeholders as required by laws, regulations, or policies" | Generate notifications (legal, regulators, customers) |
| **RS.MI — Incident Mitigation** | "Activities are performed to prevent expansion of an event and mitigate its effects" | Containment recommendations, isolate hosts, block IOCs |

### 3.2 RECOVER (RC) Categories
- **RC.RP — Incident Recovery Plan Execution**
- **RC.CO — Incident Recovery Communication**

### 3.3 LangGraph Encoding
Each LangGraph node *declares* the CSF subcategories it satisfies. The orchestrator emits a coverage map per incident (e.g., `{"RS.MA-01": "satisfied", "RS.AN-03": "satisfied"}`).

---

## 4. NIST SP 800-53 Rev. 5 — IR Control Family

- **Source:** https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final ; DOI: https://doi.org/10.6028/NIST.SP.800-53r5
- **Version / Date:** Rev. 5, Update 1 (December 2023); base Rev. 5 originally September 2020.

### 4.1 IR Family Controls and Agent Mapping

| Control | Title | Agent Capability |
|---|---|---|
| **IR-1** | Policy and Procedures | Load-time config; agent reads org policy from KB |
| **IR-2** | Incident Response Training | Out-of-scope (human) |
| **IR-3** | Incident Response Testing | Tabletop simulation hooks (replay engine) |
| **IR-4** | Incident Handling | Core orchestration loop (PICERL/CSF executor) |
| **IR-5** | Incident Monitoring | Continuous detection + telemetry ingestion |
| **IR-6** | Incident Reporting | RS.CO automation: generate stakeholder notifications |
| **IR-7** | Incident Response Assistance | Sub-agent dispatch (forensic, malware analysis specialists) |
| **IR-8** | Incident Response Plan | Plan-as-code stored in repo; agent references playbooks |
| **IR-9** | Information Spillage Response | Specialized data-spill sub-graph (sanitize, notify) |
| **IR-10** | (Withdrawn in Rev. 5; previously Integrated Information Security Analysis Team) — coverage absorbed into IR-4 / PM-4 |

Source: NIST SP 800-53r5 Appendix C IR family ([NIST CSRC](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)).

### 4.2 LangGraph Encoding
Each node tags the IR control(s) it implements. Compliance reporter aggregates per-incident control coverage for audit (SOC 2 / FedRAMP downstream consumers).

---

## 5. SANS PICERL — 6 Phase Model

- **Source:** https://www.sans.org/media/score/504-incident-response-cycle.pdf ; Incident Handler's Handbook: https://www.sans.org/white-papers/33901
- **Version / Date:** SANS 504-B Cheat-Sheet (current); Handler's Handbook (2011, evergreen).

### 5.1 Six Phases
1. **Preparation** — policy, CSIRT, tooling, asset inventory
2. **Identification** — detect, scope, document deviations
3. **Containment** — three sub-phases:
   - *Short-term* (network isolation)
   - *System backup* (forensic image before modification)
   - *Long-term* (temporary fix while clean rebuilds occur)
4. **Eradication** — remove malware, patch vulnerabilities, restore from clean backup
5. **Recovery** — return to production, validate, monitor for recurrence
6. **Lessons Learned** — post-incident review (≤2 weeks per SANS)

### 5.2 PICERL vs NIST Comparison

| SANS PICERL | NIST SP 800-61 Rev. 2 (legacy) | NIST SP 800-61 Rev. 3 (current) |
|---|---|---|
| Preparation | Preparation | GV + ID + PR |
| Identification | Detection & Analysis | DE + RS.AN |
| Containment | Containment, Eradication & Recovery | RS.MI |
| Eradication | (same phase) | RS.MI / RC.RP |
| Recovery | (same phase) | RC.RP |
| Lessons Learned | Post-Incident Activity | GV.OV (improvement) |

**Strategic note:** PICERL's explicit *system backup* sub-phase before long-term containment is **the** detail Rev. 3 leaves implicit but every defensible IR program preserves. Encode it explicitly.

### 5.3 LangGraph Encoding
PICERL is the **operational backbone**; CSF is the **outcomes overlay**. The state machine should run PICERL nodes and emit CSF subcategory IDs as side-effects.

---

## 6. MITRE ATT&CK — Enterprise Matrix

- **Source:** https://attack.mitre.org/matrices/enterprise/ ; tactics: https://attack.mitre.org/tactics/enterprise/
- **Version / Date:** v18 (current as of May 2026): 14 enterprise tactics, 216 techniques, 475 sub-techniques, 44 mitigations, 1700+ analytics ([MITRE ATT&CK](https://attack.mitre.org/resources/)).

### 6.1 14 Enterprise Tactics (chronological adversary flow)

| TA ID | Tactic |
|---|---|
| TA0043 | Reconnaissance |
| TA0042 | Resource Development |
| TA0001 | Initial Access |
| TA0002 | Execution |
| TA0003 | Persistence |
| TA0004 | Privilege Escalation |
| TA0005 | Defense Evasion |
| TA0006 | Credential Access |
| TA0007 | Discovery |
| TA0008 | Lateral Movement |
| TA0009 | Collection |
| TA0011 | Command and Control |
| TA0010 | Exfiltration |
| TA0040 | Impact |

### 6.2 Tagging Findings
- Every finding **must** carry a `technique_id` (e.g., `T1003.001` = LSASS Memory dumping).
- Sub-technique IDs use dotted notation: `T<technique>.<sub>`.
- Use **CISA Best Practices for ATT&CK Mapping** ([CISA PDF](https://www.cisa.gov/sites/default/files/publications/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)) for tagging discipline: tag the *behavior*, not the tool.

### 6.3 Detection Coverage Model (v15+ change)
Legacy "Data Sources" replaced by **Detection Strategies + Analytics + Data Components**. Agents should ingest the analytic queries (e.g., Sigma-format) attached to each technique.

### 6.4 LangGraph Encoding
- `attack_tagger` node enriches every IOC/finding with `(tactic_id, technique_id, subtechnique_id)`.
- Enables downstream `d3fend_recommender` to lookup countermeasures.

---

## 7. MITRE D3FEND — Defensive Knowledge Graph

- **Source:** https://d3fend.mitre.org/ ; whitepaper: https://d3fend.mitre.org/resources/D3FEND.pdf
- **Version / Date:** **v1.0 GA January 2025**; v1.3.0 December 2025 extended to OT environments. NSA-funded. 267 techniques across 7 tactics ([Vectra D3FEND](https://www.vectra.ai/topics/mitre-d3fend)).

### 7.1 Seven Defensive Tactics

| Tactic | Count (v1.3.0) | Purpose | When in IR |
|---|---|---|---|
| **Model** | 27 | Understand the environment | Pre-incident (ID) |
| **Harden** | 51 | Reduce attack surface | Pre-incident (PR) + Remediation |
| **Detect** | 90 | Visibility into adversary activity | Detection / Hunting |
| **Isolate** | 57 | Contain threats | **Containment recommendations** |
| **Deceive** | 11 | Misdirect with honeypots | Hunting / containment |
| **Evict** | 19 | Remove adversary | **Eradication** |
| **Restore** | 12 | Return to secure state | **Recovery** |

### 7.2 ATT&CK ↔ D3FEND Bridge: Digital Artifacts
D3FEND's **Digital Artifact Ontology** is the bridge: each ATT&CK technique produces digital artifacts (files, network traffic, software state); each D3FEND technique acts on those artifacts ([D3FEND whitepaper](https://d3fend.mitre.org/resources/D3FEND.pdf)).

### 7.3 LangGraph Encoding
`d3fend_recommender` node takes `attack_techniques[]` as input, queries the knowledge graph (D3FEND ships SPARQL/JSON), and emits ranked countermeasures grouped by tactic (Isolate for containment, Evict for eradication, Restore for recovery, Harden for remediation backlog).

---

## 8. Diamond Model of Intrusion Analysis

- **Source:** https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf (Caltagirone, Pendergast, Betz, 2013)
- **Version / Date:** Original 2013 paper; still authoritative.

### 8.1 Four Vertices
- **Adversary** — who
- **Capability** — tools/TTPs
- **Infrastructure** — C2, domains, IPs
- **Victim** — target (org, system, person)

Six **edges** connect the vertices, each bidirectional, enabling **analytical pivoting** ([Vectra](https://www.vectra.ai/topics/diamond-model-of-intrusion-analysis)).

### 8.2 Pivoting Patterns the Agent Must Support
1. **Infrastructure → Adversary** (passive DNS, WHOIS history)
2. **Capability → Adversary** (malware family attribution)
3. **Infrastructure → Capability** (sandbox detonation reveals payload)
4. **Victim → Adversary** (sector targeting patterns)
5. **Capability → Victim** (which assets did the malware touch?)
6. **Adversary → Infrastructure** (known C2 set for actor)

### 8.3 LangGraph Encoding
Maintain a `diamond_graph` (e.g., NetworkX or Neo4j) as part of `incident_state`. Every new IOC is a node; every observed relationship is an edge. The `pivot_hunter` sub-agent traverses edges to expand investigation scope.

---

## 9. Lockheed Martin Cyber Kill Chain

- **Source:** https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html ; original paper: https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf (Hutchins, Cloppert, Amin, 2011)
- **Version / Date:** 2011 framework; current Lockheed page maintained.

### 9.1 Seven Stages and Interruption Points

| # | Stage | Defender Disruption Action |
|---|---|---|
| 1 | Reconnaissance | Detect scanning; deception |
| 2 | Weaponization | Threat intel on weaponizers (mostly out of band) |
| 3 | Delivery | Block at email gateway, web proxy |
| 4 | Exploitation | Patching, EDR exploit prevention |
| 5 | Installation | EDR/AV blocking, app allowlisting |
| 6 | Command and Control | DNS sinkhole, egress filtering |
| 7 | Actions on Objectives | DLP, segmentation, behavioral detection |

**Strategic point:** disruption *earlier* in the chain is cheaper. A LangGraph hunting agent should always assess "which kill-chain stage was reached?" — earlier = lower blast radius.

### 9.2 LangGraph Encoding
`kill_chain_classifier` node assigns a stage to every observed adversary action. Drives **prioritization**: stage-7 detections jump triage queue.

---

## 10. ISO/IEC 27035 — Information Security Incident Management

- **Source:**
  - Part 1: https://www.iso.org/standard/78973.html
  - Part 2: https://www.iso.org/standard/78974.html
  - Part 3: https://www.iso.org/standard/74033.html
- **Version / Date:** Part 1 (2023), Part 2 (2023), Part 3 (2020).

### 10.1 Five-Phase Process Model (Part 1 §5)
1. **Plan and Prepare**
2. **Detection and Reporting**
3. **Assessment and Decision**
4. **Responses** (containment, eradication, recovery, forensic analysis)
5. **Learn Lessons**

### 10.2 Part Scope
- **Part 1** — principles + process model (governance backbone)
- **Part 2** — planning and preparation guidelines
- **Part 3** — ICT incident response operations: detection, reporting, **triage**, analysis, response, containment, eradication, recovery, conclusion ([ISO 27035-3](https://www.iso.org/standard/74033.html))

### 10.3 LangGraph Encoding
ISO 27035 is the **governance overlay** that maps to compliance reporting. Each incident emits an ISO 27035 phase tag in addition to CSF/PICERL tags for multi-framework attestation.

---

## 11. Unified IR Pipeline — LangGraph State Machine

### 11.1 State Schema
```python
IncidentState = {
  "incident_id": str,
  "severity": Literal["low","medium","high","critical"],
  "phase": Literal["detect","triage","analyze","contain","eradicate","recover","lessons"],
  "kill_chain_stage": int,  # 1-7
  "attack_techniques": list[str],  # T-IDs
  "diamond_graph": Graph,
  "iocs": list[IOC],
  "forensic_artifacts": list[Artifact],  # SP 800-86 chain of custody
  "csf_subcategories_satisfied": set[str],
  "iso27035_phase": str,
  "d3fend_recommendations": list[Countermeasure],
  "remediation_plan": list[Control],  # SP 800-53 IR family items
  "evidence_chain": list[HashChainEntry],
}
```

### 11.2 Node Graph
```
                    ┌── suppress (false positive)
detect ─── triage ──┤
                    └── declare_incident
                              │
                              ▼
                          analyze ◄──┐
                              │      │ (rca incomplete)
                       ┌──────┴──────┤
                       ▼             │
                  attack_tag         │
                       │             │
                       ▼             │
              kill_chain_classify ───┘
                       │
                       ▼
                d3fend_recommend
                       │
                       ▼
                   contain (RS.MI / D3FEND Isolate)
                       │  ├── short_term
                       │  ├── system_backup  ← SANS PICERL explicit
                       │  └── long_term
                       ▼
                   eradicate (D3FEND Evict)
                       │
                       ▼
                    recover (D3FEND Restore + RC.RP)
                       │
                       ▼
                lessons_learned (GV.OV + ISO 27035 phase 5)
                       │
                       ▼
                  remediation_plan (D3FEND Harden + SP 800-53 controls)
```

### 11.3 Conditional Edges (Routing Logic)
| Edge | Condition | Source of Truth |
|---|---|---|
| `triage → declare_incident` | severity ≥ medium | RS.MA-03 (CSF) |
| `analyze → analyze` (loop) | RCA incomplete, iter < N | RS.AN-03 (CSF) |
| `contain → escalate_human` | blast radius > threshold | IR-7 (SP 800-53) |
| `eradicate → analyze` | re-infection detected | PICERL phase 4 retry |
| `recover → recover` | post-restore alarms | RC.RP-01 (CSF) |
| any → `human_in_loop` | confidence < 0.7 OR irreversible action | Safety guard |

### 11.4 Required Outputs (per incident)
1. **Forensic timeline** (SP 800-86)
2. **ATT&CK technique list** with sub-IDs
3. **Diamond graph** snapshot
4. **D3FEND countermeasure recommendations** (ranked)
5. **Containment action log** (RS.MI)
6. **Recovery verification report** (RC.RP)
7. **Remediation plan** mapped to SP 800-53 controls
8. **Stakeholder notifications** (RS.CO + IR-6)
9. **Multi-framework compliance map** (CSF + ISO 27035 + IR family)
10. **Hash-chained evidence log** (chain-of-custody integrity)

### 11.5 Strategic / Second-Order Considerations
- **Reversibility gate:** any containment action with > $X cost or affecting > Y users must require human approval. The agent's value is *speed for reversible actions* and *accelerated decision-support for irreversible ones*.
- **Adversary feedback loop:** containment actions are observable to the adversary. Order operations to deny pivot ability *before* visible eviction (D3FEND Deceive ↔ Evict sequencing).
- **Compliance compounding:** by tagging every action with CSF + ISO 27035 + IR-family IDs simultaneously, a single incident produces audit evidence for *all three* regimes — eliminating duplicated reporting work.
- **Knowledge graph appreciation:** each incident enriches the Diamond and ATT&CK history. Prior cases become detection signatures — the system becomes *more valuable per incident handled*.

---

## 12. Authoritative Source Index

| Framework | Primary URL |
|---|---|
| NIST SP 800-61 Rev. 3 | https://csrc.nist.gov/pubs/sp/800/61/r3/final |
| NIST SP 800-86 | https://csrc.nist.gov/pubs/sp/800/86/final |
| NIST CSF 2.0 | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf |
| NIST SP 800-53 Rev. 5 | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final |
| SANS PICERL Cheat-Sheet | https://www.sans.org/media/score/504-incident-response-cycle.pdf |
| MITRE ATT&CK Enterprise | https://attack.mitre.org/matrices/enterprise/ |
| MITRE D3FEND | https://d3fend.mitre.org/ |
| Diamond Model (paper) | https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf |
| Cyber Kill Chain (paper) | https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf |
| ISO/IEC 27035-1:2023 | https://www.iso.org/standard/78973.html |
| ISO/IEC 27035-2:2023 | https://www.iso.org/standard/78974.html |
| ISO/IEC 27035-3:2020 | https://www.iso.org/standard/74033.html |
| CISA ATT&CK Mapping Best Practices | https://www.cisa.gov/sites/default/files/publications/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf |

**Document version:** 1.0 — May 2026. Re-pull and refresh whenever NIST/MITRE publish new minor versions; D3FEND ships quarterly, ATT&CK ships ~biannually.
