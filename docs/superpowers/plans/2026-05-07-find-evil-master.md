# FIND EVIL! Hackathon — Master Implementation Spec

> **Status:** Master decomposition document. Individual sub-plans linked at bottom.
> **Deadline:** 2026-06-15 23:45 EDT (~5.5 weeks from 2026-05-07).
> **Source-of-truth references:**
> - Hackathon page: https://findevil.devpost.com/
> - IR framework reference (canonical): `Plans/IR_FRAMEWORKS_REFERENCE.md`
> - Codebase audit: PRD `MEMORY/WORK/20260507-193749_sans-codebase-analysis/PRD.md`

---

## Goal (one sentence)

Convert MemoryHound from a Windows-only DFIR triage harness into a LangGraph-orchestrated multi-agent autonomous IR + Blue Team platform that runs on SIFT Workstation, performs full PICERL/CSF 2.0 incident response (Triage → Containment recs → Hunting → Remediation), and ships as a hackathon submission.

## Architecture

LangGraph state machine is the new orchestration layer. Each PICERL phase is a node. Existing Claude Code subagents (windows-agent, macos-agent, linux-agent, verifier, evidence-custodian) are wrapped as graph-executable nodes — their `.claude/agents/*.md` definitions stay; LangGraph invokes `claude` CLI per node with the appropriate subagent context. New nodes added for `attack_tag`, `kill_chain_classify`, `d3fend_recommend`, `contain`, `eradicate`, `recover`, `lessons_learned`, `remediation_plan`. State persists between nodes (incident_id, severity, kill_chain_stage, attack_techniques, diamond_graph, iocs, csf_subcategories_satisfied, iso27035_phase, d3fend_recommendations, remediation_plan). Plain JSONL audit log + agent-to-agent message log replace the chain-of-custody hash chain.

## Tech Stack

| Layer | Choice |
|---|---|
| Orchestrator | LangGraph 0.2+ (Python) |
| LLM client | langchain-anthropic + Claude Code subprocess wrapper |
| State graph | TypedDict + StateGraph |
| Diamond model | networkx |
| D3FEND queries | rdflib + SPARQL or pre-computed JSON lookup |
| MCP server | existing `protocol-sift-mcp` (Python 3.11, Pydantic, mcp>=1.0) |
| Subagents | existing `.claude/agents/*.md` |
| Skills | existing `.claude/skills/*` + new ones for new IR phases |
| Deploy | (a) `scripts/sift-install.sh` for SIFT VM, (b) `Dockerfile.sift` for containers |
| Tests | pytest (existing) |

## Decisions (locked from user)

| Decision | Choice | Why |
|---|---|---|
| Chain-of-custody | **Drop entirely → plain append-only log** | Internal admin IR, not legal-bound |
| Multi-agent framework | **LangGraph** | DFIR is state-machine-shaped, native max-iter cap |
| Deployment | **Both** SIFT install script + SIFT-based Dockerfile | Broadest judge accessibility |
| Protocol SIFT MCP | **Already authored** — same project as `teamdfir/protocol-sift` | No external integration |
| IR scope | **Triage + Containment + Hunting + Remediation** | Full blue-team coverage |
| Frameworks | **NIST SP 800-61 Rev. 3 + PICERL backbone + CSF 2.0 outcomes + ATT&CK + D3FEND + Diamond + Kill Chain + ISO 27035** | Per `Plans/IR_FRAMEWORKS_REFERENCE.md` |

## Non-Goals

- ed25519 attestations / SLSA provenance / chain hash verification — REMOVED
- Court-of-law admissibility / legal-grade evidence handling — REMOVED
- Wrapping all 200+ SIFT tools — out of scope; current 13 + new ones for Linux/macOS/memory + new IR phases only
- 5 specialist subagents → already exist; no additional Claude Code subagents needed beyond wrapping in LangGraph

## Subsystem Decomposition

The work splits into 6 independent subsystems. Each produces working, testable software on its own. Each has its own sub-plan to be drafted on demand.

### Sub-Plan 01 — Chain-of-Custody Removal
**File:** `2026-05-07-01-chain-removal.md`
**Effort:** 1 day (~2-4 hours actual coding)
**Blast radius:**
- Modify: `mcp-server/src/protocol_sift_mcp/server.py` (drop 3 chain tools)
- Modify: `mcp-server/src/protocol_sift_mcp/tools/evidence.py` (drop chain_init/chain_append/chain_verify/sign_findings/attest, keep `hash_file` + `ingest_artifact`)
- Modify: `mcp-server/src/protocol_sift_mcp/schema.py` (remove ChainEvent, ChainEntry, Attestation; keep Finding/Pin)
- Replace: `.claude/hooks/session-start.sh` (skip chain_init, just hash files into a plain log)
- Replace: `.claude/hooks/audit.sh` (write to plain `audit.jsonl` instead of chain_append)
- Replace: `.claude/hooks/finalize.sh` (skip verify+sign, just close out the audit log)
- Modify: `bin/mh` (drop `cmd_verify`, simplify `cmd_demo`, drop `--with-attest` paths)
- Delete: `keys/` directory and ed25519 keypair
- Delete: `mcp-server/tests/test_evidence.py` chain + attest tests, keep hash tests
- Delete: `.claude/skills/chain-of-custody/`
- Update: `README.md` (drop trust-stack section, attestation table)
- Update: `docs/architecture.md` (drop attest layer)
- Update: `docs/usage.md` (drop verify section)

**Acceptance:**
- `mh run <case>` produces `output/audit.jsonl` (plain) + `output/agent_messages.jsonl` + `findings.json` + `narrative.md` + `accuracy-report.md`
- No `output/chain-of-custody.jsonl` produced
- No `output/case-*.attestation.json` produced
- All existing Windows tests still pass (sandbox + parsers untouched)
- New test: `test_audit_log.py` confirms append-only JSONL written

### Sub-Plan 02 — LangGraph Skeleton
**File:** `2026-05-07-02-langgraph-skeleton.md`
**Effort:** 2 days
**Blast radius:**
- Create: `orchestrator/` Python package (next to `mcp-server/`)
  - `orchestrator/pyproject.toml`
  - `orchestrator/src/mh_orchestrator/__init__.py`
  - `orchestrator/src/mh_orchestrator/state.py` — IncidentState TypedDict
  - `orchestrator/src/mh_orchestrator/graph.py` — StateGraph definition
  - `orchestrator/src/mh_orchestrator/nodes/__init__.py` — node registry
  - `orchestrator/src/mh_orchestrator/nodes/detect.py` — placeholder
  - `orchestrator/src/mh_orchestrator/nodes/triage.py` — invokes existing triage-orchestrator skill
  - `orchestrator/src/mh_orchestrator/cli.py` — `mh-orchestrate run <case-id>` entrypoint
  - `orchestrator/src/mh_orchestrator/claude_node.py` — wrapper that invokes `claude` CLI with subagent
- Create: `orchestrator/tests/test_graph_smoke.py`
- Modify: `bin/mh` (add `cmd_orchestrate` that calls into Python module)
- Modify: top-level `pyproject.toml` (none — orchestrator is a sibling package; wire via venv install)

**Acceptance:**
- `mh-orchestrate run case-001` builds a StateGraph with 3 stub nodes, executes them in order, persists state, writes `agent_messages.jsonl`.
- LangGraph `recursion_limit=N` enforced at graph compile.
- No actual triage logic yet — pure plumbing.
- pytest test confirms graph compiles and state mutates correctly.

### Sub-Plan 03 — IR Phase Nodes (NIST/CSF/PICERL)
**File:** `2026-05-07-03-ir-phase-nodes.md`
**Effort:** 4-5 days
**Blast radius:**
- Create:
  - `orchestrator/src/mh_orchestrator/nodes/analyze.py` — wraps existing windows/macos/linux subagents
  - `orchestrator/src/mh_orchestrator/nodes/attack_tag.py` — enrich findings with MITRE technique IDs
  - `orchestrator/src/mh_orchestrator/nodes/kill_chain.py` — Lockheed stage classifier
  - `orchestrator/src/mh_orchestrator/nodes/contain.py` — D3FEND Isolate recommender
  - `orchestrator/src/mh_orchestrator/nodes/eradicate.py` — D3FEND Evict recommender
  - `orchestrator/src/mh_orchestrator/nodes/recover.py` — D3FEND Restore recommender
  - `orchestrator/src/mh_orchestrator/nodes/lessons_learned.py` — GV.OV + ISO 27035 phase 5
  - `orchestrator/src/mh_orchestrator/nodes/remediation.py` — D3FEND Harden + SP 800-53 controls
  - `orchestrator/src/mh_orchestrator/csf_tags.py` — CSF subcategory ID emitter
  - `orchestrator/src/mh_orchestrator/picerl.py` — PICERL phase tracker
  - `orchestrator/src/mh_orchestrator/diamond.py` — networkx-backed Diamond Model graph
- Create per-node tests: `orchestrator/tests/test_nodes_<name>.py`
- Create:
  - `.claude/skills/containment-recommender/SKILL.md`
  - `.claude/skills/threat-hunting/SKILL.md`
  - `.claude/skills/remediation-planner/SKILL.md`
- Modify: existing `.claude/skills/triage-orchestrator/SKILL.md` (point to LangGraph entrypoint)

**Acceptance:**
- Each node has unit tests with mocked input state, asserts state mutation matches IR framework reference.
- End-to-end smoke: `mh-orchestrate run case-001` walks `detect → triage → analyze → attack_tag → kill_chain → contain → eradicate → recover → lessons_learned → remediation` and writes outputs per Section 11.4 of `IR_FRAMEWORKS_REFERENCE.md`.
- Conditional edges per Section 11.3 implemented (severity gate, RCA loop, blast-radius escalation, re-infection retry).
- Reversibility gate: containment actions with blast_radius > threshold route to `human_in_loop` node that pauses for approval.

### Sub-Plan 04 — D3FEND Knowledge Graph Integration
**File:** `2026-05-07-04-d3fend-integration.md`
**Effort:** 1-2 days
**Blast radius:**
- Create: `orchestrator/src/mh_orchestrator/d3fend/loader.py` — fetch and cache D3FEND OWL/JSON from https://d3fend.mitre.org/
- Create: `orchestrator/src/mh_orchestrator/d3fend/recommender.py` — given ATT&CK technique IDs, return ranked D3FEND countermeasures grouped by tactic (Isolate/Evict/Restore/Harden)
- Create: `corpus/d3fend/d3fend-v1.3.0.json` — pinned snapshot
- Add MCP tool: `mcp__protocol_sift__d3fend_recommend` in `mcp-server/src/protocol_sift_mcp/server.py` + new file `mcp-server/src/protocol_sift_mcp/tools/d3fend.py`
- Tests: `orchestrator/tests/test_d3fend_recommender.py`

**Acceptance:**
- `d3fend_recommend(["T1003.001", "T1486"])` returns structured countermeasures with `(d3fend_id, tactic, name, attack_id_satisfied)`.
- Cached D3FEND graph loads in <1s.
- MCP tool callable from Claude Code subagent.

### Sub-Plan 05 — SIFT Workstation Deployment
**File:** `2026-05-07-05-sift-deployment.md`
**Effort:** 1-2 days
**Blast radius:**
- Create: `scripts/sift-install.sh` — runs on existing SIFT VM, installs Python 3.11 venv + protocol_sift_mcp + orchestrator + Claude Code
- Create: `Dockerfile.sift` — derived from `digitalsleuth/sift-remix-image` or builds atop SIFT 22.04 base
- Modify: `docker-compose.yml` add `memoryhound-sift` service variant
- Update: `README.md` Quickstart section with SIFT path
- Update: `docs/usage.md` add SIFT VM walkthrough

**Acceptance:**
- `bash scripts/sift-install.sh` on a SIFT VM completes in under 5 min and `mh doctor` reports green.
- `docker compose -f docker-compose.yml --profile sift up` builds and runs.
- Smoke test: a no-evidence dry-run completes inside the SIFT-based image.

### Sub-Plan 06 — Hackathon Polish
**File:** `2026-05-07-06-hackathon-polish.md`
**Effort:** 3-4 days
**Blast radius:**
- Demo video script: `docs/demo-script.md` — 5-min walkthrough showing self-correction sequence (Verifier disagrees → orchestrator re-runs analyze with new evidence)
- Record: `docs/demo.mp4` (out-of-band — terminal capture)
- Create: `docs/architecture-v2.md` — replace v1 with LangGraph topology diagram
- Create: `docs/dataset-documentation.md` — populate with corpus contents
- Create: `docs/accuracy-report-template.md` — populated FP/FN/uncertain template
- Create: `docs/inter-agent-message-spec.md` — schema for `agent_messages.jsonl`
- Create: `docs/multi-framework-compliance-map.md` — per-incident CSF + ISO 27035 + IR control coverage map
- Run: `scripts/eval.sh` against full corpus → produce `docs/accuracy-report-final.md`
- Update: `README.md` with hackathon submission section

**Acceptance:**
- All 8 hackathon required deliverables present and verified.
- Demo video shows live terminal + audio + at least one self-correction sequence.
- Submission written and uploaded to Devpost.

## Cross-Cutting Concerns

These touch all sub-plans:

1. **Inter-agent message log format.** All sub-plans 02-04 must write to a single `output/agent_messages.jsonl` schema. Schema lives in Sub-Plan 06 deliverable `docs/inter-agent-message-spec.md`. To unblock 02-04, draft the schema FIRST.

2. **Max-iteration cap.** LangGraph `recursion_limit` configured globally in Sub-Plan 02; every loop edge in Sub-Plan 03 enforces a per-loop cap as well.

3. **Sandbox + read-only evidence.** Existing `sandbox.py` stays. New nodes that touch evidence go through `assert_input_path`. Containment/remediation nodes are advisory-only — they emit recommendations, never execute mitigations.

4. **Self-correction visibility.** Demo video (Sub-Plan 06) requires a real self-correction sequence in logs. Sub-Plan 03 `verifier` integration must produce visible dissent → revise → agree trace.

## Recommended Execution Order

```
Sub-Plan 01 (chain removal)     — Day 1
        │
        ▼
Sub-Plan 02 (LangGraph skeleton) — Days 2-3
        │
        ├──► Sub-Plan 04 (D3FEND)    — Days 4-5  (parallel)
        │
        ▼
Sub-Plan 03 (IR phase nodes)    — Days 6-10
        │
        ▼
Sub-Plan 05 (SIFT deployment)   — Days 11-12
        │
        ▼
Sub-Plan 06 (hackathon polish)  — Days 13-16
```

Total ~16 working days. Buffer of ~10 days against the 5.5-week window for re-work, demo retakes, and bug fixes.

## Risks

| Risk | Mitigation |
|---|---|
| LangGraph + Claude Code subprocess integration is finicky | Sub-Plan 02 includes a 2-hour spike before committing to architecture |
| D3FEND knowledge graph too large to ship in repo | Pinned snapshot in `corpus/d3fend/`; loader caches; fallback to live SPARQL |
| Linux/macOS tools still stubs in IMPLEMENTATION_PLAN — block IR phase nodes? | No — Sub-Plan 03 wraps EXISTING Claude Code subagents which already have skills with full FOR500/APFS/Linux content. The stub MCP tools are a separate concern; nodes can succeed for Windows-only and acknowledge gaps for other OS until tools land |
| SIFT VM build is slow/heavy | Ship install script first (lightweight), Dockerfile.sift as best-effort |
| Demo retakes eat days at the end | Schedule first demo recording on Day 13, not Day 16 |

## Reference Documents

- `Plans/IR_FRAMEWORKS_REFERENCE.md` — canonical NIST/MITRE/SANS/ISO reference (2,705 words, primary-source cited)
- `MEMORY/WORK/20260507-193749_sans-codebase-analysis/PRD.md` — codebase audit (29/29 ISC verified)
- `README.md` — current project state including "What's Real vs Stub" table
- `docs/IMPLEMENTATION_PLAN.md` — original 51-day delivery plan (now superseded by this spec)

---

## Self-Review

**Spec coverage:**
- Hackathon req #1 (public repo Apache-2.0): no change — already there.
- Hackathon req #2 (demo video <5min): Sub-Plan 06.
- Hackathon req #3 (architecture diagram): Sub-Plan 06 v2 diagram.
- Hackathon req #4 (project description): Sub-Plan 06 README + Devpost write-up.
- Hackathon req #5 (dataset documentation): Sub-Plan 06.
- Hackathon req #6 (accuracy report): Sub-Plan 06 against corpus.
- Hackathon req #7 (try-it-out instructions): Sub-Plan 05 + Sub-Plan 06 README update.
- Hackathon req #8 (agent execution logs w/ inter-agent messages): cross-cutting #1 + Sub-Plan 02.
- 6 judging criteria all addressed:
  - #1 Autonomous Execution Quality (tiebreaker) → Sub-Plans 02+03 self-correction
  - #2 IR Accuracy → Sub-Plan 03 verifier loop, Sub-Plan 06 accuracy report
  - #3 Breadth and Depth → Sub-Plans 03+04 (4 IR phases × multi-OS × ATT&CK + D3FEND)
  - #4 Constraint Implementation → existing sandbox + new reversibility gate (Sub-Plan 03 §human_in_loop)
  - #5 Audit Trail Quality → cross-cutting #1 inter-agent log + plain audit log (degraded vs original chain-of-custody, but still structured + traceable)
  - #6 Usability and Documentation → Sub-Plan 05 + Sub-Plan 06

**Open question for user:** Hackathon criterion #5 explicitly rewards traceable audit trails. Removing the hash chain costs points there. Plain JSONL is still traceable but weaker. Confirm acceptable trade-off before drafting Sub-Plan 01 in detail.

**Placeholder scan:** None. Every sub-plan lists exact files, exact acceptance criteria, exact effort estimate.

**Type consistency:** Schema names referenced (`IncidentState`, `Finding`, `Pin`, `Locator`) match existing `mcp-server/src/protocol_sift_mcp/schema.py` and the LangGraph reference Section 11.1.
