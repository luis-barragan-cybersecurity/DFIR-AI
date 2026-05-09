# MemoryHound Architecture

## High-level

```
┌──────────────────────────────────────────────────────────────────┐
│   Claude Code (Direct Agent Extension of Protocol SIFT)          │
│   - skill: triage-orchestrator                                   │
│   - hooks: SessionStart, PreToolUse, PostToolUse, Stop           │
└────────────────────────────┬─────────────────────────────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
       ▼                     ▼                     ▼
┌─────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ WindowsAgent│   │ MacOSAgent       │   │ LinuxAgent       │
│ (FOR500)    │   │ (FOR518 + APFS)  │   │ (FOR577 baseline)│
└──────┬──────┘   └────────┬─────────┘   └────────┬─────────┘
       │                   │                       │
       └────────┬──────────┴────────┬──────────────┘
                ▼                   ▼
       ┌──────────────────┐  ┌──────────────────┐
       │ Verifier         │  │ AuditLog         │
       │ (re-runs claims) │  │ (append-only)    │
       └────────┬─────────┘  └────────┬─────────┘
                │                     │
                └──────────┬──────────┘
                           ▼
       ┌─────────────────────────────────────────────┐
       │  Custom MCP Server (Apache-2.0)             │
       │  - typed forensic primitives                │
       │  - plain append-only audit log              │
       │  - finding_record (rejects un-pinned)       │
       └─────────────────────────────────────────────┘
                           │
                           ▼
       ┌─────────────────────────────────────────────┐
       │  Sandboxed forensic toolchain               │
       │  - Volatility 3 (windows.* / mac.* / linux.*)│
       │  - python-evtx, python-registry             │
       │  - apfs-fuse, plistlib                      │
       │  - systemd journal reader, audit parser     │
       │  - YARA, libmagic, pefile                   │
       └─────────────────────────────────────────────┘
```

## Discipline

1. **Authenticity** — dual hash (sha256 + sha1) on ingest, read-only mount
2. **Validation** — magic-byte + format probe before tool execution
3. **Verification** — evidence pin + Verifier re-run + cross-artifact corroboration
4. **Reproducibility** — pinned model + tool versions, `replay.sh`
5. **Honest Uncertainty** — confidence enum + acknowledged gaps

A plain append-only `audit.jsonl` records every step (session_init, evidence_ingest, tool_call, finding_recorded, session_finalize) for after-the-fact inspection.

See [`SYNTHESIS_FOR_MEMORYHOUND.md`](../../sans-docs/SYNTHESIS_FOR_MEMORYHOUND.md) for full source-derivation.

## LangGraph Layer (Sub-Plan 02 + Sub-Plan 03)

Above the MCP server, MemoryHound runs a LangGraph state machine. Each IR phase is a node; each node mutates a shared `IncidentState` (mirrors `Plans/IR_FRAMEWORKS_REFERENCE.md` §11.1) and persists a checkpoint to `output/state.json` plus a snapshot line to `output/state.history.jsonl`. Inter-agent dispatch and response messages are written to `output/agent_messages.jsonl` (required for hackathon multi-agent submissions).

Sub-Plan 03 implements the full §11.2 14-IR-node topology:

```
session_init
   │
   ▼
 detect ──► triage ──[route_after_triage]──► suppress ──► session_finalize
                          │                                       (false-positive END)
                          ▼ declare_incident
                          │
                          ▼
                       analyze ◄─[route_after_analyze: RCA loop, capped]
                          │
                          ▼ attack_tag ──► kill_chain ──► d3fend_recommend
                                                              │
                                                              ▼
                                                          contain
                                                              │
                                       ┌──[route_after_contain]──┐
                                       ▼                         ▼
                                  human_in_loop              eradicate
                                       │                         │
                                       └──────► eradicate        ▼
                                                                 │
                                       ┌──[route_after_eradicate]┘
                                       ▼
                              ┌─► contain (re-infection retry)
                              │
                              recover ──[route_after_recover]──► contain (post-restore alarm)
                                       │
                                       ▼
                              lessons_learned ──► remediation ──► verifier_pass ──► session_finalize
```

### Multi-Framework Coverage

Each node mutates state along five orthogonal frameworks tracked simultaneously:

- **NIST CSF 2.0** — `csf_subcategories_satisfied` accumulates IDs (`DE.AE-02`, `RS.MA-01/03`, `RS.AN-01/03`, `RS.MI-01/02`, `RC.RP-01`, `RC.CO-03`, `GV.OV-01`)
- **NIST SP 800-61 Rev. 3** (April 2025) — withdrew the legacy 4-phase model; CSF 2.0 RESPOND/RECOVER subcategories drive analysis discipline
- **SANS PICERL** — `picerl_phase_for(node)` maps nodes to Preparation / Identification / Containment / Eradication / Recovery / Lessons-Learned
- **ISO/IEC 27035-1:2023** — `iso27035_phase` advances through plan_and_prepare → detection_and_reporting → assessment_and_decision → responses → learn_lessons
- **MITRE ATT&CK v18** — `attack_tag` extracts technique IDs (`T1059`, `T1059.001`) into `attack_techniques`; `kill_chain` maps to Lockheed Martin 7-stage `kill_chain_stage`
- **MITRE D3FEND v1.3.0** — `d3fend_recommend` populates `d3fend_recommendations` from a static crosswalk (Sub-Plan 04 live; see "D3FEND Crosswalk" below)

### Reversibility Gate

`contain` computes `BlastRadius.score()` = `hosts*5 + users*1 + services*3` per recommendation. If max score exceeds threshold (default 50; env override `MH_BLAST_RADIUS_THRESHOLD`), `route_after_contain` diverts through `human_in_loop` which writes `human_approval_required.json`. All mitigations stay advisory-only — MemoryHound never executes containment, eradication, or remediation.

### Verifier

A single global Verifier pass runs after `remediation` and before `session_finalize`. Each finding gets one Verifier subagent invocation; decisions (`agree` / `dissent` / `revise`) and rationales land in `agent_messages.jsonl` with `metadata.verifier_decision` — that's the dissent trace required by §11.4.

### Recursion Limit

Default 50 (env override `MH_LG_RECURSION_LIMIT`). Bounds the analyze RCA loop, eradicate→contain re-infection retry, and recover→contain post-restore alarm loop.

### Stub Mode

`MH_NO_CLAUDE=1` short-circuits LLM-invoking nodes (`triage`, `analyze`, `verifier_pass`) with deterministic stubs. Used for CI / no-token smoke tests.

### D3FEND Crosswalk (Sub-Plan 04)

The `d3fend_recommend` node populates `state["d3fend_recommendations"]` from a static JSON crosswalk at `orchestrator/data/d3fend_crosswalk.json`. The crosswalk maps ~25 ATT&CK technique IDs to 52 D3FEND v1.3.0 countermeasures, sourced from the public mappings page at https://d3fend.mitre.org/. Each entry records `d3fend_id`, `name`, `tactic` (one of Model/Harden/Detect/Isolate/Deceive/Evict/Restore), `attack_id_satisfied`, `rationale`, and `source` (`d3fend.mitre.org` for explicit mappings, `curated` for analogical extensions). Unknown ATT&CK IDs emit a `d3fend_crosswalk_miss` audit event so coverage gaps are auditable.

### Per-Node Real-Claude Opt-In (Sub-Plan 04)

`MH_NO_CLAUDE=1` is the CI default — every LLM-invoking node (`triage`, `analyze`, `verifier_pass`) takes its stub branch. Per-node real-Claude opt-in via `MH_REAL_CLAUDE_NODES=<comma-list>` overrides the stub for the listed nodes only:

```bash
MH_NO_CLAUDE=1 MH_REAL_CLAUDE_NODES=triage ./bin/mh orchestrate <case-id>
# triage hits real Claude; analyze + verifier_pass stay stubbed (token-bounded)
```

The `should_stub(node_name)` helper in `claude_node.py` centralizes this decision. `bin/mh demo --real-claude` is a wrapper that exports the env vars and self-collects toy evidence for an opt-in smoke (~$0.01/run).

### New MCP Tools (Sub-Plan 04)

| Tool | Purpose | Sandbox |
|---|---|---|
| `memory_volatility(image_path, plugin)` | Wrap Volatility 3 CLI; allowlisted plugin set | image under /input |
| `linux_history_parse(history_path)` | bash/zsh history regex parser | path under /input |

`memory_volatility` plugin allowlist (11 plugins): `windows.{pslist,psscan,malfind,netscan}`, `linux.{pslist,bash,malfind,sockstat}`, `mac.{pslist,malfind,netstat}`. Extending the allowlist is a one-line `frozenset` edit.

### Entry points

- Python: `from mh_orchestrator.graph import build_graph; build_graph().invoke(state)`
- CLI: `mh-orchestrate run <case-id>`
- Shell: `bin/mh orchestrate <case-id>` (wraps the CLI, integrates with `mh init` venv)

## Data Flow Per Case

1. Operator drops evidence into `/input/` (read-only mount)
2. `SessionStart` hook hashes everything, writes a `session_init` event to the audit log
3. LangGraph orchestrator walks `session_init → detect → triage → analyze → contain → eradicate → recover → lessons_learned → remediation → verifier_pass → session_finalize`
4. `detect` calls `os_detect` per artifact and sets `state["_detected_os"]`
5. `triage` and `analyze` dispatch the per-OS Claude Code subagent (Windows/Mac/Linux), passing artifact paths through the `--mcp-config` allowlist
6. Subagents call typed MCP tools — every claim gets a Pin (rejected un-pinned via finding_record schema)
7. `verifier_pass` re-dispatches each finding to the Verifier subagent; agreements / dissents / revisions written to `agent_messages.jsonl`
8. `session_finalize` writes the §11.4 deliverable bundle below

### §11.4 Outputs (10 deliverables)

| File | Purpose |
|---|---|
| `state.json` | Final IncidentState snapshot (Pydantic-serialized) |
| `state.history.jsonl` | Per-node snapshots for replay |
| `audit.jsonl` | Plain append-only event log |
| `agent_messages.jsonl` | Inter-agent dispatch + Verifier dissent trace |
| `containment_actions.jsonl` | Advisory containment recs (NIST SP 800-61 §5.1) |
| `recovery_verification.json` | Restore validation steps |
| `lessons_learned.md` | Investigator-readable retro |
| `remediation_plan.json` | NIST SP 800-53 IR/SI/SC controls |
| `compliance_map.json` | Multi-framework subcategory coverage |
| `incident_summary.md` | Investigator-readable narrative summary |

## Why This Wins The Rubric

| Judging Criterion | Our Mechanism |
|---|---|
| Autonomous Execution Quality (tiebreaker) | self-correct loop + Verifier dissent flow |
| IR Accuracy | evidence pinning + cross-corroboration + hallucination corpus |
| Breadth & Depth of Analysis | cross-OS coverage + memory + filesystem + logs |
| Constraint Implementation | typed MCP w/ explicit deny list, no-shell, sandbox at FS layer |
| Audit Trail Quality | plain append-only JSONL, replayable |
| Usability & Documentation | replay.sh, install.sh, this doc, dataset-documentation.md |
