# MemoryHound

**Drop-in DFIR superpowers for Claude Code.** Autonomous, cross-OS incident-response triage with structured findings, an independent verifier, and a plain audit trail.

Submission to the [SANS FIND EVIL!](https://findevil.devpost.com) Hackathon (Apr 15 – Jun 15, 2026).

> AI threats strike in minutes. Build the defender that responds in seconds.
> — SANS

---

## At a Glance

| | |
|---|---|
| **What** | Autonomous IR triage agent — drop evidence, get a pinned forensic report |
| **How** | Custom MCP server + Claude Code skills/agents/hooks + LangGraph state machine |
| **Surface** | 31 typed forensic tools across 13 modules · 14 skills · 4 specialist subagents · 5 lifecycle hooks · 20-node IR graph (14 IR + `session_init` + `session_finalize` + `suppress` + `correlate` + `manifest_ingest` + `scope`) |
| **OS coverage** | Windows (registry, EVTX, Prefetch, LNK, MFT, Amcache via EZ Tools), macOS (plist, KnowledgeC), Linux (shell history, journald, audit), Memory (Volatility 3 — 45+ plugins; MemProcFS FindEvil), Disk (Sleuth Kit — fls/icat/mmls/mactime/istat), Timeline (Plaso log2timeline + psort), Network (tshark, Zeek), Malware/Carving (YARA, bulk_extractor, binwalk, strings) |
| **Frameworks** | NIST CSF 2.0 · ISO/IEC 27035-1:2023 · SANS PICERL · MITRE ATT&CK · D3FEND |
| **Trust** | Schema-rejected un-pinned findings · independent Verifier subagent with self-correction loop · cross-finding Correlator · **sha256-chained audit log** · **SHA256 manifest at ingest** · `mh verify` spoliation re-check |
| **Deploy** | One-line installer (`bash scripts/install.sh`) · Host install · Docker (advanced — see [`docs/deployment.md`](docs/deployment.md)) |
| **Auth** | Pro/Max subscription · Anthropic API key · Bedrock · Vertex |
| **Code** | ~10K LoC Python · 58 test files · 360 tests · CI green |
| **Demo video** | _Recording in W6 (May 31 – Jun 6, 2026) — link added on upload._ Must show verifier dissent → re-analyze self-correction (per hackathon rules). |

---

## What This Is

MemoryHound turns Claude Code into an autonomous DFIR analyst. You drop evidence into a folder, run one command, and get back a structured forensic report whose every claim is pinned to a specific tool call against a specific artifact.

Inspired by Daniel Miessler's [PAI](https://github.com/danielmiessler/PAI) pattern: the `.claude/` directory plus a custom MCP server give Claude the skills, subagents, hooks, and forensic primitives to operate as a domain specialist — without modifying Claude itself.

```
You drop:    Evidence files (memory dumps, registry hives, EVTX, plist, etc.)
You run:     mh run <case-id>     OR     mh orchestrate <case-id>
You get:     Pinned findings, investigative narrative, accuracy report,
             audit log, multi-framework compliance map
```

Two execution modes with the same trust contract:

- **`mh run <case-name|file-path|folder-path> --interactive`** — free-form Claude Code session driven by the `triage-orchestrator` skill. Best for exploratory casework.
- **`mh orchestrate`** — deterministic LangGraph state machine walking the §11.2 14-IR-node topology. Best for repeatable, framework-aligned IR.

---

## Quickstart

One command from a freshly cloned repo to a working install:

```bash
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound && cd memoryhound
bash scripts/install.sh
```

The installer checks Python 3.11+, checks the `claude` CLI, then runs `bin/mh init` (creates `.venv`, installs deps). It surfaces missing system packages with the exact `brew`/`apt` command to fix them — it never installs anything for you silently.

Once installed, sign in to Claude Code (one-time) and run the quickstart:

```bash
claude /login                     # Pro/Max subscription (recommended)
# OR
export ANTHROPIC_API_KEY=sk-ant-...   # API key

./bin/mh quickstart               # auth check + stub demo (no tokens spent)
```

After `mh quickstart` finishes, full IR triage is **one command**. Point it at a file, a folder, or an existing case name — it figures out the rest:

```bash
./bin/mh run /path/to/memory.raw          # auto-wraps the file into a new case
./bin/mh run /path/to/evidence-folder/    # auto-wraps the folder into a new case
./bin/mh run case-001                     # uses cases/case-001/input/
```

That single command drives the entire IR pipeline: SHA256 manifest, ingest, OS detection, skill routing (FOR500 / FOR518 / FOR577), Windows/macOS/Linux subagent triage, Volatility memory analysis, Verifier dissent loop, MITRE ATT&CK tagging, NIST CSF 2.0 / ISO 27035 / PICERL framework mapping, D3FEND countermeasures, containment + remediation plans, narrative, accuracy report, sha256-chained audit log. Add `--interactive` for the skill-driven free-form Claude TUI (live tool calls visible) when you want to explore manually.

After triage:

```bash
./bin/mh serve                    # browse findings at http://127.0.0.1:8765/
./bin/mh report --exec case-001   # one-page executive summary
./bin/mh verify case-001          # chain-of-custody re-hash; exit 0 on no spoliation
```

> Need a containerized run, a SIFT/Ubuntu host bootstrap with the full forensics toolchain, or the prebuilt image? See [`docs/deployment.md`](docs/deployment.md).

---

## Demo — 60 Seconds, No API Key Needed

The demo proves the end-to-end pipeline without spending a token:

```bash
./bin/mh init       # if not already done
./bin/mh demo
```

Output:

```
» Step 1: self-collect safe host artifacts            ✓
» Step 2: ingest, hash, write to audit log            ✓
» Step 3: classify each artifact with os_detect       ✓
» Step 4: parse plist contents                        ✓
```

**Real-Claude smoke (opt-in):**

```bash
./bin/mh demo --real-claude       # ~$0.01, ≤1500 tokens, triage subagent only
```

---

## Architecture

> Every architecture claim below is grounded in a specific file. The codebase is the source of truth — diagrams summarize it, not the other way around.

### System Layers

```
┌──────────────────────────────────────────────────────────────────┐
│  USER                                                             │
│  Drops evidence into cases/<id>/input/                            │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  CLI WRAPPER          bin/mh                                      │
│  Bash dispatcher with 14 subcommands; manages venv + auth +       │
│  fresh-cycle output reset; shells out to claude or mh-orchestrate │
└─────────────┬───────────────────────────────────┬─────────────────┘
              │                                   │
              ▼                                   ▼
┌────────────────────────────────┐  ┌────────────────────────────────┐
│  EXECUTION MODE A              │  │  EXECUTION MODE B              │
│  Skill-driven (free-form)      │  │  LangGraph (deterministic)     │
│                                │  │                                │
│  claude --mcp-config …         │  │  mh-orchestrate run <id>       │
│   │                            │  │   │                            │
│   ▼                            │  │   ▼                            │
│  triage-orchestrator skill     │  │  17-node IR graph + 6          │
│   │                            │  │  conditional edges             │
│   ├─→ WindowsAgent             │  │   │                            │
│   ├─→ MacOSAgent               │  │   ├─→ ClaudeNode (LLM)         │
│   ├─→ LinuxAgent               │  │   ├─→ deterministic nodes      │
│   └─→ Verifier                 │  │   └─→ Verifier pass            │
│                                │  │                                │
│  .claude/skills/*/SKILL.md     │  │  orchestrator/src/             │
│  .claude/agents/*.md           │  │   mh_orchestrator/nodes/       │
└────────────┬───────────────────┘  └────────────┬───────────────────┘
             │                                   │
             └──────────────┬────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│  CUSTOM MCP SERVER     mcp-server/src/protocol_sift_mcp/         │
│  ─ stdio protocol; 31 typed tools across 13 modules              │
│  ─ schema-rejects findings without pins (finding.py)             │
│  ─ path-escape sandbox (sandbox.py); evidence read-only          │
│  ─ writes audit.jsonl + findings.json directly                   │
└────────────────────────────┬──────────────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  FORENSIC TOOLCHAIN     (vendored or pip-installed)              │
│  ─ Volatility 3 (windows.* / mac.* / linux.* plugin families)    │
│  ─ python-registry, python-evtx, pylnk3, windowsprefetch         │
│  ─ plistlib, libmagic, hashlib                                   │
│  ─ ISF symbols vendored at corpus/<case>/symbols/                │
└──────────────────────────────────────────────────────────────────┘
```

### Two Execution Modes Compared

| | **`mh run`** (skill-driven) | **`mh orchestrate`** (LangGraph) |
|---|---|---|
| Driver | `triage-orchestrator` skill in a Claude Code session | `mh-orchestrate run` invoking compiled `StateGraph` |
| Determinism | Free-form within the skill spec | 20 nodes, 6 typed conditional edges |
| Output deliverables | 4 files (audit, findings, narrative, accuracy-report) | 10 §11.4 files (state, history, audit, agent_messages, containment, recovery, lessons, remediation, compliance, summary) |
| LLM calls | All triage steps | Only `ClaudeNode` calls; deterministic nodes are pure Python |
| Stub mode | n/a | `MH_NO_CLAUDE=1` short-circuits LLM nodes |
| Re-route on dissent | Skill spec says re-run subagent | `verifier_pass` → `analyze` (capped at 1 revision) |
| Source | `.claude/skills/triage-orchestrator/SKILL.md` | `orchestrator/src/mh_orchestrator/graph.py` |

### LangGraph Topology

The orchestrator implements the §11.2 14-IR-node topology from `Plans/IR_FRAMEWORKS_REFERENCE.md`, plus `session_init`, `session_finalize`, `suppress` (false-positive path), `correlate` (cross-finding linker after `verifier_pass`), `manifest_ingest` (chain-of-custody manifest), and `scope` (multi-host scoping) — **20 nodes total**. Six conditional edges (§11.3) govern branching and bounded loops.

```mermaid
flowchart TD
    SI[session_init] --> D[detect]
    D --> T[triage]
    T -->|severity ∈ {low,info}<br/>and findings=∅| SP[suppress]
    T -->|else| DI[declare_incident]
    DI --> A[analyze]
    A -->|RCA incomplete<br/>and iter < 3| A
    A -->|RCA complete<br/>OR cap reached| AT[attack_tag]
    AT --> KC[kill_chain]
    KC --> D3[d3fend_recommend]
    D3 --> C[contain]
    C -->|blast > threshold| HIL[human_in_loop]
    C -->|else| E[eradicate]
    HIL --> E
    E -->|reinfection| C
    E -->|clean| R[recover]
    R -->|post-restore alarm| C
    R -->|clean| LL[lessons_learned]
    LL --> RM[remediation]
    RM --> VP[verifier_pass]
    VP -->|dissent and<br/>revisions < 1| A
    VP -->|complete| SF[session_finalize]
    SP --> SF
    SF --> END([END])
```

**Six conditional edges** (`graph.py:43–149`):

| Edge | Source line | §11.3 row | NIST CSF tag | Trigger |
|------|-------------|-----------|--------------|---------|
| `route_after_triage` | `graph.py:43` | row 1 | RS.MA-03 | severity ∈ {low, informational} ∧ findings=∅ → `suppress`; else → `declare_incident` |
| `route_after_analyze` | `graph.py:60` | row 2 | RS.AN-03 | RCA loop, capped at 3 iterations (`_ANALYZE_ITER_CAP`) |
| `route_after_contain` | `graph.py:73` | row 3 | IR-7 | blast-radius score > `MH_BLAST_RADIUS_THRESHOLD` (default 50) → `human_in_loop` |
| `route_after_eradicate` | `graph.py:97` | row 4 | PICERL phase 4 retry | re-infection detected → loop back to `contain` |
| `route_after_recover` | `graph.py:108` | row 5 | RC.RP-01 | post-restore alarm → re-contain |
| `route_after_verifier_pass` | `graph.py:119` | dissent edge | — | dissent ∧ revision available → re-`analyze`; else → `session_finalize` |

### IncidentState Schema

`orchestrator/src/mh_orchestrator/state.py` mirrors §11.1 of the framework reference. Public fields are visible to every node; underscore-prefixed fields are internal plumbing.

| Public field | Type | Purpose |
|--------------|------|---------|
| `incident_id` | `str` | Stable case identifier |
| `severity` | `low \| medium \| high \| critical \| unknown` | Triage verdict |
| `phase` | `detect \| triage \| analyze \| contain \| eradicate \| recover \| lessons` | Current PICERL phase |
| `kill_chain_stage` | `int` | Lockheed Martin Cyber Kill Chain stage (0–7) |
| `attack_techniques` | `list[str]` | MITRE ATT&CK technique IDs |
| `forensic_artifacts` | `list[Artifact]` | Pinned evidence with hash + label |
| `csf_subcategories_satisfied` | `set[str]` | NIST CSF 2.0 subcategory IDs |
| `iso27035_phase` | `str` | Plan / Detect / Assess / Respond / Lessons |
| `d3fend_recommendations` | `list[Countermeasure]` | D3FEND countermeasures |
| `containment_actions` / `eradication_actions` / `recovery_actions` | `list[dict]` | Advisory actions, never executed |
| `remediation_plan` | `list[dict]` | NIST SP 800-53 IR/SI/SC controls |

### Trust Contract — Five Layers of "No Hallucinations"

```
1. SCHEMA            mcp-server/src/protocol_sift_mcp/tools/finding.py
                     finding_record() rejects un-pinned claims at the
                     MCP schema layer (pins[].minItems = 1).

2. TOOL BOUNDARY     .claude/hooks/guard.sh   (PreToolUse)
                     Re-rejects un-pinned finding_record calls plus
                     any Bash, Write to /input, or network egress.

3. SANDBOX           mcp-server/src/protocol_sift_mcp/sandbox.py
                     Path-escape rejection on every tool call.
                     Evidence mounted read-only.

4. AUDIT             .claude/hooks/audit.sh   (PostToolUse)
                     Every tool call appended to cases/<id>/output/audit.jsonl.

5. VERIFIER          .claude/agents/verifier.md  +
                     orchestrator/.../nodes/verifier_pass.py
                     Independent subagent re-runs the cited tool against
                     the cited evidence with NO context from the
                     originating agent. Disagreements re-route through
                     analyze (capped at 1 revision).
```

Confidence enum (`triage-orchestrator/SKILL.md`):

- **`confirmed`** — corroborated across ≥2 independent artifacts
- **`inferred`** — single artifact, well-understood semantics
- **`uncertain`** — observation suggestive but not conclusive
- **`unknown`** — explicit gap; pinned, never guessed

### MCP Tool Surface (31 tools, 13 modules)

`mcp-server/src/protocol_sift_mcp/tools/` ([source](mcp-server/src/protocol_sift_mcp/tools/)):

| Module | Tools | Purpose |
|--------|-------|---------|
| `audit.py` | `audit_append` | Append-only event log |
| `evidence.py` | `hash` | sha256 + sha1 + size of any artifact |
| `finding.py` | `finding_record` | Schema-validated pinned findings (rejects un-pinned) |
| `parse.py` | `os_detect`, `magic_check` | Cross-OS routing primitives |
| `windows.py` | `win_registry_get`, `win_prefetch_parse`, `win_evtx_query`, `win_lnk_parse` | FOR500-aligned native Windows triage |
| `win_artifacts.py` | `ez_evtxecmd`, `ez_mftecmd`, `ez_recmd`, `ez_amcacheparser` | EZ Tools wrappers (EVTX, MFT, registry, Amcache) |
| `macos.py` | `mac_plist_get`, `mac_knowledgec_query` | FOR518-aligned macOS triage |
| `linux.py` | `linux_history_parse` | Bash + zsh history (FOR577) |
| `memory.py` | `memory_volatility`, `memprocfs_findevil` | Volatility 3 (11-plugin allowlist) + MemProcFS FindEvil |
| `filesystem.py` | `tsk_fls`, `tsk_icat`, `tsk_mmls`, `tsk_mactime`, `tsk_istat` | The Sleuth Kit — file listing, content extract, partition map, timeline, inode stat |
| `timeline.py` | `plaso_log2timeline`, `plaso_psort` | Plaso super-timeline build + sort |
| `network.py` | `tshark_extract`, `zeek_log_read` | tshark protocol extract, Zeek log reader |
| `carving.py` | `yara_scan`, `bulk_extractor`, `binwalk`, `strings_extract` | Malware/carving — YARA rule scan, bulk_extractor, binwalk, strings |

### Claude Code Layer

`.claude/` ([source](.claude/)):

| Surface | Count | Files |
|---------|-------|-------|
| Skills | 14 | `triage-orchestrator`, `windows-triage`, `macos-triage`, `linux-triage`, `memory-forensics`, `evidence-pin`, `gap-acknowledgment`, `self-correct`, `ir-narrative`, `accuracy-report`, `exec-report`, `containment-recommender`, `remediation-planner`, `threat-hunting` |
| Subagents | 4 | `WindowsAgent`, `MacOSAgent`, `LinuxAgent`, `Verifier` |
| Hooks | 5 | `session-start.sh` (ingest+hash), `inject-context.sh` (UserPromptSubmit), `guard.sh` (PreToolUse trust gate), `audit.sh` (PostToolUse log), `finalize.sh` (Stop summary) |
| Permissions | — | `allow: mcp__protocol_sift__*, Read, Glob, Grep` · `deny: Bash, WebFetch, WebSearch, Edit, Write, mcp__filesystem__write_*` |

The `bin/mh:claude_run` wrapper extends the headless `--allowedTools` set to also include `Write` and `TodoWrite` so the agent can land `narrative.md` and `accuracy-report.md` without an interactive approval channel.

---

## Output Schemas

### `mh run` deliverables — `cases/<id>/output/`

| File | Schema | Purpose |
|------|--------|---------|
| `audit.jsonl` | `{seq, ts, event, data}` | Append-only log of every step |
| `findings.json` | `[{finding_id, claim, confidence, pins[], mitre_attck[]}]` | Structured findings, schema-validated |
| `narrative.md` | Investigator prose | Plain-English report with timeline, IOCs, gaps |
| `accuracy-report.md` | TP/FP/FN/uncertain tally | Honest accuracy disclosure |

### `mh orchestrate` deliverables — `cases/<id>/output/` (§11.4, 10 files)

| File | Source node | Purpose |
|------|------------|---------|
| `state.json` | `session_finalize` | Final IncidentState (Pydantic-serialized) |
| `state.history.jsonl` | every node | One snapshot per node exit |
| `audit.jsonl` | `nodes/__init__.record_audit` | Append-only event log |
| `agent_messages.jsonl` | `nodes/__init__.emit_message` | Inter-agent + Verifier dissent trace |
| `containment_actions.jsonl` | `contain` | Advisory NIST SP 800-61 §5.1 recs |
| `recovery_verification.json` | `recover` | Restore validation steps |
| `lessons_learned.md` | `lessons_learned` | Investigator retro |
| `remediation_plan.json` | `remediation` | NIST SP 800-53 IR/SI/SC controls |
| `compliance_map.json` | `session_finalize` | CSF 2.0 + ISO 27035 + ATT&CK + kill-chain |
| `incident_summary.md` | `session_finalize` | Investigator-readable narrative |

### Pin Schema (mandatory on every finding)

```json
{
  "artifact": "/input/memory.raw",
  "tool": "mcp__protocol_sift__memory_volatility",
  "locator": {"type": "file_offset", "value": "psscan@0x1cdbeb00"},
  "raw_excerpt": "explorer.exe PID=1172 PPID=2024 Threads=32 …",
  "captured_at": "2026-05-10T01:55:01Z"
}
```

---

## CLI Reference (`bin/mh`)

```
mh init [--with-forensics]   First-time setup: venv, deps.
                             --with-forensics adds heavy libs (Volatility, etc.)
mh doctor                    Health check across env, deps, auth.
mh demo [--real-claude]      Showcase run — no real evidence, no tokens
                             (--real-claude does one ≤1500-token smoke test).
mh run <case-id>             Skill-driven Claude Code triage on cases/<id>/input/.
mh orchestrate <case-id>     Full §11.2 LangGraph IR state machine.
mh report <case-id>          Plain-English summary (no LLM, no tokens).
mh serve [--port=8765]       Local web viewer for findings + narrative.
mh status                    List cases + their phase.
mh tools                     List MCP tools the agent can call.
mh check                     Quick env probe (exit 0/1).
mh help                      Show this list.
```

Each command is a `cmd_*` function in `bin/mh`; subcommand source lines are easy to grep:

```bash
grep -nE "^cmd_[a-z]+\(\)" bin/mh
```

---

## Configuration

### Environment Variables

| Variable | Effect | Default |
|----------|--------|---------|
| `ANTHROPIC_API_KEY` | API-key auth (alternative to `claude /login`) | unset |
| `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` | Cloud-provider auth | unset |
| `MH_HOME` | Project root override | repo dir |
| `MH_VENV` | Python venv path | `$MH_HOME/.venv` |
| `MH_NO_CLAUDE` | Stub LLM-invoking nodes (CI / no-token testing) | `0` |
| `MH_BLAST_RADIUS_THRESHOLD` | `route_after_contain` escalation cutoff | `50` |
| `MH_LG_RECURSION_LIMIT` | LangGraph recursion cap (default 50, ~3× headroom over 15-node happy path) | `50` |
| `MH_CLAUDE_HEADLESS` | `claude -p` print mode for CI/scripts | `0` |
| `MH_DEMO_NONINTERACTIVE` | Skip the `mh demo --real-claude` y/N prompt | `0` |
| `VOLATILITY_SYMBOL_PATH` | Vendored ISF symbols (Linux/macOS kernels) | `corpus/<case>/symbols/` |

### Auth modes (inherits from Claude Code)

- **Pro/Max subscription** — `claude /login` once; persistent `~/.claude/`
- **Anthropic API key** — `export ANTHROPIC_API_KEY=sk-ant-...`
- **AWS Bedrock** — `export CLAUDE_CODE_USE_BEDROCK=1`
- **Google Vertex** — `export CLAUDE_CODE_USE_VERTEX=1`

---

## Capability Matrix

| Component | Status |
|---|---|
| Sandbox (path-escape rejection, deny-list hooks) | ✅ live |
| `os_detect`, `magic_check` (cross-OS routing) | ✅ live |
| Windows tools: `win_registry_get`, `win_prefetch_parse`, `win_evtx_query`, `win_lnk_parse` | ✅ live |
| 13 Claude Code skills (FOR500 / APFS / Linux + IR planners) | ✅ live |
| 4 specialist subagents (Windows / macOS / Linux / Verifier) | ✅ live |
| 5 hooks (session-start / inject-context / guard / audit / finalize) | ✅ live |
| `mh` CLI + `mh-mcp-server` portable launcher | ✅ live |
| LangGraph orchestrator (full §11.2 17-node topology, 6 conditional edges) | ✅ live |
| Multi-framework state (CSF 2.0 + ISO 27035 + PICERL + ATT&CK + kill-chain) | ✅ live |
| Reversibility gate + human-in-loop + Verifier pass | ✅ live |
| §11.4 deliverables (10 outputs incl. compliance_map + incident_summary) | ✅ live |
| `memory_volatility` (Volatility 3 CLI, 11-plugin allowlist) | ✅ live |
| Mimikatz / credential-extraction allowlist (`windows.lsadump`, `hashdump`, `cmdline`, `dlllist`, `svcscan`, `handles`) | ✅ live (allowlisted; OtterCTF staging) |
| `linux_history_parse` (bash/zsh formats) | ✅ live |
| D3FEND ATT&CK → countermeasure crosswalk (25 techniques, 52 countermeasures) | ✅ live |
| `mh demo --real-claude` opt-in real-Claude smoke | ✅ live (gated test in CI) |
| Verifier dissent → analyze re-route (one-shot self-correction) | ✅ live |
| Subagent failure paths (loud RuntimeError on analyze; `tool_failure` on verifier; `severity=unknown` on triage) | ✅ live |
| Pre-commit gate (ruff + pytest + license check) | ✅ live |
| `mac_*` macOS tools (apfs / tracev3 / spotlight) | 🛠️ Sub-Plan 06+ |
| `linux_journal_query`, `linux_audit_query`, `linux_systemd_units` | 🛠️ Sub-Plan 06+ |

**213 tests passing** (75 mcp-server + 138 orchestrator + 2 opt-in skips). CI green on every commit.

---

## Project Structure

```
memoryhound/
├── bin/
│   ├── mh                    # 11-subcommand bash dispatcher (claude_run + cmd_*)
│   └── mh-mcp-server         # MCP server launcher (used by both modes)
│
├── mcp-server/               # Custom MCP server — typed forensic primitives
│   ├── src/protocol_sift_mcp/
│   │   ├── server.py         # 13 Tool() declarations, stdio wiring
│   │   ├── sandbox.py        # path-escape rejection
│   │   ├── schema.py         # Pin / Finding pydantic schemas
│   │   └── tools/            # 8 modules (audit/evidence/finding/parse/windows/macos/linux/memory)
│   └── tests/                # 12 test files
│
├── orchestrator/             # LangGraph IR state machine
│   ├── src/mh_orchestrator/
│   │   ├── graph.py          # build_graph(): 17 nodes, 6 conditional edges
│   │   ├── state.py          # IncidentState TypedDict (§11.1)
│   │   ├── claude_node.py    # ClaudeNode abstraction for LLM-invoking nodes
│   │   ├── blast_radius.py   # contain() reversibility scorer
│   │   ├── csf_tags.py       # NIST CSF 2.0 subcategory tagging
│   │   ├── d3fend_crosswalk.py   # ATT&CK → D3FEND mapping
│   │   ├── picerl.py         # PICERL phase mapping
│   │   ├── persistence.py    # state.history.jsonl writer
│   │   ├── cli.py            # mh-orchestrate run <id>
│   │   └── nodes/            # 17 node implementations (one .py per node)
│   └── tests/                # 28 test files
│
├── .claude/                  # Claude Code config (PAI pattern)
│   ├── settings.json         # permissions + MCP wiring + 5 hooks
│   ├── mcp-config.json       # standalone MCP config for headless mode
│   ├── skills/               # 13 SKILL.md (one per skill)
│   ├── agents/               # 4 subagents (Windows/MacOS/Linux/Verifier)
│   └── hooks/                # 5 lifecycle .sh hooks
│
├── scripts/
│   ├── install-sift.sh       # SIFT/Ubuntu host bootstrap
│   ├── install.sh            # generic host bootstrap
│   ├── fetch-isf-symbols.sh  # ISF kernel symbol fetcher
│   ├── self-collect.sh       # demo evidence collector
│   ├── plain-summary.py      # mh report (no LLM)
│   ├── serve.py              # mh serve (local viewer)
│   └── replay.sh, eval.sh, record-demo.sh, …
│
├── corpus/                   # Vendored evidence + ground truth
│   ├── _template/            # Per-case template
│   └── dfrws-2008-memory/    # First public corpus case
│       ├── ground-truth.json
│       └── symbols/          # ISF symbols (gitignored binaries)
│
├── docs/
│   ├── architecture.md       # Deep-dive system design
│   ├── deployment.md         # Three deployment paths in detail
│   ├── usage.md              # End-to-end walkthrough
│   ├── development.md        # Pre-commit + CI workflow
│   ├── dataset-documentation.md
│   └── superpowers/plans/    # Master spec + sub-plan history
│
├── cases/                    # Per-case input/output (gitignored)
│   └── <case-id>/
│       ├── input/            # Evidence (read-only)
│       └── output/           # Audit log + findings + reports
│
├── Dockerfile                # Multi-stage runtime image (Sub-Plan 05)
├── docker-compose.yml        # Local-build compose (two services)
└── .pre-commit-config.yaml   # ruff + pytest + license check
```

Top-of-tree counts (current branch):
- **Python:** ~10K LoC (3.5K mcp-server + 4.7K orchestrator + 1.8K scripts)
- **Tests:** 41 test files, 213 tests passing
- **Skills:** 13 · **Subagents:** 4 · **Hooks:** 5 · **MCP tools:** 13
- **LangGraph nodes:** 17 (14 IR + session_init + session_finalize + suppress)
- **Conditional edges:** 6

---

## Development

### Running the test suite

```bash
.venv/bin/python -m pytest mcp-server/tests orchestrator/tests
```

Per-area:

```bash
.venv/bin/python -m pytest mcp-server/tests        # 75 tests, ~3s
.venv/bin/python -m pytest orchestrator/tests      # 138 tests, ~6s
```

Opt-in real-Claude smoke (~$0.01, ≤1500 tokens):

```bash
RUN_REAL_CLAUDE=1 .venv/bin/python -m pytest orchestrator/tests/test_demo_real_claude.py
```

### Pre-commit gates

`.pre-commit-config.yaml` runs on every commit:

- `ruff check` + `ruff format` (linting + formatting)
- `pytest` (full suite)
- License-header check on Python sources
- `shellcheck` on `bin/mh` and hooks

```bash
pre-commit install            # one-time
pre-commit run --all-files    # manual full run
```

### CI

`.github/workflows/` runs the same suite on push + PR, plus builds and pushes the Docker image to `ghcr.io/saivarun3407/memoryhound` on tagged releases.

### Adding a new MCP tool

1. Drop the implementation into `mcp-server/src/protocol_sift_mcp/tools/<family>.py`
2. Register the `Tool()` declaration in `mcp-server/src/protocol_sift_mcp/server.py`
3. Add a smoke test in `mcp-server/tests/test_<family>.py`
4. Allowlist the tool in `bin/mh:38` (`claude_run` `--allowedTools`) — headless mode skips the consent prompt for allowlisted tools only

### Adding a new LangGraph node

1. Create `orchestrator/src/mh_orchestrator/nodes/<name>.py` exporting `def run(state: IncidentState) -> IncidentState`
2. Register it in `orchestrator/src/mh_orchestrator/nodes/__init__.py:NODES`
3. Wire edges in `orchestrator/src/mh_orchestrator/graph.py:build_graph`
4. Add a unit test in `orchestrator/tests/test_node_<name>.py`

---

## Hackathon Deliverables (8 / 8)

| # | Deliverable | Where |
|---|---|---|
| 1 | Public GitHub repo (Apache-2.0) | this repo, [`LICENSE`](LICENSE) at root |
| 2 | Demo video < 5 min | *W6 — May 31 – Jun 6* |
| 3 | Architecture diagram | this README + [`docs/architecture.md`](docs/architecture.md) |
| 4 | Project description | this README + [`docs/usage.md`](docs/usage.md) |
| 5 | Evidence dataset documentation | [`docs/dataset-documentation.md`](docs/dataset-documentation.md) + [`corpus/README.md`](corpus/README.md) |
| 6 | Accuracy report | `cases/<id>/output/accuracy-report.md` per run |
| 7 | Deployment / setup instructions | this Quickstart + [`docs/deployment.md`](docs/deployment.md) |
| 8 | Agent execution logs (timestamps + tokens) | `cases/<id>/output/audit.jsonl` |

---

## Documentation Index

- [`docs/architecture.md`](docs/architecture.md) — full system design, beyond what this README covers
- [`docs/deployment.md`](docs/deployment.md) — three deployment paths in detail
- [`docs/usage.md`](docs/usage.md) — end-to-end walkthrough with a worked example
- [`docs/development.md`](docs/development.md) — pre-commit + CI workflow
- [`docs/dataset-documentation.md`](docs/dataset-documentation.md) — evidence corpus + ground truth
- [`docs/superpowers/plans/2026-05-07-find-evil-master.md`](docs/superpowers/plans/2026-05-07-find-evil-master.md) — current master spec (supersedes earlier plan)
- [`corpus/README.md`](corpus/README.md) — evidence corpus layout

---

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

## Acknowledgments

- **SANS Institute** — SIFT Workstation, FOR500 / FOR518 / FOR577 curricula, FIND EVIL! hackathon
- **The DFIR community** — 19 years of open tooling
- **Volatility Foundation** — Volatility 3
- **Anthropic** — Claude Code, MCP
- **Daniel Miessler** — [PAI](https://github.com/danielmiessler/PAI) pattern for AI-as-domain-specialist
