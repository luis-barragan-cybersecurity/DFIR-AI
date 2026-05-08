# MemoryHound

**Drop-in DFIR superpowers for Claude Code.** Autonomous, cross-OS incident response triage with structured findings and a plain audit trail.

Submission to the [SANS FIND EVIL!](https://findevil.devpost.com) Hackathon (Apr 15 – Jun 15, 2026).

> AI threats strike in minutes. Build the defender that responds in seconds.
> — SANS

## What This Is

MemoryHound turns Claude Code into an autonomous DFIR analyst. Drop evidence into a folder, run one command, get a structured forensic report.

Inspired by Daniel Miessler's [PAI](https://github.com/danielmiessler/PAI) pattern: the `.claude/` directory plus a custom MCP server give Claude the skills, agents, hooks, and forensic primitives to operate as a domain specialist — without modifying Claude itself.

```
You drop:    Evidence files (memory dumps, registry hives, EVTX, plist, etc.)
You run:     mh run <case-id>
You get:     Structured findings, investigative narrative, plain audit log
```

## Works With Both Auth Modes

MemoryHound is a layer on top of Claude Code. Whatever auth Claude Code uses, MemoryHound inherits.

- ✅ **Claude Pro / Max subscription** — `claude /login` once, you're done
- ✅ **Anthropic API key** — `export ANTHROPIC_API_KEY=sk-ant-...`
- ✅ **AWS Bedrock / Google Vertex** — set `CLAUDE_CODE_USE_BEDROCK=1` or `CLAUDE_CODE_USE_VERTEX=1`

## Quickstart

```bash
# 1. Clone + install (one time)
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound
cd memoryhound
./bin/mh init                                    # creates .venv, installs deps
./bin/mh doctor                                  # confirms env is healthy

# 2. Choose your auth (one time)
claude /login                                    # subscription
# OR
export ANTHROPIC_API_KEY=sk-ant-...             # API key

# 3. Drop evidence + run triage
mkdir -p cases/case-001/input
cp /path/to/evidence/* cases/case-001/input/
./bin/mh run case-001
```

Output lands in `cases/case-001/output/`:

| File | Purpose |
|---|---|
| `audit.jsonl` | Plain append-only audit log of every step |
| `findings.json` | Structured findings, every claim pinned |
| `narrative.md` | Investigator-ready prose report |
| `accuracy-report.md` | Honest FP / FN / hallucination tally |

## See It Work In 60 Seconds (No API Key Needed)

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

This is the 15 seconds of footage that wins the hackathon's Audit Trail Quality criterion.

## Architecture

```
You → claude (CLI) → triage-orchestrator skill
                            │
        ┌───────────────────┼─────────────────────┬──────────┐
        ▼                   ▼                     ▼          ▼
  WindowsAgent         MacOSAgent            LinuxAgent   MemoryAgent
  (FOR500 KB)          (APFS + plist)        (journal)    (Volatility 3)
        │                   │                     │          │
        └───────┬───────────┴───────┬─────────────┘──────────┘
                ▼                   ▼
           Verifier        AuditLog
        (re-runs claims)   (plain append-only)
                │                   │
                └─────────┬─────────┘
                          ▼
              Custom MCP Server (Apache-2.0)
              ─ typed forensic primitives
              ─ NO shell, NO destructive ops
              ─ schema-enforced finding records
```

## Discipline

MemoryHound enforces a hard contract: every finding requires a structured evidence pin (artifact + tool + locator + raw excerpt). The MCP server rejects un-pinned claims at the schema layer; the PreToolUse hook rejects them again at the tool boundary. An independent Verifier subagent re-runs the cited tool against the cited evidence and dissents if it cannot reproduce the claim. Gaps are recorded explicitly with `confidence='unknown'` rather than fabricated.

## Supported Operating Systems

- **Windows** (10 / 11) — registry, EVTX, Prefetch, LNK, ShellBags, Recycle Bin, browser, USB, cloud connectors
- **macOS** — APFS, plist, Unified Logs (`tracev3`), KnowledgeC, Spotlight *(W3 in progress)*
- **Linux** — systemd journal, audit log, shell history, persistence vectors *(W4 in progress)*
- **Memory** (cross-OS) — Volatility 3 windows.* / mac.* / linux.* plugin families *(W2-W4)*

## CLI Reference

```
mh init [--with-forensics]   First-time setup: venv, deps.
                             --with-forensics adds heavy libs (Volatility, etc.)
mh doctor                    Health check across env, deps, auth.
mh demo                      Showcase run — no real evidence, no tokens.
mh run <case-id>             Run Claude Code triage on cases/<id>/input/.
mh status                    List cases + their phase.
mh tools                     List MCP tools the agent can call.
mh check                     Quick env probe (exit 0/1).
```

## What's Real vs Stub

| Component | Status |
|---|---|
| Sandbox (path-escape rejection, deny-list hooks) | ✅ live |
| `os_detect`, `magic_check` (cross-OS routing) | ✅ live (15 tests) |
| Windows tools: `win_registry_get`, `win_prefetch_parse`, `win_evtx_query`, `win_lnk_parse` | ✅ live (16 tests) |
| 11 Claude Code skills (full FOR500 / APFS / Linux content) | ✅ live |
| 5 specialist subagents | ✅ live |
| 5 hooks (guard / audit / finalize / etc.) | ✅ live |
| Pre-commit gate (ruff + pytest + license check) | ✅ live |
| `mh` CLI + `mh-mcp-server` portable launcher | ✅ live |
| `mac_*` macOS tools | 🛠️ W3 (May 10–16) |
| `linux_*` Linux tools | 🛠️ W4 (May 17–23) |
| `memory_volatility` wrapper | 🛠️ W2-W4 |

48 unit tests passing. CI green on every commit.

## Required Hackathon Deliverables (8 of 8)

| # | Deliverable | Where |
|---|---|---|
| 1 | Public GitHub repo (Apache-2.0) | this repo, [`LICENSE`](LICENSE) at root |
| 2 | Demo video < 5 min | *W6 — May 31 – Jun 6* |
| 3 | Architecture diagram | [`docs/architecture.md`](docs/architecture.md) |
| 4 | Project description | this README + [`docs/usage.md`](docs/usage.md) |
| 5 | Evidence dataset documentation | [`docs/dataset-documentation.md`](docs/dataset-documentation.md) |
| 6 | Accuracy report | [`docs/accuracy-report-template.md`](docs/) — populated per run |
| 7 | Deployment / setup instructions | this Quickstart + [`bin/mh`](bin/mh) installer |
| 8 | Agent execution logs (timestamps + tokens) | `cases/<id>/output/audit.jsonl` |

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — full system design
- [`docs/usage.md`](docs/usage.md) — detailed usage walkthrough
- [`docs/development.md`](docs/development.md) — pre-commit + CI workflow
- [`docs/dataset-documentation.md`](docs/dataset-documentation.md) — evidence corpus + ground truth
- [`docs/superpowers/plans/2026-05-07-find-evil-master.md`](docs/superpowers/plans/2026-05-07-find-evil-master.md) — current master spec (supersedes earlier plan)

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

## Acknowledgments

- **SANS Institute** — SIFT Workstation, FOR500 / FOR518 / FOR577 curricula, FIND EVIL! hackathon
- **The DFIR community** — 19 years of open tooling
- **Volatility Foundation** — Volatility 3
- **Anthropic** — Claude Code, MCP
- **Daniel Miessler** — [PAI](https://github.com/danielmiessler/PAI) pattern for AI-as-domain-specialist
