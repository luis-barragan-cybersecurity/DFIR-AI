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

## Data Flow Per Case

1. Operator drops evidence into `/input/` (read-only mount)
2. `SessionStart` hook hashes everything, writes a `session_init` event to the audit log
3. `triage-orchestrator` calls `os_detect` per artifact
4. Routes to Windows/Mac/Linux/Memory subagent
5. Subagent calls typed MCP tools, every claim gets a Pin
6. Each `finding_record` triggers `Verifier` subagent re-run
7. Disagreements → revision; agreements → finalize
8. `Stop` hook writes a `session_finalize` event and emits the report bundle
9. Output: `findings.json`, `narrative.md`, `accuracy-report.md`, `audit.jsonl`

## Why This Wins The Rubric

| Judging Criterion | Our Mechanism |
|---|---|
| Autonomous Execution Quality (tiebreaker) | self-correct loop + Verifier dissent flow |
| IR Accuracy | evidence pinning + cross-corroboration + hallucination corpus |
| Breadth & Depth of Analysis | cross-OS coverage + memory + filesystem + logs |
| Constraint Implementation | typed MCP w/ explicit deny list, no-shell, sandbox at FS layer |
| Audit Trail Quality | plain append-only JSONL, replayable |
| Usability & Documentation | replay.sh, install.sh, this doc, dataset-documentation.md |
