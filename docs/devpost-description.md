# MemoryHound — Devpost Submission Description

> Devpost markdown subset; 4000-char target. Paste verbatim into the
> "Project description" field on the submission form.

---

**MemoryHound** is an autonomous DFIR agent built for the SANS *Find Evil!*
hackathon. It triages memory dumps, disk images, and Windows/macOS/Linux
artifacts the way a senior analyst would — sequencing the SIFT
Workstation toolkit, **self-correcting when its own verifier disagrees**,
pinning every claim with raw forensic evidence, and writing a
court-defensible audit trail.

### What it does

Drop evidence into `cases/<case-id>/input/` and run `./bin/mh orchestrate
<case-id>`. The LangGraph state machine walks 18 IR nodes (manifest →
session_init → detect → triage → scope → declare → analyze → attack_tag
→ kill_chain → d3fend_recommend → contain → human_in_loop → eradicate
→ recover → lessons_learned → remediation → verifier_pass → correlate →
session_finalize), pulling typed MCP tool calls into Volatility 3, Sleuth
Kit, Plaso, EZ Tools, RegRipper, YARA, MemProcFS, tshark, Zeek,
bulk_extractor, and the python-only Windows/macOS/Linux parsers.

Every finding carries:
- A claim
- One or more pins (artifact + tool + locator + raw_excerpt + captured_at)
- An ATT&CK technique mapping
- A `confidence_rationale` ("X because Y") — mandatory; the schema
  rejects findings without it
- An auto-derived `evidence_tier` (`confirmed_by_evidence` ≥ 2 pins,
  `inferred_from_evidence` otherwise)

### Self-correction (the hackathon's load-bearing requirement)

After analyze + remediation, a global verifier pass re-grades every
finding against its pins. If the verifier dissents on any claim, the
graph routes back through analyze **exactly once** — the revision cap is
deterministic, set in `verifier_pass.py`. Dissent reasons land in the
audit log; the demo video shows the live re-route.

A separate **correlator** node runs after verifier-clean: it
cross-references findings for contradictions about shared PIDs/users,
ATT&CK tactic-sequence gaps, and confidence mismatches between linked
findings. Its report feeds the exec report.

### Constraint implementation (architectural, not prompted)

- Evidence paths are sandbox-asserted under `/input` at every MCP tool
  boundary — escape attempts raise `SandboxViolation`.
- Writes are confined to `/output`. No raw shell, no `rm -rf`, no `dd`.
- Volatility plugins are allowlisted (45+ plugins across windows.*,
  linux.*, mac.*); anything outside the set is rejected before disk
  touch.
- `audit.jsonl` is **hash-chained** — every entry's `prev_hash` is the
  sha256 of the predecessor's canonical JSON. Any tamper breaks the
  chain.
- `manifest.json` records sha256 of every input artifact at ingest.
- `./bin/mh verify <case>` re-hashes input vs manifest AND re-verifies
  the audit chain — the spoliation guarantee, exit code 0 if clean.

### Try it

```bash
git clone https://github.com/saivarun3407/DFIR-AI
cd DFIR-AI
./bin/mh init
./bin/mh doctor
./bin/mh orchestrate _demo           # safe self-collect smoke
./bin/mh serve                       # local web viewer
./bin/mh verify _demo                # spoliation re-check
```

### Stack

- **Agents**: LangGraph + Claude Sonnet/Opus 4.x (Claude Code CLI driver)
- **MCP**: FastAPI-style stdio server with 28+ typed tool functions
- **Orchestration**: pure-Python state machine; deterministic conditional
  edges; bounded recursion cap
- **Audit**: append-only JSONL + sha256 hash chain
- **Reporting**: exec-report (Markdown + Mermaid), narrative,
  accuracy-report, compliance map (NIST CSF 2.0, ISO 27035, MITRE
  ATT&CK, D3FEND)
- **License**: Apache-2.0

### What's included (8/8 submission deliverables)

1. ✅ Public Apache-2.0 repo
2. ✅ 5-min demo video (link below) — shows verifier self-correction
3. ✅ Architecture diagram (README + docs/architecture.md)
4. ✅ This description
5. ✅ Dataset docs (docs/dataset-documentation.md)
6. ✅ Accuracy report (cases/rocba-memory/output/accuracy-report.md)
   with spoliation test
7. ✅ Try-it instructions (README setup section)
8. ✅ Structured execution logs (cases/*/output/audit.jsonl with
   prev_hash chain + agent_messages.jsonl)

### Links

- Repo: https://github.com/saivarun3407/DFIR-AI
- Demo video: <add URL after recording in W6>
- Architecture deep-dive: docs/architecture.md
- Spoliation proof: `./bin/mh verify rocba-memory`
