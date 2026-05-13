# MemoryHound — 5-Minute Demo Script

> Hackathon submission requirement #2 — must **show self-correction**.
> Target length: 5:00. Record W6 (May 31 – Jun 6, 2026). Upload to YouTube
> unlisted; link in `README.md` and the Devpost submission page.

## Pre-flight checklist (run before recording)

1. `git switch sp05-deployment && git pull`.
2. `./bin/mh doctor` — every check green.
3. `cases/rocba-memory/output` exists with prior artifacts (we'll wipe and
   re-run live).
4. Window setup: tmux with three panes — left (terminal), right-top
   (live audit.jsonl tail), right-bottom (`mh serve` browser).
5. Mic check + screen capture at 1920×1080.

## Storyboard

### 0:00–0:30  Intro + thesis

> "MemoryHound is an autonomous DFIR agent for the SANS Find Evil!
> hackathon. It triages memory dumps the way a senior analyst would —
> sequencing the SIFT toolkit, pinning every claim, **self-correcting
> when its own verifier disagrees**, and writing a court-defensible
> audit trail. This run takes the official hackathon case — `Rocba-Memory.raw`
> — and produces an executive report in under five minutes."

On-screen: README architecture diagram (full Mermaid). Highlight the 8
SIFT-category MCP servers and the verifier dissent edge.

### 0:30–1:15  Chain-of-custody on the way in

```
$ ./bin/mh orchestrate rocba-memory
```

Show in the right-top pane:

```
{event: "manifest_complete", manifest_sha256: 7a4f…, entry_count: 1,
 input_dir: "cases/rocba-memory/input"}
```

> "Every run starts by hashing the input tree into `manifest.json` and
> recording the sha256 in a hash-chained audit log. After the run we'll
> prove the evidence is byte-identical."

### 1:15–3:00  Triage + analyze + verifier dissent (the load-bearing 90s)

Tail the audit log live. Call out:
- `triage_complete_stub` → `incident_declared`
- `analyze_complete` first pass
- **`verifier_pass_summary` with `dissent` on a low-confidence finding**
- Re-routing to analyze (graph.py `route_after_verifier_pass`)
- Second `analyze_complete` — finding upgraded or dropped
- Show the `_verifier_revision_count: 1` cap in state.json

> "Notice the verifier disagreed with the first analyze pass. The graph
> routes back through analyze exactly once — the revision cap is
> deterministic, set in `verifier_pass.py:171`. This is real
> self-correction, not just chain-of-thought rationalization."

### 3:00–4:00  Correlator + reporter

Show `correlation_complete` event:

```
{event: "correlation_complete", contradictions: 0, tactic_gaps: 2,
 confidence_mismatches: 0}
```

> "The correlator runs after verifier — it cross-references findings for
> contradictions, ATT&CK tactic gaps, and confidence mismatches between
> linked findings. Then session_finalize renders the exec report,
> incident summary, attack timeline, and compliance map."

Switch to the browser pane (`mh serve`). Click the **Exec** tab. Walk
the page:
- Executive Summary (plain English for C-level)
- Attack Timeline (Mermaid kill-chain + Gantt wall-clock)
- Top-3 actions for the next 4 hours
- Risk reduction score

### 4:00–4:45  Spoliation proof

```
$ ./bin/mh verify rocba-memory
✓ manifest matches input/ — 1 files re-hashed
✓ audit chain intact (47 entries)
✓ agent_messages chain intact
✓ Verification PASSED
```

> "The original memory image is byte-identical before and after. The
> audit log is hash-chained — any tampering anywhere in the file breaks
> the chain at that line. This is the spoliation guarantee the accuracy
> report documents."

### 4:45–5:00  Close

> "MemoryHound — autonomous IR with deterministic guardrails. Code is
> Apache-2.0 at github.com/saivarun3407/DFIR-AI. Try-it instructions in
> the README; full architecture under docs/architecture.md."

## Post-record

- Trim to ≤ 5:00.
- Add captions for every command line so audio-off viewers follow.
- Upload unlisted; copy the URL into:
  - `README.md` (link near top)
  - Devpost submission page
  - `docs/devpost-description.md`

## Self-correction note for judges

The verifier dissent → re-analyze loop is the single submission-mandatory
demonstration. If the live run doesn't trigger dissent on its own, fall
back to a pre-prepared `cases/dissent-demo/` case dir where a synthetic
finding with weak pin coverage is staged to guarantee dissent. Switching
case dirs mid-recording is acceptable; faking the output is not.
