# Usage

## Prereqs

- SANS SIFT Workstation OVA (Ubuntu 22.04-based VM)
- Docker + docker compose
- Python 3.11
- Anthropic API key

## First-Time Setup

```bash
git clone <repo>
cd memory-hound
./scripts/install.sh
docker compose build
```

## Running A Case

```bash
mkdir -p input output
cp /path/to/evidence/* input/

export ANTHROPIC_API_KEY="sk-ant-..."
export CASE_ID=case-001
docker compose up
```

Watch for output in `output/`:
- `audit.jsonl` — plain append-only audit log of every step
- `findings.json` — structured findings, every one pinned
- `narrative.md` — investigator-ready prose
- `accuracy-report.md` — honest FP/FN/hallucination tally

## Inspecting An Audit Log

The audit log lives at `output/audit.jsonl`. Inspect with:

```bash
head -5 output/audit.jsonl | jq .
wc -l output/audit.jsonl
```

Each line is one event: `session_init`, `evidence_ingest`, `tool_call`, `finding_recorded`, `session_finalize`. Sequence numbers increment monotonically.

## Replay (Reproducibility)

```bash
./scripts/replay.sh dfrws-2008-memory
# Re-runs the exact same case, diffs against ground truth.
```
