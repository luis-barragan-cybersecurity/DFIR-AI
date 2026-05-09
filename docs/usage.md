# Usage

> For setup, see [`deployment.md`](deployment.md).

## Prereqs

Run on SIFT, stock Ubuntu, or any of the three deployment paths in [`deployment.md`](deployment.md).

- Python 3.11
- Docker + docker compose (Paths 1 & 2 only)
- Anthropic API key, or `claude /login` once on host

## First-Time Setup

Pick a deployment path from [`deployment.md`](deployment.md). For host install:

```bash
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound
cd memoryhound
bash scripts/install-sift.sh --install --with-forensics --with-symbols
./bin/mh doctor
```

For local Docker build:

```bash
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound
cd memoryhound
docker compose build
```

## Running A Case

Host install:

```bash
mkdir -p cases/case-001/input
cp /path/to/evidence/* cases/case-001/input/

export ANTHROPIC_API_KEY="sk-ant-..."
./bin/mh orchestrate case-001
```

Docker:

```bash
mkdir -p cases/case-001/input
cp /path/to/evidence/* cases/case-001/input/

export ANTHROPIC_API_KEY="sk-ant-..."
docker compose run --rm memoryhound orchestrate case-001
```

Watch for output in `cases/case-001/output/`:
- `audit.jsonl` — plain append-only audit log of every step
- `findings.json` — structured findings, every one pinned
- `narrative.md` — investigator-ready prose
- `accuracy-report.md` — honest FP/FN/hallucination tally

## Inspecting An Audit Log

The audit log lives at `cases/<case-id>/output/audit.jsonl`. Inspect with:

```bash
head -5 cases/case-001/output/audit.jsonl | jq .
wc -l cases/case-001/output/audit.jsonl
```

Each line is one event: `session_init`, `evidence_ingest`, `tool_call`, `finding_recorded`, `session_finalize`. Sequence numbers increment monotonically.

## Replay (Reproducibility)

```bash
./scripts/replay.sh dfrws-2008-memory
# Re-runs the exact same case, diffs against ground truth.
```
