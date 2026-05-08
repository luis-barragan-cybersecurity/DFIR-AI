#!/usr/bin/env bash
# Replay a frozen case — reproducibility primitive for judges.
#
# Usage: ./scripts/replay.sh <case_id>
set -euo pipefail

CASE_ID="${1:?usage: replay.sh <case_id>}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS_DIR="$PROJECT_DIR/corpus/$CASE_ID"
OUT_DIR="$PROJECT_DIR/output/replay/$CASE_ID"

if [[ ! -d "$CORPUS_DIR" ]]; then
    echo "No corpus at $CORPUS_DIR" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
export EVIDENCE_PATH="$CORPUS_DIR"
export OUTPUT_PATH="$OUT_DIR"
export CASE_ID

echo ">> Replaying case=$CASE_ID"
echo ">> Evidence: $EVIDENCE_PATH"
echo ">> Output:   $OUTPUT_PATH"

claude code --skills "$PROJECT_DIR/.claude/skills/triage-orchestrator"

echo ""
echo ">> Audit log: $OUT_DIR/audit.jsonl ($(wc -l <"$OUT_DIR/audit.jsonl" 2>/dev/null || echo 0) entries)"

if [[ -f "$CORPUS_DIR/ground-truth.json" ]]; then
    echo ">> Diffing findings vs ground truth..."
    python3.11 "$PROJECT_DIR/scripts/diff_findings.py" \
        --actual "$OUT_DIR/findings.json" \
        --truth "$CORPUS_DIR/ground-truth.json"
fi
