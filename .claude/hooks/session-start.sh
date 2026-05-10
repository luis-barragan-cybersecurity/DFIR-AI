#!/usr/bin/env bash
# SessionStart hook — initialize the audit log and hash all input evidence.
# No chain hash, no signing — plain append-only JSONL.
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
OUTPUT_DIR="${OUTPUT_PATH:-${PROJECT_DIR}/output}"
INPUT_DIR="${EVIDENCE_PATH:-${PROJECT_DIR}/input}"
CASE_ID="${CASE_ID:-default-$(date -u +%Y%m%d%H%M%S)}"

mkdir -p "$OUTPUT_DIR"
AUDIT_LOG="$OUTPUT_DIR/audit.jsonl"

# Session-init entry.
python3 -c "
from pathlib import Path
from protocol_sift_mcp.tools import audit
audit.audit_append(
    Path('$AUDIT_LOG'),
    event='session_init',
    data={
        'case_id': '$CASE_ID',
        'evidence_path': '$INPUT_DIR',
        'agent_version': 'memoryhound@0.1.0',
        'model': '${MODEL_NAME:-claude-opus-4-7}',
    },
)
"

# Hash + record every input artifact.
if [[ -d "$INPUT_DIR" ]]; then
    while IFS= read -r -d '' artifact; do
        python3 -m protocol_sift_mcp.tools.evidence ingest \
            --audit "$AUDIT_LOG" \
            --artifact "$artifact"
    done < <(find "$INPUT_DIR" -type f -print0)
fi

echo "{\"hookSpecificOutput\": {\"hookEventName\": \"SessionStart\", \"additionalContext\": \"audit log initialized at $AUDIT_LOG, case=$CASE_ID\"}}"
