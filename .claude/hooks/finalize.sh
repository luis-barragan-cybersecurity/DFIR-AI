#!/usr/bin/env bash
# Stop hook — close out the audit log with a session summary.
# No chain verification, no signing — plain append-only.
set -euo pipefail

OUTPUT_DIR="${OUTPUT_PATH:-${CLAUDE_PROJECT_DIR}/output}"
AUDIT_LOG="$OUTPUT_DIR/audit.jsonl"
CASE_ID="${CASE_ID:-unknown}"

python3 -c "
from pathlib import Path
from protocol_sift_mcp.tools import audit
audit.audit_append(
    Path('$AUDIT_LOG'),
    event='session_finalize',
    data={'case_id': '$CASE_ID'},
)
"

echo "{\"hookSpecificOutput\": {\"hookEventName\": \"Stop\", \"additionalContext\": \"audit log finalized for case $CASE_ID\"}}"
