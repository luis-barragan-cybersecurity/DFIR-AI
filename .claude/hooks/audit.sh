#!/usr/bin/env bash
# PostToolUse hook — append every tool call to the plain audit log.
set -euo pipefail

INPUT_JSON=$(cat)
OUTPUT_DIR="${OUTPUT_PATH:-${CLAUDE_PROJECT_DIR}/output}"
AUDIT_LOG="$OUTPUT_DIR/audit.jsonl"

python3 -c "
import json, sys
from pathlib import Path
from protocol_sift_mcp.tools import audit
data = json.loads('''$INPUT_JSON''') if '''$INPUT_JSON'''.strip() else {}
audit.audit_append(Path('$AUDIT_LOG'), event='tool_call', data=data)
" 2>/dev/null || {
    echo "{\"hookSpecificOutput\": {\"hookEventName\": \"PostToolUse\", \"additionalContext\": \"audit append failed (non-fatal)\"}}"
    exit 0
}

echo '{"hookSpecificOutput": {"hookEventName": "PostToolUse"}}'
