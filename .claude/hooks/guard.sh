#!/usr/bin/env bash
# PreToolUse hook — enforce the trust contract before tool execution:
#   - reject Bash, Write to /input, network egress
#   - reject finding_record without pins
#   - log intent to the audit log
set -euo pipefail

INPUT_JSON=$(cat)

TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // ""')
TOOL_INPUT=$(echo "$INPUT_JSON" | jq -c '.tool_input // {}')

DENY_TOOLS=("Bash" "WebFetch" "WebSearch")
for denied in "${DENY_TOOLS[@]}"; do
    if [[ "$TOOL_NAME" == "$denied" ]]; then
        cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Tool '${TOOL_NAME}' is denied by MemoryHound trust contract. Use the protocol_sift MCP server only."
  }
}
EOF
        exit 0
    fi
done

if [[ "$TOOL_NAME" == *"finding_record"* ]]; then
    PINS_LEN=$(echo "$TOOL_INPUT" | jq '.pins | length // 0')
    if [[ "$PINS_LEN" -lt 1 ]]; then
        cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "finding_record requires at least one pin. Use confidence='unknown' with a gap-explaining claim if you cannot pin this claim."
  }
}
EOF
        exit 0
    fi
fi

if [[ "$TOOL_NAME" == "Edit" || "$TOOL_NAME" == "Write" ]]; then
    FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // ""')
    if [[ "$FILE_PATH" == /input* ]]; then
        cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "/input is mounted read-only. Evidence is immutable during the case."
  }
}
EOF
        exit 0
    fi
fi

echo '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}'
