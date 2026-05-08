#!/usr/bin/env bash
# UserPromptSubmit hook — inject case context (case_id, evidence path, OS detection result)
# into every prompt so the agent has stable reference state.
set -euo pipefail

CASE_ID="${CASE_ID:-unknown}"
EVIDENCE_PATH="${EVIDENCE_PATH:-/input}"
OUTPUT_PATH="${OUTPUT_PATH:-/output}"

cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": "Active case: ${CASE_ID}\nEvidence path (read-only): ${EVIDENCE_PATH}\nOutput path (write): ${OUTPUT_PATH}\nTrust contract: every finding requires evidence pin; finding_record rejects un-pinned. Use confidence='unknown' with a gap-explaining claim when uncertain."
  }
}
EOF
