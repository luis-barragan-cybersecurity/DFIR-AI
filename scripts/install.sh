#!/usr/bin/env bash
# MemoryHound install script — sets up dev environment on a SIFT Workstation.
set -euo pipefail

echo ">> MemoryHound install"

if ! command -v python3.11 >/dev/null 2>&1; then
    echo "Python 3.11 required. Install with:"
    echo "  apt-get update && apt-get install -y python3.11 python3.11-venv"
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    echo ">> Installing uv"
    python3.11 -m pip install --user uv
fi

echo ">> Installing protocol-sift-mcp (core + dev + forensics)"
cd "$(dirname "$0")/../mcp-server"
uv pip install --system -e ".[dev,forensics]"

echo ">> Done. Next:"
echo "  export ANTHROPIC_API_KEY=..."
echo "  export CASE_ID=demo-001"
echo "  export EVIDENCE_PATH=/path/to/case/data"
echo "  claude code --skills .claude/skills/triage-orchestrator"
