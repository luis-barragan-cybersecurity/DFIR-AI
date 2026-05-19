#!/usr/bin/env bash
# MemoryHound one-line installer.
#
# Usage (from a freshly cloned repo):
#   bash scripts/install.sh
#
# Or via curl (after pushing to a fixed URL):
#   curl -fsSL https://raw.githubusercontent.com/saivarun3407/DFIR-AI/main/scripts/install.sh | bash
#
# What this does (in order):
#   1. Detects OS (macOS / Linux) and prints a banner
#   2. Checks for Python 3.11+ — prints brew/apt install hint if missing
#   3. Checks for the `claude` CLI — prints docs URL if missing (warn, not fail)
#   4. Runs `bin/mh init` to create venv + install deps
#   5. Prints the single next-step command: `mh quickstart`
#
# This script does NOT auto-install system packages. It surfaces what's missing
# and tells the user exactly which command to run. Newbie-friendly without
# being silently invasive.
#
# For the heavyweight SIFT/Ubuntu host bootstrap (Volatility, EZ Tools, ISF
# symbols), use `scripts/install-sift.sh` instead.

set -euo pipefail

GREEN=$'\e[0;32m'
RED=$'\e[0;31m'
YELLOW=$'\e[0;33m'
BOLD=$'\e[1m'
NC=$'\e[0m'

ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; }
info() { echo -e "${BOLD}»${NC} $*"; }

# Resolve repo root (script lives in scripts/)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo ""
info "MemoryHound installer"
info "  Repo:    $REPO_ROOT"

# ─── Step 1: OS detection ────────────────────────────────────────────────────
OS_KIND="unknown"
case "$(uname -s)" in
    Darwin) OS_KIND="macos" ;;
    Linux)  OS_KIND="linux" ;;
    *)      OS_KIND="unknown" ;;
esac
info "  OS:      $OS_KIND ($(uname -s) $(uname -r 2>/dev/null || echo '?'))"
echo ""

# ─── Step 2: Python 3.11+ check ──────────────────────────────────────────────
info "Step 1/4: checking Python 3.11+"
PY_BIN=""
for cand in python3.13 python3.12 python3.11; do
    if command -v "$cand" >/dev/null 2>&1; then
        PY_BIN="$(command -v "$cand")"
        break
    fi
done

if [[ -n "$PY_BIN" ]]; then
    ok "Found: $PY_BIN ($("$PY_BIN" --version 2>&1))"
else
    fail "No Python 3.11+ on PATH."
    case "$OS_KIND" in
        macos)
            echo "        Install with Homebrew:"
            echo "          brew install python@3.12"
            echo "        Then re-run this installer."
            ;;
        linux)
            echo "        Install with your package manager, e.g.:"
            echo "          sudo apt-get install -y python3.12 python3.12-venv"
            echo "        Or on RPM-based:"
            echo "          sudo dnf install -y python3.12"
            ;;
        *)
            echo "        Install Python 3.11 or newer from https://www.python.org/downloads/"
            ;;
    esac
    exit 1
fi

# ─── Step 3: claude CLI check (warn-only) ────────────────────────────────────
echo ""
info "Step 2/4: checking Claude Code CLI"
if command -v claude >/dev/null 2>&1; then
    ok "Found: $(command -v claude)"
    if claude --version >/dev/null 2>&1; then
        info "  Version: $(claude --version 2>&1 | head -1)"
    fi
else
    warn "claude CLI not on PATH."
    echo "        MemoryHound can install without it, but you'll need it to run real triage."
    echo "        Install Claude Code: https://docs.claude.com/en/docs/claude-code/quickstart"
    echo "        After install, choose ONE of:"
    echo "          claude /login                     # Pro/Max subscription (recommended)"
    echo "          export ANTHROPIC_API_KEY=sk-ant-…  # API key"
fi

# ─── Step 4: bin/mh init ─────────────────────────────────────────────────────
echo ""
info "Step 3/4: running bin/mh init (creates .venv, installs deps)"
if [[ ! -x "$REPO_ROOT/bin/mh" ]]; then
    chmod +x "$REPO_ROOT/bin/mh" 2>/dev/null || true
fi

if "$REPO_ROOT/bin/mh" init; then
    ok "Init complete"
else
    fail "mh init failed — see output above"
    exit 1
fi

# ─── Step 5: next-step guidance ──────────────────────────────────────────────
echo ""
info "Step 4/4: ready"
echo ""
ok "MemoryHound installed."
echo ""
echo "  Next:  ${BOLD}./bin/mh quickstart${NC}      # auth check + 60-second demo"
echo ""
echo "  Or add bin/ to PATH so 'mh' works from anywhere:"
echo "    export PATH=\"$REPO_ROOT/bin:\$PATH\""
echo ""
