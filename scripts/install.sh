#!/usr/bin/env bash
# MemoryHound one-line installer.
#
# Installs EVERYTHING MemoryHound needs to run real DFIR cases out of the box:
#   - System packages: python 3.11+, git, curl, jq, libmagic, yara, sleuthkit,
#     tshark, zeek, binwalk (best-effort), node, claude CLI
#   - Python deps: protocol_sift_mcp + orchestrator (editable) + forensics
#     extras (volatility3, python-evtx, python-registry, pefile, yara-python,
#     windowsprefetch, pylnk3, python-magic)
#   - Vendored ISF symbols for Volatility 3 (Linux/macOS memory dumps)
#
# Usage:
#   bash scripts/install.sh                # interactive — prompts before sudo/brew
#   MH_INSTALL_YES=1 bash scripts/install.sh  # non-interactive (CI / unattended)
#
# OS support:
#   - macOS (Homebrew required — installer prints URL if missing)
#   - Ubuntu / Debian / SIFT (apt; needs sudo)
#   - Fedora / RHEL / Rocky / CentOS (dnf; needs sudo, best-effort)
#
# Time estimate: 3–15 minutes depending on what's already installed.
#
# This is the friendly entry point. The heavy lifting lives in
# `scripts/install-sift.sh` (--install --with-forensics --with-symbols) — this
# script wraps it with an upfront banner, time/sudo expectations, and an
# optional confirmation prompt.

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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ─── Banner: what this installer does ───────────────────────────────────────
OS_KIND="unknown"
case "$(uname -s)" in
    Darwin) OS_KIND="macos" ;;
    Linux)  OS_KIND="linux" ;;
esac

echo ""
echo -e "${BOLD}MemoryHound installer — full out-of-the-box install${NC}"
echo ""
echo "  Repo:    $REPO_ROOT"
echo "  OS:      $OS_KIND ($(uname -s) $(uname -r 2>/dev/null || echo '?'))"
echo ""
echo "  What this will install (3–15 minutes total):"
echo "    • Python 3.11+, git, curl, jq, libmagic (base utilities)"
echo "    • node + Claude Code CLI"
echo "    • Forensics system packages — yara, sleuthkit, tshark, zeek, binwalk"
echo "    • Python deps — protocol_sift_mcp, orchestrator, volatility3,"
echo "                    python-evtx, python-registry, pefile, yara-python,"
echo "                    windowsprefetch, pylnk3, python-magic"
echo "    • Vendored ISF symbols for Volatility 3"
echo ""

case "$OS_KIND" in
    macos)
        echo -e "  ${YELLOW}macOS:${NC} requires ${BOLD}Homebrew${NC}. Installer will print install URL if missing."
        ;;
    linux)
        echo -e "  ${YELLOW}Linux:${NC} requires ${BOLD}sudo${NC} for apt/dnf package install."
        ;;
    *)
        warn "OS '$OS_KIND' not auto-supported. Installer will degrade to Python-only."
        ;;
esac

echo ""

# ─── Confirmation gate (skippable for CI) ────────────────────────────────────
if [[ "${MH_INSTALL_YES:-0}" != "1" ]]; then
    read -r -p "  Continue? [Y/n] " response || true
    case "$response" in
        ""|[yY]|[yY][eE][sS]) ;;
        *) info "Aborted by user."; exit 0 ;;
    esac
    echo ""
fi

# ─── Delegate to install-sift.sh with full flags ─────────────────────────────
info "Delegating to scripts/install-sift.sh --install --with-forensics --with-symbols"
echo ""

if [[ ! -x "$REPO_ROOT/scripts/install-sift.sh" ]]; then
    chmod +x "$REPO_ROOT/scripts/install-sift.sh" 2>/dev/null || true
fi

if ! bash "$REPO_ROOT/scripts/install-sift.sh" --install --with-forensics --with-symbols; then
    echo ""
    fail "install-sift.sh failed — see output above"
    echo ""
    info "  Common fixes:"
    info "    macOS: ensure Homebrew is installed → https://brew.sh"
    info "    Linux: re-run with sudo, or set MH_INSTALL_NO_SUDO=1 to skip system packages"
    info "    All:   see scripts/install-sift.sh --help"
    exit 1
fi

# ─── Next-step guidance ──────────────────────────────────────────────────────
echo ""
ok "MemoryHound installed (full forensics toolchain)."
echo ""
echo "  Next:"
echo -e "    1. ${BOLD}claude /login${NC}                                    # Pro/Max subscription (recommended)"
echo "       OR"
echo -e "       ${BOLD}export ANTHROPIC_API_KEY=sk-ant-…${NC}               # API key"
echo ""
echo -e "    2. ${BOLD}./bin/mh quickstart${NC}                              # auth check + stub demo (no tokens)"
echo ""
echo "    3. Real triage:"
echo -e "       ${BOLD}mkdir -p cases/case-001/input${NC}"
echo -e "       ${BOLD}cp /path/to/evidence/* cases/case-001/input/${NC}"
echo -e "       ${BOLD}./bin/mh run case-001${NC}                            # interactive (free-form)"
echo -e "       ${BOLD}./bin/mh orchestrate case-001${NC}                    # deterministic (LangGraph)"
echo ""
echo "  Add bin/ to PATH so 'mh' works from anywhere:"
echo -e "    ${BOLD}export PATH=\"$REPO_ROOT/bin:\$PATH\"${NC}"
echo ""
