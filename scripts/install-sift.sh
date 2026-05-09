#!/usr/bin/env bash
# install-sift.sh — host bootstrap for MemoryHound (Sub-Plan 05).
#
# Modes:
#   --check (default)   Report prereq status, exit 0 if all OK, else 1. No mutation.
#   --install           Run the bootstrap pipeline (Sub-Plan 05 Task 5).
#
# Flags:
#   --with-forensics    Install Volatility 3 + transitives (heavy; ~250 MB)
#   --with-symbols      Verify/refresh vendored ISF symbol cache
#   --help, -h          Print usage + exit 0
#
# OS support:
#   Ubuntu/Debian/SIFT (full path)
#   Fedora/RHEL/Rocky/CentOS (best-effort APT→DNF translation)
#   macOS (skip APT; warn the user; venv + pip steps still run)
#   Other (warn; manual install required)
#
# Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors — match bin/mh style
if [[ -t 1 ]]; then
    BLUE='\033[34m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
else
    BLUE=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi
info() { printf '%b» %s%b\n' "$BLUE" "$1" "$RESET"; }
ok()   { printf '%b✓ %s%b\n' "$GREEN" "$1" "$RESET"; }
warn() { printf '%b! %s%b\n' "$YELLOW" "$1" "$RESET" >&2; }
fail() { printf '%b✗ %s%b\n' "$RED" "$1" "$RESET" >&2; }

# OS detection
detect_os() {
    if [[ -f /etc/sift-version ]]; then
        echo "sift"
    elif [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        local id
        id=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        case "$id" in
            ubuntu|debian)             echo "$id" ;;
            fedora|rhel|centos|rocky)  echo "$id" ;;
            *)                         echo "linux-other" ;;
        esac
    else
        case "$(uname -s)" in
            Darwin) echo "macos" ;;
            *)      echo "other" ;;
        esac
    fi
}

# Per-prereq probes
check_python() {
    if command -v python3.11 >/dev/null 2>&1; then
        local v
        v=$(python3.11 --version 2>&1)
        ok "python3.11 — $v"
        return 0
    fi
    if command -v python3.12 >/dev/null 2>&1; then
        local v
        v=$(python3.12 --version 2>&1)
        ok "python3.12 — $v (3.11+ acceptable)"
        return 0
    fi
    fail "python3.11+ — not found"
    return 1
}

check_command() {
    local name="$1" hint="${2:-}"
    if command -v "$name" >/dev/null 2>&1; then
        ok "$name — $(command -v "$name")"
        return 0
    fi
    if [[ -n "$hint" ]]; then
        fail "$name — not found ($hint)"
    else
        fail "$name — not found"
    fi
    return 1
}

check_node() {
    if ! command -v node >/dev/null 2>&1; then
        fail "node — not found (need >= 18; install via NodeSource or brew)"
        return 1
    fi
    local raw v_major
    raw=$(node --version 2>&1 | tr -d 'v')
    v_major=${raw%%.*}
    if (( v_major < 18 )); then
        fail "node — $raw (need >= 18)"
        return 1
    fi
    ok "node — v$raw"
    return 0
}

check_libmagic() {
    if command -v file >/dev/null 2>&1; then
        ok "libmagic — file binary present"
        return 0
    fi
    warn "libmagic/file binary not detected"
    return 1
}

check_venv() {
    if [[ -d "$REPO_ROOT/.venv" ]]; then
        ok "MemoryHound venv — $REPO_ROOT/.venv"
        return 0
    fi
    warn ".venv missing — run 'mh init' or 'install-sift.sh --install'"
    return 1
}

check_mcp_server() {
    if [[ -x "$REPO_ROOT/.venv/bin/mh-mcp-server" ]]; then
        ok "mh-mcp-server installed"
        return 0
    fi
    if [[ -d "$REPO_ROOT/.venv" ]]; then
        warn "mh-mcp-server not installed in venv (run 'mh init')"
    else
        warn "venv missing — see above"
    fi
    return 1
}

check_isf_symbols() {
    local isf="$REPO_ROOT/corpus/dfrws-2008-memory/symbols/linux/2.6.18-8.1.15.el5_64.json.xz"
    if [[ -f "$isf" ]]; then
        ok "ISF symbols vendored — $(wc -c <"$isf" | tr -d ' ') bytes"
        return 0
    fi
    warn "ISF symbols missing — run 'install-sift.sh --install --with-symbols'"
    return 1
}

run_check() {
    info "MemoryHound prereq check"
    info "OS: $(detect_os)"
    local fails=0
    check_python                  || ((fails+=1)) || true
    check_command pip             || ((fails+=1)) || true
    check_command git             || ((fails+=1)) || true
    check_command curl            || ((fails+=1)) || true
    check_command jq              || ((fails+=1)) || true
    check_libmagic                || ((fails+=1)) || true
    check_node                    || ((fails+=1)) || true
    check_command claude "npm i -g @anthropic-ai/claude-code" || ((fails+=1)) || true
    check_venv                    || ((fails+=1)) || true
    check_mcp_server              || ((fails+=1)) || true
    check_isf_symbols             || ((fails+=1)) || true

    echo
    if (( fails == 0 )); then
        ok "all prereqs satisfied"
        return 0
    fi
    warn "$fails check(s) failed — run 'install-sift.sh --install' to bootstrap"
    return 1
}

run_install() {
    info "install pipeline (NYI — Sub-Plan 05 Task 5)"
    info "Task 5 implements: APT prereqs, Node 18 + claude CLI, mh init, ISF fetch"
    return 0
}

print_help() {
    cat <<EOF
Usage: install-sift.sh [MODE] [FLAGS]

Modes:
  --check (default)   Report prereq status, exit 0 if all OK, else 1.
  --install           Run the full bootstrap pipeline.

Flags:
  --with-forensics    Install Volatility 3 + transitives (heavy)
  --with-symbols      Refresh vendored ISF symbol cache
  --help, -h          Print this help and exit
EOF
}

# Arg parser
MODE="check"
WITH_FORENSICS=0
WITH_SYMBOLS=0

while (( $# > 0 )); do
    case "$1" in
        --check)            MODE="check"; shift ;;
        --install)          MODE="install"; shift ;;
        --with-forensics)   WITH_FORENSICS=1; shift ;;
        --with-symbols)     WITH_SYMBOLS=1; shift ;;
        -h|--help)          print_help; exit 0 ;;
        *)                  fail "unknown flag: $1"; print_help; exit 2 ;;
    esac
done

case "$MODE" in
    check)   run_check ;;
    install) run_install ;;
esac
