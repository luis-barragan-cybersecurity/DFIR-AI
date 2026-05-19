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

# ─── privilege helpers ───────────────────────────────────────────────────────

check_sudo_or_root() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then return 0; fi
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then return 0; fi
    return 1
}

run_root() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ─── install pipeline ────────────────────────────────────────────────────────

run_install() {
    local os
    os=$(detect_os)
    info "MemoryHound install — OS=$os, forensics=$WITH_FORENSICS, symbols=$WITH_SYMBOLS"

    case "$os" in
        sift|ubuntu|debian)
            install_apt_prereqs
            ;;
        fedora|rhel|centos|rocky)
            install_dnf_prereqs
            ;;
        macos)
            install_brew_prereqs
            ;;
        *)
            warn "OS '$os' not auto-supported — manual prereq install required."
            ;;
    esac

    install_node_and_claude_cli "$os"
    install_memoryhound_via_mh_init
    if (( WITH_SYMBOLS )); then
        install_isf_symbols
    fi
    final_doctor_check
}

install_apt_prereqs() {
    info "APT prereqs (Debian/Ubuntu/SIFT)"
    if ! check_sudo_or_root; then
        if [[ "${MH_INSTALL_NO_SUDO:-0}" == "1" ]]; then
            warn "MH_INSTALL_NO_SUDO=1 — skipping APT block"
            return 0
        fi
        fail "APT install needs sudo or root; re-run with sudo or set MH_INSTALL_NO_SUDO=1"
        exit 1
    fi
    # Idempotency: refresh apt cache only if older than 60s
    if [[ -d /var/lib/apt/lists ]]; then
        local age now
        age=$(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
        now=$(date +%s)
        if (( now - age > 60 )); then
            run_root apt-get update -qq || warn "apt-get update returned non-zero — continuing"
        else
            info "apt cache fresh — skipping update"
        fi
    fi

    # Python 3.11+ is hard-required by pyproject.toml. SIFT Workstation
    # (Ubuntu 22.04) ships python3.10 and has no python3.11 in default
    # repos — we have to add the deadsnakes PPA when python3.11 isn't
    # already known to apt. Skip the PPA if any python3.11+ is already
    # installed system-wide.
    if ! command -v python3.11 >/dev/null 2>&1 \
            && ! command -v python3.12 >/dev/null 2>&1 \
            && ! command -v python3.13 >/dev/null 2>&1; then
        if ! apt-cache show python3.11 >/dev/null 2>&1; then
            info "python3.11 not in apt cache — adding deadsnakes PPA"
            run_root apt-get install -y --no-install-recommends \
                software-properties-common ca-certificates || \
                warn "couldn't pre-install software-properties-common"
            if ! run_root add-apt-repository -y ppa:deadsnakes/ppa; then
                fail "add-apt-repository ppa:deadsnakes/ppa failed — install python3.11 manually then re-run"
                exit 1
            fi
            run_root apt-get update -qq || warn "post-PPA apt-get update returned non-zero — continuing"
        fi
    fi

    if ! run_root apt-get install -y --no-install-recommends \
            python3.11 python3.11-venv python3-pip git curl ca-certificates \
            jq unzip libmagic1; then
        fail "APT install failed"
        exit 1
    fi
    ok "APT base prereqs installed"

    # Forensics extras gated on WITH_FORENSICS — keeps CI / minimal installs
    # lightweight. Zeek and bulk-extractor often live outside Ubuntu main:
    # we attempt them with `|| warn` so failure doesn't abort install.
    if (( WITH_FORENSICS )); then
        info "APT forensics extras: yara sleuthkit tshark binwalk"
        if ! run_root apt-get install -y --no-install-recommends \
                yara libyara-dev sleuthkit tshark binwalk; then
            warn "APT forensics partial/failed — some Python forensics deps may fail to build"
        fi
        # Best-effort optional forensics packages. Zeek lives in its own repo
        # on Ubuntu, bulk-extractor is often in universe — warn-only.
        run_root apt-get install -y --no-install-recommends zeek bulk-extractor 2>/dev/null \
            || warn "zeek / bulk-extractor not in default repos — manual install if needed"
        ok "APT forensics prereqs attempted"
    fi
}

install_dnf_prereqs() {
    info "DNF prereqs (Fedora/RHEL family — best-effort)"
    if ! check_sudo_or_root; then
        warn "DNF install needs sudo or root — skipping (pip steps will still try)"
        return 0
    fi
    # Base: python + system utils. Forensics extras (yara, sleuthkit, wireshark,
    # binwalk) gated on WITH_FORENSICS to avoid surprise on users who only
    # want Windows / Linux text-artifact triage.
    run_root dnf install -y python3.11 python3-pip git curl jq unzip file-libs || \
        warn "DNF base install partial/failed — continuing"
    if (( WITH_FORENSICS )); then
        info "DNF forensics extras: yara sleuthkit wireshark-cli binwalk"
        run_root dnf install -y yara yara-devel sleuthkit wireshark-cli binwalk || \
            warn "DNF forensics partial/failed — some Python forensics deps may fail to build"
    fi
    ok "DNF prereqs attempted"
}

# ─── macOS / Homebrew install path ──────────────────────────────────────────
#
# Strategy: Homebrew is the de facto package manager on macOS for forensics
# tooling. We DO NOT auto-install Homebrew itself (that's a `curl | bash`
# pattern from someone else's server and the user should opt in to it
# explicitly). If brew is missing, we print the official install URL and exit.
# Once brew is present, we install everything non-interactively.

install_brew_prereqs() {
    info "macOS prereqs via Homebrew"

    if ! command -v brew >/dev/null 2>&1; then
        fail "Homebrew not found."
        echo
        echo "    Install Homebrew first (one-time, ~5 min):"
        echo "      /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo
        echo "    Then re-run: bash scripts/install.sh"
        exit 1
    fi

    ok "brew — $(command -v brew)"

    # Base set: python + system utils. Always installed on macOS path.
    local base_pkgs=(python@3.12 git curl jq libmagic)
    info "brew install (base): ${base_pkgs[*]}"
    if ! brew install "${base_pkgs[@]}" 2>&1 | grep -E '^(==>|Error)' | head -20; then
        # brew install returns 0 even on "already installed"; suppress noise
        true
    fi
    ok "base brew prereqs installed (or already present)"

    # Forensics set: gated on flag. Wireshark on macOS is a full GUI cask
    # (~250 MB) — we install the lighter `wireshark` formula which provides
    # tshark only. zeek is available as a formula. bulk_extractor is NOT in
    # core Homebrew — warn-only with manual link.
    if (( WITH_FORENSICS )); then
        local forensics_pkgs=(yara sleuthkit wireshark zeek binwalk)
        info "brew install (forensics): ${forensics_pkgs[*]}"
        info "  (this can take 5–15 min on first run; brew compiles some deps)"
        if ! brew install "${forensics_pkgs[@]}" 2>&1 | grep -E '^(==>|Error)' | head -30; then
            true
        fi
        ok "forensics brew prereqs installed (or already present)"

        if ! command -v bulk_extractor >/dev/null 2>&1; then
            warn "bulk_extractor not in core Homebrew."
            warn "  Optional manual install: https://github.com/simsong/bulk_extractor#installing"
        fi
    fi

    # node + claude CLI handled by install_node_and_claude_cli; we install
    # node here via brew so that helper finds it instead of warning "install
    # via brew install node@18 manually".
    if ! command -v node >/dev/null 2>&1; then
        info "brew install node"
        brew install node 2>&1 | grep -E '^(==>|Error)' | head -10 || true
        ok "node installed via brew"
    fi
}

install_node_and_claude_cli() {
    local os="$1"
    if command -v node >/dev/null 2>&1; then
        local raw v_major
        raw=$(node --version 2>&1 | tr -d 'v')
        v_major=${raw%%.*}
        if (( v_major >= 18 )); then
            ok "node v$raw — already satisfied"
        else
            warn "node v$raw < 18; upgrading via NodeSource"
            install_node_via_nodesource "$os"
        fi
    else
        case "$os" in
            sift|ubuntu|debian)
                install_node_via_nodesource "$os"
                ;;
            fedora|rhel|centos|rocky)
                if check_sudo_or_root; then
                    run_root dnf install -y nodejs || warn "DNF nodejs install failed"
                else
                    warn "node missing and no sudo — skipping"
                fi
                ;;
            macos)
                warn "macOS: install node via 'brew install node@18' manually"
                return 0
                ;;
            *)
                warn "node not installed — manual install required"
                return 0
                ;;
        esac
    fi

    if command -v claude >/dev/null 2>&1; then
        ok "claude CLI — $(command -v claude)"
    else
        info "installing @anthropic-ai/claude-code via npm"
        if command -v npm >/dev/null 2>&1; then
            if ! run_root npm install -g @anthropic-ai/claude-code; then
                warn "npm install failed — install claude CLI manually"
            else
                ok "claude CLI installed"
            fi
        else
            warn "npm not on PATH — claude CLI install skipped"
        fi
    fi
}

install_node_via_nodesource() {
    local os="$1"
    if ! check_sudo_or_root; then
        warn "NodeSource needs sudo — node install skipped"
        return 0
    fi
    info "fetching NodeSource setup_18.x"
    if ! run_root bash -c 'curl -fsSL https://deb.nodesource.com/setup_18.x | bash -'; then
        warn "NodeSource fetch failed"
        return 1
    fi
    if ! run_root apt-get install -y nodejs; then
        warn "apt-get install nodejs failed"
        return 1
    fi
    ok "node installed: $(node --version 2>&1)"
}

install_memoryhound_via_mh_init() {
    info "delegating to bin/mh init (venv + pip install)"
    local mh_init_args=()
    if (( WITH_FORENSICS )); then
        mh_init_args+=("--with-forensics")
    fi
    if ! "${REPO_ROOT}/bin/mh" init "${mh_init_args[@]}"; then
        fail "mh init failed"
        exit 1
    fi
    ok "mh init complete"
}

install_isf_symbols() {
    info "verifying / fetching ISF symbols"
    local fetcher="${SCRIPT_DIR}/fetch-isf-symbols.sh"
    if [[ ! -x "$fetcher" ]]; then
        warn "fetch-isf-symbols.sh missing or not executable — skipping"
        return 0
    fi
    if "$fetcher" --check >/dev/null 2>&1; then
        ok "vendored ISF symbols present + sha256-correct"
        return 0
    fi
    info "ISF symbols missing or corrupt — refreshing from upstream"
    if ! MH_REFRESH_SYMBOLS=1 "$fetcher"; then
        warn "ISF refresh failed — continuing without"
        return 0
    fi
    ok "ISF symbols refreshed"
}

final_doctor_check() {
    info "running 'mh doctor' to verify install"
    if "${REPO_ROOT}/bin/mh" doctor; then
        ok "install complete — mh doctor passes"
        info "next step: ./bin/mh demo"
        return 0
    fi
    warn "mh doctor reported issues — review output above"
    return 1
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
