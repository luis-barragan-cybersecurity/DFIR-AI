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

# Returns the best Python 3.11+ apt package name available in the current
# repos (probes python3.13 → 3.12 → 3.11). Echoes the name; empty string if
# none found. Used to pick the right Python version per Ubuntu/Debian release
# without hard-coding (3.12 on Noble, 3.11 on Jammy, deadsnakes on Focal).
_apt_resolve_python_pkg() {
    for cand in python3.13 python3.12 python3.11; do
        if apt-cache show "$cand" 2>/dev/null | grep -q '^Package: '; then
            echo "$cand"
            return 0
        fi
    done
    echo ""
}

install_apt_prereqs() {
    info "APT prereqs (Debian/Ubuntu/SIFT) — probing dependencies first"
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

    # ─── Probe phase: build the list of missing packages first ────────────
    # Issue a single apt-get install for only what's missing. Skip apt-get
    # entirely when everything is already present.
    local missing=()
    local probe_log=""

    # Python 3.11+: prefer an existing binary, else install whatever
    # python3.11+ apt offers. pyproject.toml requires >=3.11, any of 3.11,
    # 3.12, 3.13 satisfies it.
    local have_python="" py_pkg=""
    for cand in python3.13 python3.12 python3.11; do
        if command -v "$cand" >/dev/null 2>&1; then
            have_python="$cand"
            probe_log+="    ✓ $cand already on PATH ($(command -v "$cand"))\n"
            break
        fi
    done

    if [[ -z "$have_python" ]]; then
        py_pkg="$(_apt_resolve_python_pkg)"
        if [[ -z "$py_pkg" ]]; then
            info "no python3.11+ in apt cache — adding deadsnakes PPA"
            run_root apt-get install -y --no-install-recommends \
                software-properties-common ca-certificates || \
                warn "couldn't pre-install software-properties-common"
            if ! run_root add-apt-repository -y ppa:deadsnakes/ppa; then
                fail "add-apt-repository ppa:deadsnakes/ppa failed — install python3.11 manually then re-run"
                exit 1
            fi
            run_root apt-get update -qq || warn "post-PPA apt-get update returned non-zero — continuing"
            py_pkg="$(_apt_resolve_python_pkg)"
            if [[ -z "$py_pkg" ]]; then
                fail "no python3.11+ available even after deadsnakes PPA — manual install required"
                exit 1
            fi
        fi
        probe_log+="    → will install $py_pkg + ${py_pkg}-venv\n"
        missing+=("$py_pkg" "${py_pkg}-venv")
    else
        # Python binary is on PATH, but on Debian/Ubuntu the venv/ensurepip
        # module ships as a SEPARATE apt package (python3.X-venv). Without
        # it, `python3.X -m venv` fails with "ensurepip is not available"
        # downstream in `mh init`. Probe explicitly: a working ensurepip
        # import is the canonical test.
        if ! "$have_python" -c "import ensurepip" >/dev/null 2>&1; then
            missing+=("${have_python}-venv")
            probe_log+="    → will install ${have_python}-venv (ensurepip missing on $have_python)\n"
        else
            probe_log+="    ✓ $have_python venv/ensurepip module available\n"
        fi
    fi

    # pip
    if ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
        missing+=("python3-pip")
        probe_log+="    → will install python3-pip\n"
    else
        probe_log+="    ✓ pip already present\n"
    fi

    # Base utilities
    local util
    for util in git curl jq unzip; do
        if command -v "$util" >/dev/null 2>&1; then
            probe_log+="    ✓ $util already present\n"
        else
            missing+=("$util")
            probe_log+="    → will install $util\n"
        fi
    done

    # libmagic — `file` is the probe. Ubuntu 24.04 ships libmagic1t64 (the
    # 64-bit time_t transition), earlier releases ship libmagic1. We request
    # libmagic1 and let apt resolve the alias.
    if command -v file >/dev/null 2>&1; then
        probe_log+="    ✓ libmagic (file binary) already present\n"
    else
        missing+=("libmagic1")
        probe_log+="    → will install libmagic1 (apt may substitute libmagic1t64 on 24.04)\n"
    fi

    if ! dpkg -s ca-certificates >/dev/null 2>&1; then
        missing+=("ca-certificates")
        probe_log+="    → will install ca-certificates\n"
    fi

    echo -en "$probe_log"

    if (( ${#missing[@]} == 0 )); then
        ok "all base APT prereqs already installed — skipping apt-get install"
    else
        info "installing missing base packages: ${missing[*]}"
        if ! run_root apt-get install -y --no-install-recommends "${missing[@]}"; then
            fail "APT install failed for: ${missing[*]}"
            exit 1
        fi
        ok "APT base prereqs installed"
    fi

    # ─── Forensics phase (probe-first, same pattern) ──────────────────────
    if (( WITH_FORENSICS )); then
        info "APT forensics extras — probing dependencies first"
        local forensics_missing=()
        local forensics_log=""

        if command -v yara >/dev/null 2>&1; then
            forensics_log+="    ✓ yara already present\n"
        else
            forensics_missing+=("yara" "libyara-dev")
            forensics_log+="    → will install yara + libyara-dev\n"
        fi

        # `fls` is the canonical probe for sleuthkit (it's invoked by the
        # tsk_fls MCP tool).
        if command -v fls >/dev/null 2>&1; then
            forensics_log+="    ✓ sleuthkit (fls) already present\n"
        else
            forensics_missing+=("sleuthkit")
            forensics_log+="    → will install sleuthkit\n"
        fi

        if command -v tshark >/dev/null 2>&1; then
            forensics_log+="    ✓ tshark already present\n"
        else
            forensics_missing+=("tshark")
            forensics_log+="    → will install tshark\n"
        fi

        # Phase 3a network forensics — capinfos/editcap/mergecap come from
        # wireshark-common. tshark usually pulls it transitively but request
        # it explicitly so the wrappers (pcap_info, pcap_slice_time, pcap_merge)
        # always have their binaries.
        if command -v capinfos >/dev/null 2>&1 \
            && command -v editcap >/dev/null 2>&1 \
            && command -v mergecap >/dev/null 2>&1; then
            forensics_log+="    ✓ wireshark-common (capinfos/editcap/mergecap) already present\n"
        else
            forensics_missing+=("wireshark-common")
            forensics_log+="    → will install wireshark-common (capinfos/editcap/mergecap)\n"
        fi

        # Phase 3a — tcpdump backs pcap_filter_bpf (BPF-filter pcap-to-pcap).
        if command -v tcpdump >/dev/null 2>&1; then
            forensics_log+="    ✓ tcpdump already present\n"
        else
            forensics_missing+=("tcpdump")
            forensics_log+="    → will install tcpdump (pcap_filter_bpf wrapper)\n"
        fi

        # Phase 3a — tcpflow backs tcp_reassemble (TCP-stream-to-files).
        if command -v tcpflow >/dev/null 2>&1; then
            forensics_log+="    ✓ tcpflow already present\n"
        else
            forensics_missing+=("tcpflow")
            forensics_log+="    → will install tcpflow (tcp_reassemble wrapper)\n"
        fi

        # Phase 3a — nfdump package provides BOTH nfdump (query) and nfpcapd
        # (pcap→NetFlow converter). Backs pcap_to_netflow + nfdump_query.
        if command -v nfdump >/dev/null 2>&1 && command -v nfpcapd >/dev/null 2>&1; then
            forensics_log+="    ✓ nfdump (nfdump + nfpcapd) already present\n"
        else
            forensics_missing+=("nfdump")
            forensics_log+="    → will install nfdump (provides nfdump + nfpcapd for NetFlow)\n"
        fi

        if command -v binwalk >/dev/null 2>&1; then
            forensics_log+="    ✓ binwalk already present\n"
        else
            forensics_missing+=("binwalk")
            forensics_log+="    → will install binwalk\n"
        fi

        echo -en "$forensics_log"

        if (( ${#forensics_missing[@]} == 0 )); then
            ok "all forensics APT prereqs already installed — skipping"
        else
            info "installing missing forensics packages: ${forensics_missing[*]}"
            if ! run_root apt-get install -y --no-install-recommends "${forensics_missing[@]}"; then
                warn "APT forensics partial/failed — some Python forensics deps may fail to build"
            fi
        fi

        # Optional extras — probe first, warn-only on apt failure.
        if ! command -v zeek >/dev/null 2>&1 && ! command -v bro >/dev/null 2>&1; then
            run_root apt-get install -y --no-install-recommends zeek 2>/dev/null \
                || warn "zeek not in default repos — manual: https://docs.zeek.org/en/master/install.html"
        fi
        if ! command -v bulk_extractor >/dev/null 2>&1; then
            run_root apt-get install -y --no-install-recommends bulk-extractor 2>/dev/null \
                || warn "bulk-extractor not in default repos — manual: https://github.com/simsong/bulk_extractor"
        fi
        # Phase 3a — passivedns: not in default apt; build-from-source or
        # use Suricata's dns.log as a substitute. The pcap_to_passivedns
        # wrapper raises a typed error with this exact hint at runtime, so
        # we keep this as a non-fatal note.
        if ! command -v passivedns >/dev/null 2>&1; then
            warn "passivedns not in apt — pcap_to_passivedns wrapper will be unavailable until you:"
            warn "  1. Build from source: github.com/gamelinux/passivedns"
            warn "  2. OR use Suricata's dns.log (apt install suricata) as a workflow substitute"
        fi
    fi
}

install_dnf_prereqs() {
    info "DNF prereqs (Fedora/RHEL family) — probing dependencies first"
    if ! check_sudo_or_root; then
        warn "DNF install needs sudo or root — skipping (pip steps will still try)"
        return 0
    fi

    local missing=()
    local probe_log=""

    # Python: same probe pattern as apt. Fedora ships python3.12/3.13 in
    # current releases; RHEL 9 ships python3.11.
    local have_python="" py_pkg=""
    for cand in python3.13 python3.12 python3.11; do
        if command -v "$cand" >/dev/null 2>&1; then
            have_python="$cand"
            probe_log+="    ✓ $cand already on PATH\n"
            break
        fi
    done
    if [[ -z "$have_python" ]]; then
        for cand in python3.13 python3.12 python3.11; do
            if dnf list --quiet "$cand" >/dev/null 2>&1; then
                py_pkg="$cand"; break
            fi
        done
        if [[ -z "$py_pkg" ]]; then
            warn "no python3.11+ available in dnf repos — manual install required"
        else
            missing+=("$py_pkg")
            probe_log+="    → will install $py_pkg\n"
        fi
    fi

    if ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
        missing+=("python3-pip")
        probe_log+="    → will install python3-pip\n"
    fi
    for util in git curl jq unzip; do
        if ! command -v "$util" >/dev/null 2>&1; then
            missing+=("$util")
            probe_log+="    → will install $util\n"
        else
            probe_log+="    ✓ $util already present\n"
        fi
    done
    if ! command -v file >/dev/null 2>&1; then
        missing+=("file-libs")
        probe_log+="    → will install file-libs\n"
    fi

    echo -en "$probe_log"

    if (( ${#missing[@]} == 0 )); then
        ok "all base DNF prereqs already installed — skipping dnf install"
    else
        info "installing missing base packages: ${missing[*]}"
        run_root dnf install -y "${missing[@]}" || \
            warn "DNF base install partial/failed — continuing"
    fi

    if (( WITH_FORENSICS )); then
        info "DNF forensics extras — probing"
        local forensics_missing=()
        command -v yara >/dev/null 2>&1 || forensics_missing+=("yara" "yara-devel")
        command -v fls >/dev/null 2>&1 || forensics_missing+=("sleuthkit")
        command -v tshark >/dev/null 2>&1 || forensics_missing+=("wireshark-cli")
        command -v binwalk >/dev/null 2>&1 || forensics_missing+=("binwalk")
        # Phase 3a network forensics extras (Fedora/RHEL)
        (command -v capinfos >/dev/null 2>&1 && command -v editcap >/dev/null 2>&1 \
            && command -v mergecap >/dev/null 2>&1) || forensics_missing+=("wireshark-cli")
        command -v tcpdump >/dev/null 2>&1 || forensics_missing+=("tcpdump")
        command -v tcpflow >/dev/null 2>&1 || forensics_missing+=("tcpflow")
        (command -v nfdump >/dev/null 2>&1 && command -v nfpcapd >/dev/null 2>&1) \
            || forensics_missing+=("nfdump")
        if (( ${#forensics_missing[@]} == 0 )); then
            ok "all forensics DNF prereqs already installed"
        else
            info "installing missing forensics packages: ${forensics_missing[*]}"
            run_root dnf install -y "${forensics_missing[@]}" || \
                warn "DNF forensics partial/failed — some Python forensics deps may fail to build"
        fi
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
    info "macOS prereqs via Homebrew — probing dependencies first"

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

    # ─── Probe phase ──────────────────────────────────────────────────────
    local missing=()
    local probe_log=""

    # Python: existing 3.11+ on PATH satisfies. Otherwise install
    # python@3.12 (Homebrew's default formula for current Python).
    if command -v python3.13 >/dev/null 2>&1; then
        probe_log+="    ✓ python3.13 already on PATH\n"
    elif command -v python3.12 >/dev/null 2>&1; then
        probe_log+="    ✓ python3.12 already on PATH\n"
    elif command -v python3.11 >/dev/null 2>&1; then
        probe_log+="    ✓ python3.11 already on PATH\n"
    else
        missing+=("python@3.12")
        probe_log+="    → will brew install python@3.12\n"
    fi

    local util
    for util in git curl jq; do
        if command -v "$util" >/dev/null 2>&1; then
            probe_log+="    ✓ $util already present\n"
        else
            missing+=("$util")
            probe_log+="    → will brew install $util\n"
        fi
    done

    # libmagic — `file` is the system probe. macOS ships `file` by default
    # but Python's python-magic needs the Homebrew libmagic dylib at runtime.
    if brew list libmagic >/dev/null 2>&1; then
        probe_log+="    ✓ libmagic already installed via brew\n"
    else
        missing+=("libmagic")
        probe_log+="    → will brew install libmagic (needed by python-magic)\n"
    fi

    echo -en "$probe_log"

    if (( ${#missing[@]} == 0 )); then
        ok "all base brew prereqs already installed — skipping brew install"
    else
        info "brew install (base): ${missing[*]}"
        brew install "${missing[@]}" 2>&1 | grep -E '^(==>|Error|Warning)' | head -20 || true
        ok "base brew prereqs installed"
    fi

    # ─── Forensics phase (probe-first) ────────────────────────────────────
    if (( WITH_FORENSICS )); then
        info "brew forensics extras — probing"
        local forensics_missing=()
        local forensics_log=""

        if command -v yara >/dev/null 2>&1; then
            forensics_log+="    ✓ yara already present\n"
        else
            forensics_missing+=("yara")
            forensics_log+="    → will brew install yara\n"
        fi

        # `fls` is the canonical sleuthkit probe.
        if command -v fls >/dev/null 2>&1; then
            forensics_log+="    ✓ sleuthkit (fls) already present\n"
        else
            forensics_missing+=("sleuthkit")
            forensics_log+="    → will brew install sleuthkit\n"
        fi

        # `wireshark` formula on macOS ships tshark.
        if command -v tshark >/dev/null 2>&1; then
            forensics_log+="    ✓ tshark already present\n"
        else
            forensics_missing+=("wireshark")
            forensics_log+="    → will brew install wireshark (provides tshark)\n"
        fi

        if command -v zeek >/dev/null 2>&1; then
            forensics_log+="    ✓ zeek already present\n"
        else
            forensics_missing+=("zeek")
            forensics_log+="    → will brew install zeek\n"
        fi

        if command -v binwalk >/dev/null 2>&1; then
            forensics_log+="    ✓ binwalk already present\n"
        else
            forensics_missing+=("binwalk")
            forensics_log+="    → will brew install binwalk\n"
        fi

        # Phase 3a — macOS: brew `wireshark` ships capinfos/editcap/mergecap/tshark
        # together; checking tshark above is enough but probe explicitly for the
        # other binaries in case someone installed a stripped-down formula.
        if command -v capinfos >/dev/null 2>&1 \
            && command -v editcap >/dev/null 2>&1 \
            && command -v mergecap >/dev/null 2>&1; then
            forensics_log+="    ✓ capinfos/editcap/mergecap already present\n"
        elif ! [[ " ${forensics_missing[*]} " == *" wireshark "* ]]; then
            forensics_missing+=("wireshark")
            forensics_log+="    → will brew install wireshark (provides capinfos/editcap/mergecap)\n"
        fi

        if command -v tcpflow >/dev/null 2>&1; then
            forensics_log+="    ✓ tcpflow already present\n"
        else
            forensics_missing+=("tcpflow")
            forensics_log+="    → will brew install tcpflow (tcp_reassemble wrapper)\n"
        fi

        if command -v nfdump >/dev/null 2>&1 && command -v nfpcapd >/dev/null 2>&1; then
            forensics_log+="    ✓ nfdump (nfdump + nfpcapd) already present\n"
        else
            forensics_missing+=("nfdump")
            forensics_log+="    → will brew install nfdump (NetFlow query + pcap→nfcapd)\n"
        fi

        echo -en "$forensics_log"

        if (( ${#forensics_missing[@]} == 0 )); then
            ok "all forensics brew prereqs already installed — skipping"
        else
            info "brew install (forensics): ${forensics_missing[*]}"
            info "  (this can take 5–15 min on first run; brew compiles some deps)"
            brew install "${forensics_missing[@]}" 2>&1 | grep -E '^(==>|Error|Warning)' | head -30 || true
            ok "forensics brew prereqs installed"
        fi

        # bulk_extractor is not in core Homebrew — warn-only.
        if ! command -v bulk_extractor >/dev/null 2>&1; then
            warn "bulk_extractor not in core Homebrew"
            warn "  optional manual install: https://github.com/simsong/bulk_extractor#installing"
        fi

        # Phase 3a — passivedns not in core Homebrew either. pcap_to_passivedns
        # wrapper raises a clear typed error with build instructions at runtime.
        if ! command -v passivedns >/dev/null 2>&1; then
            warn "passivedns not in core Homebrew — pcap_to_passivedns will be unavailable until you:"
            warn "  1. Build from source: github.com/gamelinux/passivedns"
            warn "  2. OR use Suricata's dns.log as a workflow substitute (brew install suricata)"
        fi
    fi

    # node: required by install_node_and_claude_cli to install the claude CLI.
    # Probe first to skip if user already has it (via nvm, asdf, system).
    if command -v node >/dev/null 2>&1; then
        info "node $(node --version 2>&1) already on PATH — skipping brew install node"
    else
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
