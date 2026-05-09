#!/usr/bin/env bash
# fetch-isf-symbols.sh -- refresh vendored Volatility 3 ISF symbol tables.
#
# Default behaviour: verify vendored files match SHA256SUMS. Exits 0 when all
# vendored ISFs are present and match the recorded hash; exits 1 if any are
# missing, corrupt, or out of date.
#
# When MH_REFRESH_SYMBOLS=1: re-download each ISF from its upstream URL,
# validate it is xz-compressed, replace the vendored copy, and rewrite
# SHA256SUMS with the new hash. Useful for dev hosts pulling fresh symbol
# updates and for the Dockerfile build stage (Sub-Plan 05 Task 6).
#
# Usage:
#   bash scripts/fetch-isf-symbols.sh              # verify vendored
#   bash scripts/fetch-isf-symbols.sh --check      # alias for verify (default)
#   MH_REFRESH_SYMBOLS=1 bash scripts/fetch-isf-symbols.sh   # refresh
#
# Exit codes:
#   0   all vendored ISFs verified (or refresh succeeded)
#   1   verification failed, download failed, or sanity check failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SYMBOLS_DIR="${REPO_ROOT}/corpus/dfrws-2008-memory/symbols"
SHA_FILE="${SYMBOLS_DIR}/SHA256SUMS"

# --- Upstream catalogue ---------------------------------------------------
# Each entry maps the vendored relative path (under SYMBOLS_DIR) to the URL
# that produced it. Add new entries here as additional ISFs are vendored.
#
# Format: "<relative-path>|<upstream-url>|<bundle-member-or-empty>"
# If the upstream URL points at a zip bundle, "bundle-member" is the file
# inside the zip to extract.

ISF_CATALOGUE=(
    "linux/2.6.18-8.1.15.el5_64.json.xz|https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip|linux/Centos_2.6.18-8.1.15.el5_2.6.18-8.1.15.el5_x64.json.xz"
)

# --- Output helpers -------------------------------------------------------

info() { printf '» %s\n' "$1"; }
ok()   { printf '✓ %s\n' "$1"; }
warn() { printf '! %s\n' "$1" >&2; }
fail() { printf '✗ %s\n' "$1" >&2; }

# --- Verify mode ----------------------------------------------------------

verify_vendored() {
    if [[ ! -f "$SHA_FILE" ]]; then
        fail "missing $SHA_FILE"
        return 1
    fi
    local sha_log
    sha_log="$(mktemp -t mh-isf-sha.XXXXXX)"
    if ! ( cd "$SYMBOLS_DIR" && shasum -a 256 -c SHA256SUMS ) > "$sha_log" 2>&1; then
        fail "sha256 mismatch -- see $sha_log"
        cat "$sha_log" >&2
        return 1
    fi
    rm -f "$sha_log"
    ok "vendored ISF symbols verified ($(wc -l < "$SHA_FILE" | tr -d ' ') file(s))"
}

# --- Refresh mode ---------------------------------------------------------

download_to_tmp() {
    # Prints path of downloaded file on stdout; non-zero exit on failure.
    local url="$1"
    local tmp
    tmp="$(mktemp -t mh-isf-download.XXXXXX)"
    if ! curl -fsSL --max-time 180 -o "$tmp" "$url"; then
        rm -f "$tmp"
        return 1
    fi
    printf '%s\n' "$tmp"
}

extract_member_to_tmp() {
    # Extract a single member from a zip into a fresh tmp file; print path.
    local zip_path="$1"
    local member="$2"
    local tmp
    tmp="$(mktemp -t mh-isf-extract.XXXXXX.json.xz)"
    if ! unzip -p "$zip_path" "$member" > "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        return 1
    fi
    printf '%s\n' "$tmp"
}

assert_xz() {
    local path="$1"
    if ! file "$path" | grep -q 'XZ compressed'; then
        fail "$path is not xz-compressed"
        return 1
    fi
}

refresh_all() {
    mkdir -p "$SYMBOLS_DIR"
    : > "${SHA_FILE}.tmp"

    local entry rel_path url member src_xz dl_path got_sha target_dir
    for entry in "${ISF_CATALOGUE[@]}"; do
        IFS='|' read -r rel_path url member <<< "$entry"
        info "fetching $rel_path"
        info "  upstream: $url"

        if ! dl_path="$(download_to_tmp "$url")"; then
            fail "download failed for $url"
            rm -f "${SHA_FILE}.tmp"
            return 1
        fi

        if [[ -n "$member" ]]; then
            info "  extracting $member"
            if ! src_xz="$(extract_member_to_tmp "$dl_path" "$member")"; then
                fail "could not extract '$member' from bundle"
                rm -f "$dl_path" "${SHA_FILE}.tmp"
                return 1
            fi
            rm -f "$dl_path"
        else
            src_xz="$dl_path"
        fi

        if ! assert_xz "$src_xz"; then
            rm -f "$src_xz" "${SHA_FILE}.tmp"
            return 1
        fi

        target_dir="${SYMBOLS_DIR}/$(dirname "$rel_path")"
        mkdir -p "$target_dir"
        mv "$src_xz" "${SYMBOLS_DIR}/${rel_path}"

        got_sha="$(shasum -a 256 "${SYMBOLS_DIR}/${rel_path}" | awk '{print $1}')"
        info "  sha256: $got_sha"
        printf '%s  %s\n' "$got_sha" "$rel_path" >> "${SHA_FILE}.tmp"
    done

    mv "${SHA_FILE}.tmp" "$SHA_FILE"
    ok "refreshed $(wc -l < "$SHA_FILE" | tr -d ' ') ISF file(s); SHA256SUMS rewritten"
}

# --- Argument parsing -----------------------------------------------------

mode="check"
case "${1:-}" in
    ""|--check|check)
        mode="check"
        ;;
    -h|--help|help)
        sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        warn "unknown argument: $1 (use --check or --help)"
        exit 2
        ;;
esac

if [[ "${MH_REFRESH_SYMBOLS:-0}" == "1" ]]; then
    refresh_all
else
    verify_vendored
fi
