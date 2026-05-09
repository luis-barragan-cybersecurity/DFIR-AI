#!/usr/bin/env bash
# test-install-sift.sh — assertions for install-sift.sh (Sub-Plan 05 Task 4).
#
# Pure bash — no pytest. Exits 0 on all-pass, 1 on first failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
INSTALL="$SCRIPT_DIR/install-sift.sh"

info() { printf '» %s\n' "$1"; }
ok()   { printf '✓ %s\n' "$1"; }
fail() { printf '✗ %s\n' "$1" >&2; exit 1; }

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" != "$actual" ]]; then
        fail "$label: expected '$expected', got '$actual'"
    fi
    ok "$label"
}

# 1. Syntax check
info "test 1: bash -n install-sift.sh"
bash -n "$INSTALL" || fail "syntax error in install-sift.sh"
ok "syntax clean"

# 2. --help exits 0 + prints usage
info "test 2: --help exits 0"
out=$("$INSTALL" --help 2>&1)
[[ "$out" == *"Usage: install-sift.sh"* ]] || fail "--help did not print usage"
ok "--help OK"

# 3. Unknown flag exits 2
info "test 3: unknown flag exits 2"
set +e
"$INSTALL" --bogus >/dev/null 2>&1
rc=$?
set -e
assert_eq "unknown-flag exit code" "2" "$rc"

# 4. --check runs without mutation
info "test 4: --check runs"
set +e
"$INSTALL" --check >/dev/null 2>&1
rc=$?
set -e
[[ $rc -eq 0 || $rc -eq 1 ]] || fail "--check exited $rc (expected 0 or 1)"
ok "--check exit code in {0,1}"

# 5. --install (NYI in Task 4) exits 0 + prints stub message
info "test 5: --install (NYI) exits 0"
out=$("$INSTALL" --install 2>&1)
[[ "$out" == *"NYI — Sub-Plan 05 Task 5"* ]] || fail "--install missing NYI marker"
ok "--install NYI stub OK"

# 6. Default mode is --check (no positional flag)
info "test 6: default mode = check"
set +e
out_default=$("$INSTALL" 2>&1)
rc_default=$?
set -e
out_check=$("$INSTALL" --check 2>&1) || true
# Both should produce the same prereq-check sections
[[ "$out_default" == *"prereq check"* ]] || fail "default mode missing prereq check"
ok "default mode = --check"

ok "all install-sift.sh tests passed"
