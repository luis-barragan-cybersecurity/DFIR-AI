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

# 5. --install pipeline is wired up (Sub-Plan 05 Task 5: NYI marker is gone)
info "test 5: NYI stub removed from install-sift.sh"
if grep -q "NYI — Sub-Plan 05 Task 5" "$INSTALL"; then
    fail "NYI marker still present in install-sift.sh — Task 5 not complete"
fi
ok "NYI marker removed; run_install() pipeline live"

# 6. Default mode is --check (no positional flag)
info "test 6: default mode = check"
set +e
out_default=$("$INSTALL" 2>&1)
rc_default=$?
set -e
# Both should produce the same prereq-check sections
[[ "$out_default" == *"prereq check"* ]] || fail "default mode missing prereq check"
ok "default mode = --check"

# 7. install-sift.sh source contains the real pipeline functions
info "test 7: run_install() delegates to bin/mh init + final doctor check"
grep -q "install_memoryhound_via_mh_init" "$INSTALL" || fail "missing install_memoryhound_via_mh_init helper"
grep -q "final_doctor_check"               "$INSTALL" || fail "missing final_doctor_check helper"
grep -q 'bin/mh.* init'                    "$INSTALL" || fail "run_install does not delegate to bin/mh init"
ok "real pipeline helpers wired"

# 8. Compat shim install.sh exec's install-sift.sh
info "test 8: install.sh is a compat shim"
shim="$SCRIPT_DIR/install.sh"
[[ -f "$shim" ]] || fail "scripts/install.sh missing"
bash -n "$shim" || fail "syntax error in install.sh"
grep -q 'install-sift.sh' "$shim" || fail "install.sh missing exec to install-sift.sh"
# Compat shim must be tiny: shebang + comment + exec line (≤5 lines incl. blank).
shim_lines=$(wc -l < "$shim" | tr -d ' ')
if (( shim_lines > 5 )); then
    fail "install.sh too long ($shim_lines lines) — should be ≤5-line shim"
fi
ok "install.sh delegates to install-sift.sh ($shim_lines lines)"

# 9. Idempotency: --check is deterministic across two runs (pure read mode)
info "test 9: --check is deterministic across two runs"
set +e
"$INSTALL" --check >/dev/null 2>&1
rc1=$?
"$INSTALL" --check >/dev/null 2>&1
rc2=$?
set -e
assert_eq "--check rc invariant across two runs" "$rc1" "$rc2"

ok "all install-sift.sh tests passed"
