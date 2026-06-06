#!/usr/bin/env bash
# scripts/check-claude-auth.sh — pre-flight Claude auth validation.
#
# Tier A (--quick): format checks only — instant, no network.
#                   * ANTHROPIC_API_KEY prefix + length sanity
#                   * ~/.claude credentials file exists + non-empty
# Tier C (--full):  Tier A + live probe (1 tiny request, no cache).
#                   * API key mode: POST https://api.anthropic.com/v1/messages
#                     with claude-haiku-4-5, max_tokens=1, content="." —
#                     costs ≈ $0.0000004 per call.
#                   * Subscription mode: invoke `claude -p` with a 1-token
#                     prompt (≤15s timeout). Catches expired / revoked
#                     subscription credentials before the orchestrator
#                     launches.
#
# Exit codes:
#   0  every check passed
#   1  at least one ✗ row (or live probe failed in a way that should abort)
#   2  bad CLI argument
#   3  auth OK but headless mode (claude -p / API) is gated by billing —
#      caller should fall back to --interactive mode (which uses the
#      subscription TUI path, no separate API credits required).
#
# Callers:
#   - bin/mh:cmd_run     calls --full as part of preflight; checks exit 3
#                        for the headless-gated → interactive fallback
#   - bin/mh:cmd_doctor  calls --full
#   - standalone         ./scripts/check-claude-auth.sh [--quick|--full]
#
# Important: do NOT echo the API key, the credentials file contents, or
# the HTTP response body anywhere this script writes to stdout/stderr /
# audit log / temp file outside /tmp. The key is the highest-value secret
# the user holds; treat it like the password it is.

set -euo pipefail

MODE="${1:---quick}"

# ─── colors (TTY-aware, respects NO_COLOR) ────────────────────────────────
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    GREEN=$'\e[0;32m'
    RED=$'\e[0;31m'
    YELLOW=$'\e[0;33m'
    BOLD=$'\e[1m'
    NC=$'\e[0m'
else
    GREEN=""
    RED=""
    YELLOW=""
    BOLD=""
    NC=""
fi

ok()   { echo "${GREEN}✓${NC} $*"; }
fail() { echo "${RED}✗${NC} $*"; }
warn() { echo "${YELLOW}!${NC} $*"; }
info() { echo "${BOLD}»${NC} $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [--quick | --full | --help]

  --quick   Format check only (default). Instant, no network calls.
  --full    Format + live probe. One tiny API call per invocation
            (≈ \$0.0000004 in API-key mode). No cache — every call
            actually contacts Anthropic so revoked keys / outages
            surface immediately.
  --help    This message.

Exit 0 on success, 1 on any check failure, 2 on bad CLI usage.
EOF
}

case "$MODE" in
    --help|-h) usage; exit 0 ;;
    --quick|--full) ;;
    *) fail "unknown mode: $MODE"; usage >&2; exit 2 ;;
esac

info "Claude auth check ($MODE)"

errors=0
headless_gated=0  # set to 1 when a billing/credit error blocks claude -p

# Markers that indicate "headless is gated by API credits, not your subscription".
# Liberal heuristic — Anthropic's exact wording may vary; we look for the most
# common substrings. If --interactive would work but --p won't, return exit 3
# so bin/mh:cmd_run can auto-switch modes.
_billing_markers='credit balance|out of credits|api credits|insufficient credits|payment required|402|requires.*credits|requires.*api.*key|headless.*not.*available|need.*top.*up|billing.*required'

_looks_like_billing() {
    # $1 = haystack
    echo "$1" | grep -qiE "$_billing_markers"
}

# ─── Detect auth mode ─────────────────────────────────────────────────────
auth_mode=""
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    auth_mode="api_key"
elif [[ -d "$HOME/.claude" ]]; then
    auth_mode="subscription"
else
    fail "no Claude auth configured"
    info "  fix (subscription): claude /login"
    info "  fix (api key):      export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi
ok "auth mode:    $auth_mode"

# ─── Tier A: format checks ────────────────────────────────────────────────
if [[ "$auth_mode" == "api_key" ]]; then
    key="$ANTHROPIC_API_KEY"
    key_len=${#key}
    # Real keys: prefix sk-ant-, ~108 chars total (varies; >=80 is a safe floor).
    if [[ "$key" == sk-ant-* ]]; then
        ok "key prefix:   sk-ant-... (recognized)"
    else
        fail "key prefix:   does not start with 'sk-ant-' (key looks malformed)"
        info "  fix: copy a real key from https://console.anthropic.com/settings/keys"
        info "  ENV: ANTHROPIC_API_KEY first 8 chars = '${key:0:8}...' (rest hidden)"
        errors=$((errors + 1))
    fi
    if (( key_len >= 80 )); then
        ok "key length:   $key_len chars (>=80 floor)"
    elif (( key_len > 0 )); then
        fail "key length:   $key_len chars — real keys are ~108; this looks truncated"
        errors=$((errors + 1))
    fi
else
    # subscription mode — sanity-check the credentials store. Different
    # claude-code versions store creds in different places; we accept any
    # non-empty file under ~/.claude that looks like a credentials artifact.
    cred_candidates=(
        "$HOME/.claude/.credentials.json"
        "$HOME/.claude/credentials.json"
        "$HOME/.claude/auth.json"
    )
    cred_found=""
    for c in "${cred_candidates[@]}"; do
        if [[ -f "$c" ]] && [[ -s "$c" ]]; then
            cred_found="$c"
            break
        fi
    done
    if [[ -n "$cred_found" ]]; then
        ok "credentials:  $cred_found ($(wc -c < "$cred_found" | tr -d ' ') bytes)"
    else
        warn "credentials:  no recognizable credentials file under ~/.claude"
        info "  (claude-code may store auth elsewhere — live probe will tell)"
    fi
    if ! command -v claude >/dev/null 2>&1; then
        fail "claude CLI:   not in PATH"
        info "  install: https://docs.claude.com/en/docs/claude-code/quickstart"
        errors=$((errors + 1))
    else
        ok "claude CLI:   $(command -v claude)"
    fi
fi

# ─── Tier C: live probe ───────────────────────────────────────────────────
if [[ "$MODE" == "--full" ]]; then
    if [[ "${CLAUDECODE:-0}" == "1" ]]; then
        warn "live probe:   skipped (CLAUDECODE=1 in env — nested claude calls blocked)"
        info "  to enable: run from a plain terminal, or env -u CLAUDECODE ..."
    elif [[ "$auth_mode" == "api_key" ]]; then
        if ! command -v curl >/dev/null 2>&1; then
            fail "live probe:   curl not installed (need it for the API ping)"
            errors=$((errors + 1))
        else
            info "live probe:   POST api.anthropic.com (claude-haiku-4-5, max_tokens=1)"
            # Use a temp file for the body so the API key never appears in
            # process listings or shell history.
            body_file="$(mktemp -t mh-auth-body-XXXXXX.json)"
            resp_file="$(mktemp -t mh-auth-resp-XXXXXX.json)"
            trap 'rm -f "$body_file" "$resp_file"' EXIT
            cat > "$body_file" <<'JSON'
{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"."}]}
JSON
            # --max-time 10: hard 10-second budget. http_code=000 means timeout.
            metrics=$(curl --max-time 10 -s \
                -o "$resp_file" \
                -w '%{http_code}|%{time_total}' \
                https://api.anthropic.com/v1/messages \
                -H "Content-Type: application/json" \
                -H "x-api-key: $ANTHROPIC_API_KEY" \
                -H "anthropic-version: 2023-06-01" \
                --data-binary "@$body_file" 2>/dev/null || echo "000|0")

            http_code="${metrics%%|*}"
            elapsed="${metrics##*|}"

            case "$http_code" in
                200)
                    ok "live probe:   200 OK (${elapsed}s) — key is valid"
                    ;;
                401)
                    fail "live probe:   401 Unauthorized — key is invalid or revoked"
                    info "  fix: generate a fresh key at https://console.anthropic.com/settings/keys"
                    errors=$((errors + 1))
                    ;;
                402)
                    fail "live probe:   402 Payment Required — out of API credits"
                    info "  the API call needs credits; your subscription doesn't cover -p / SDK calls"
                    info "  option A: top up at https://console.anthropic.com/billing"
                    info "  option B: re-run with --interactive (uses subscription, no credits)"
                    headless_gated=1
                    ;;
                403)
                    # 403 sometimes hides a billing/credit issue in the body
                    if [[ -s "$resp_file" ]] && _looks_like_billing "$(cat "$resp_file")"; then
                        fail "live probe:   403 Forbidden — looks like a billing/credit issue"
                        info "  body excerpt: $(head -c 200 "$resp_file" | tr '\n' ' ')"
                        info "  fix: top up at https://console.anthropic.com/billing"
                        info "       OR re-run with --interactive (subscription path)"
                        headless_gated=1
                    else
                        fail "live probe:   403 Forbidden — key lacks required permissions"
                        info "  check the key's scopes in https://console.anthropic.com/settings/keys"
                        errors=$((errors + 1))
                    fi
                    ;;
                429)
                    # Rate-limited is a soft warning: key is valid, you're just throttled.
                    # Whether to abort the run is a judgment call; we lean "warn, don't block"
                    # since the actual orchestrator run may queue and recover.
                    warn "live probe:   429 Rate Limited — key valid, but throttled right now"
                    info "  (the orchestrator run may queue and recover; not aborting)"
                    ;;
                5*)
                    warn "live probe:   $http_code — likely Anthropic transient issue"
                    info "  https://status.anthropic.com"
                    ;;
                000)
                    fail "live probe:   no response (network timeout >10s or DNS issue)"
                    info "  check connectivity: curl --max-time 5 https://api.anthropic.com/"
                    errors=$((errors + 1))
                    ;;
                *)
                    # Unknown code — peek at the body for billing-style markers
                    if [[ -s "$resp_file" ]] && _looks_like_billing "$(cat "$resp_file")"; then
                        fail "live probe:   $http_code with billing-shaped body"
                        info "  body excerpt: $(head -c 200 "$resp_file" | tr '\n' ' ')"
                        info "  fix: top up at https://console.anthropic.com/billing"
                        info "       OR re-run with --interactive (subscription path)"
                        headless_gated=1
                    else
                        fail "live probe:   unexpected $http_code"
                        if [[ -s "$resp_file" ]]; then
                            info "  body (first 200 chars): $(head -c 200 "$resp_file" | tr '\n' ' ')"
                        fi
                        errors=$((errors + 1))
                    fi
                    ;;
            esac
        fi
    else
        # subscription mode live probe — invoke claude -p with a tiny prompt.
        # We unset CLAUDECODE proactively in case the caller is from a nested
        # context (already checked above for the outer script, but defensive).
        if ! command -v claude >/dev/null 2>&1; then
            fail "live probe:   claude CLI not in PATH (already reported above)"
            errors=$((errors + 1))
        else
            info "live probe:   claude -p (subscription, 1-turn ping, 15s budget)"
            probe_out=$(env -u CLAUDECODE -u CLAUDE_CODE_SSE_PORT -u CLAUDE_CODE_ENTRYPOINT \
                            -u CLAUDE_CODE_EXECPATH -u CLAUDE_CODE_SESSION_ID \
                            bash -c '
                                printf "%s" "ping" | (
                                    if command -v gtimeout >/dev/null 2>&1; then
                                        gtimeout 15 claude -p --output-format text \
                                            --model claude-haiku-4-5 2>&1
                                    elif command -v timeout >/dev/null 2>&1; then
                                        timeout 15 claude -p --output-format text \
                                            --model claude-haiku-4-5 2>&1
                                    else
                                        # macOS lacks coreutils timeout — fall back to perl
                                        perl -e "alarm 15; exec @ARGV" -- \
                                            claude -p --output-format text \
                                            --model claude-haiku-4-5 2>&1
                                    fi
                                )
                            ' 2>&1) && probe_rc=0 || probe_rc=$?
            if (( probe_rc == 0 )) && [[ -n "$probe_out" ]]; then
                # Truncate output to a single line and cap length so we never
                # bleed a model response into the preflight banner.
                first_line=$(printf '%s\n' "$probe_out" | head -1)
                ok "live probe:   subscription works (claude returned: '${first_line:0:60}...')"
            elif (( probe_rc == 124 )); then
                fail "live probe:   timed out after 15s (subscription stuck or network slow)"
                errors=$((errors + 1))
            elif _looks_like_billing "${probe_out:-}"; then
                # Subscription auth exists but claude -p specifically asked for
                # API credits → headless mode is gated. Signal the caller to
                # fall back to --interactive (which uses the TUI, no -p).
                fail "live probe:   claude -p reported a billing/credit error"
                info "  excerpt: $(printf '%s\n' "$probe_out" | head -3 | cut -c1-200)"
                info "  meaning: headless mode (claude -p) needs API credits even"
                info "           when your subscription is active. Interactive mode"
                info "           (the TUI) still works on subscription."
                info "  fix:     re-run with --interactive, OR top up at"
                info "           https://console.anthropic.com/billing"
                headless_gated=1
            else
                fail "live probe:   subscription probe failed (rc=$probe_rc)"
                if [[ -n "${probe_out:-}" ]]; then
                    info "  output (first line): $(printf '%s\n' "$probe_out" | head -1 | cut -c1-200)"
                fi
                info "  fix: claude /login   (re-authenticate)"
                errors=$((errors + 1))
            fi
        fi
    fi
fi

# ─── Result ───────────────────────────────────────────────────────────────
echo ""
if (( errors == 0 )) && (( headless_gated == 0 )); then
    ok "all checks passed"
    exit 0
elif (( errors == 0 )) && (( headless_gated == 1 )); then
    # Auth is fine; --interactive would work. Caller can fall back.
    warn "auth ok, but headless mode (claude -p) is gated by billing"
    info "  bin/mh:cmd_run will auto-fall-back to --interactive when it sees exit 3"
    exit 3
else
    fail "$errors check(s) failed — see ✗ rows above"
    exit 1
fi
