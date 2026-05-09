# Development Workflow

## First-Time Setup

```bash
git clone https://github.com/saivarun3407/DFIR-AI.git
cd DFIR-AI
./scripts/install.sh         # installs core + dev + forensics extras
pip install pre-commit
pre-commit install           # registers git hook
pre-commit run --all-files   # smoke test all hooks once
```

## Pre-Commit Checks (run on every `git commit`)

| Check | Purpose |
|---|---|
| `ruff` | Lint + auto-fix; blocks commit on remaining issues |
| `ruff-format` | Consistent formatting |
| `check-yaml` / `check-toml` | Syntax-validate config files |
| `check-merge-conflict` | Block commits with unresolved markers |
| `end-of-file-fixer` | Trailing newline normalization |
| `trailing-whitespace` | Strip stray whitespace |
| `check-added-large-files` (>1MB) | Stop accidental binary commits (evidence files belong in /input) |
| `detect-private-key` | Block accidental key commits |
| `license-at-top` | Asserts LICENSE is Apache-2.0 at repo root (hackathon req) |
| `pytest` | Runs full unit test suite if mcp-server/* changed |

## CI Mirrors These

GitHub Actions runs the same ruff + pytest + license check. If pre-commit passes locally, CI passes. The pre-commit hook is the structural fix for the three CI roundtrips that happened during initial scaffolding.

## Skipping (sparingly)

```bash
git commit --no-verify -m "..."  # only if hook is broken or you're amending docs-only
```

Never use `--no-verify` to push code that fails real checks. The hackathon grades on Audit Trail Quality — passing tests and clean lint are part of that.

## Bypass For Auto-Fix Loops

If `ruff --fix` modifies files, the commit aborts so you can re-stage:

```bash
git add -A
git commit -m "..."   # retry — now applies clean
```

## Shellcheck pre-commit

The repo lints all bash scripts (`scripts/*.sh`, `bin/mh`, `bin/mh-mcp-server`) with shellcheck via pre-commit. Install once:

```bash
pre-commit install
```

To run on demand:

```bash
pre-commit run shellcheck --all-files
```

## Install harness

Sub-Plan 05 ships a bash test harness for `install-sift.sh`:

```bash
bash scripts/test-install-sift.sh
```

Asserts syntax, --help, --check, --install (NYI marker absent), unknown-flag handling, and idempotency. Pure bash — no pytest dep. Should pass on any host that can run `bash`.
