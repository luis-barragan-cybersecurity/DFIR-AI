# Deployment

MemoryHound ships three deployment paths for hackathon judges and operators.
Pick the one that matches your environment.

## Path 1 — Pre-built Docker image (recommended for judges)

The MemoryHound CI publishes a pre-built image to GitHub Container Registry on every `sub-plan-*-complete` tag push. No build needed.

```bash
docker pull ghcr.io/saivarun3407/memoryhound:sub-plan-05-complete
docker run --rm \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    -v "$PWD/cases:/work/cases" \
    ghcr.io/saivarun3407/memoryhound:sub-plan-05-complete \
    orchestrate <case-id>
```

Replace `<case-id>` with a directory you've populated under `cases/<case-id>/input/`.

**Auth options**:
- `ANTHROPIC_API_KEY` env var (primary)
- Mount `~/.claude` from host: `-v "$HOME/.claude:/home/hound/.claude:ro"` (alternative — for judges who already ran `claude /login`)

**Stub mode** (no API tokens consumed): add `-e MH_NO_CLAUDE=1`.

## Path 2 — Local Docker build

If you'd rather build the image locally:

```bash
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound
cd memoryhound
docker compose build
docker compose run --rm memoryhound orchestrate <case-id>
```

Or directly:

```bash
docker buildx build --target runtime -t memoryhound:dev .
docker run --rm memoryhound:dev orchestrate <case-id>
```

Build takes ~5 min cold cache, ~30s warm. Image size: ~1.5 GB.

## Path 3 — Host install (SIFT VM or stock Ubuntu 22.04)

Bootstrap a fresh SIFT Workstation VM or stock Ubuntu 22.04 host:

```bash
git clone https://github.com/saivarun3407/DFIR-AI.git memoryhound
cd memoryhound
bash scripts/install-sift.sh --check                      # report prereq status
bash scripts/install-sift.sh --install --with-forensics --with-symbols
./bin/mh doctor                                           # confirm green
./bin/mh demo                                             # showcase run
./bin/mh orchestrate <case-id>                            # real run
```

Detection: SIFT, Ubuntu, Debian, Fedora/RHEL, macOS. macOS warns + skips APT block but lets the venv path proceed for development.

## Auth Setup

For real-Claude orchestration (any of the three paths):

| Method | Where to set | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | Environment variable | Simplest; works in CI |
| `claude /login` | Run on host once | Then mount `~/.claude` into container, OR rely on `MH_HOME/.claude` on host install |

Stub mode (`MH_NO_CLAUDE=1`) needs no auth and consumes zero tokens.

## Verification

After deploying, `mh doctor` should report green (✓) on:
- python3.11+, pip, git, curl, jq, libmagic, node ≥18, claude CLI, MemoryHound venv, mh-mcp-server installed
- ISF symbols vendored (`corpus/dfrws-2008-memory/symbols/linux/2.6.18-8.1.15.el5_64.json.xz`)

ISF symbols missing → warning (Volatility linux.* plugins return empty without it). Run `bash scripts/fetch-isf-symbols.sh` to refresh.

## Architecture

| Layer | Purpose |
|---|---|
| Claude Code CLI | LLM-invoking nodes (`triage`, `analyze`, `verifier_pass`) |
| LangGraph orchestrator | §11.2 14-IR-node state machine (Sub-Plan 03) |
| MCP server | Typed forensic primitives (Windows/Linux/Memory tools) |
| Volatility 3 + ISF | Memory dump parsing |
| `.claude/` skills | Domain knowledge (FOR500/APFS/Linux/D3FEND/IR planners) |

See [`architecture.md`](architecture.md) for the full diagram and the framework-coverage map.

## Multi-Architecture

SP05 ships `linux/amd64` only. Apple Silicon judges run via Rosetta — slower but functional. Multi-arch builds may land in Sub-Plan 06.

## License Compatibility

The runtime image combines Apache-2.0 (MemoryHound), MIT (Volatility Foundation symbol tables), and GPL-2.0-only (kernel-derived ISF data). The OCI label `org.opencontainers.image.licenses` records the SPDX expression `Apache-2.0 AND MIT AND GPL-2.0-only`. See `corpus/dfrws-2008-memory/symbols/LICENSE-symbols.md` for attribution.
