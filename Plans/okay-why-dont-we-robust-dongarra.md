# MemoryHound Multi-Provider LLM Refactor — Plan

**Status:** Approved scope, execution **post-demo (after Jun 6, 2026)**.
**Owner:** TBD.
**Estimated effort:** 13–14 engineering days for full surface; 5 days to first non-Claude provider (OpenAI).

---

## Context

MemoryHound today is **Claude-only**. Every LLM-invoking node in the LangGraph orchestrator (`triage`, `analyze`, `verifier_pass`) shells out to `claude -p` via `orchestrator/src/mh_orchestrator/claude_node.py:invoke_subagent`. The interactive mode (`bin/mh:claude_run`) opens the Claude Code TUI. The 44 forensic tools are exposed via MCP, which is currently a Claude-Code-only protocol layer in this project.

**Why this needs to change:**

1. **Anthropic's recent billing change** routes `claude -p` and the Agent SDK against a separate API credit pool, not the Pro/Max subscription. Subscription-only users can no longer run the LangGraph path end-to-end without buying API credits. The auto-fallback-to-interactive we shipped (`92d6ecd`) handles this for now, but it means subscription users always go through the TUI — which is slower, less deterministic, and ties analysts to a terminal session.
2. **Vendor lock-in.** Judges, contributors, and enterprise users all have different LLM access. Some have OpenAI credits, some have AWS Bedrock, some have Azure or Gemini, some have local Ollama. MemoryHound's value (the trust contract + 44 forensic tools + LangGraph state machine) is provider-agnostic in principle but Claude-coupled in practice.
3. **Open-source adoption story.** Multi-provider support is a strength for the post-demo pitch ("this runs on YOUR stack"), and a credible answer to judges who ask "what if I don't have Claude?".

**Intended outcome:** Every LangGraph node body stays unchanged. A new provider abstraction layer behind `invoke_subagent` lets MemoryHound run identical analysis flows on **OpenAI, AWS Bedrock, Azure OpenAI, Google Gemini, GitHub Models, local (Ollama/LM Studio), and GitHub Copilot Chat**, in addition to the existing Claude path. Every provider can call every forensic tool ("full parity" — confirmed user decision).

**Trust contract is invariant:** schema-validated findings, Verifier dissent loop with the `parse_error → dissent` fallback, chain-of-custody audit log — all preserved across every provider.

---

## Architectural Decision: where Claude coupling actually lives

Verified from Phase 1 Explore reports — **all Claude coupling is at exactly two seams**:

| Seam | File | What it does |
|---|---|---|
| **CLI dispatch** | `bin/mh:claude_run()` (lines 36–80) | Builds runtime MCP config, sets `--allowedTools`, invokes `claude` (interactive TUI or headless `-p`) |
| **Orchestrator subagent invocation** | `orchestrator/src/mh_orchestrator/claude_node.py:invoke_subagent` (lines 81–147) | Spawns `claude -p --output-format stream-json` per LLM-invoking node |

Everything else is already model-agnostic:

- **MCP server** (`mcp-server/src/protocol_sift_mcp/server.py`) — stdio protocol; client-agnostic.
- **LangGraph topology** (`graph.py`, `state.py`, all 20 nodes) — pure Python, no Claude dep.
- **44 MCP tool schemas** — JSON Schema; translate 1:1 to OpenAI / Anthropic / Gemini / Bedrock Converse tool formats.
- **14 skills + 4 agent .md files** — prose with frontmatter; portable as system prompts.

The MCP `inputSchema → provider tool schema` translation is mostly structural rewrapping with one Gemini quirk (strip `additionalProperties:false`, `$schema`, `examples`).

This means the refactor is **single-seam surgery**, not a rewrite. The plan is sized accordingly.

---

## Recommended approach

### Module structure (new package)

Create `orchestrator/src/mh_orchestrator/llm_provider/`:

```
llm_provider/
  __init__.py              public API: get_provider, list_mcp_tools, run_mcp_tool
  base.py                  LLMProvider ABC + ToolCallResult + ProviderConfig
  registry.py              provider name → factory; reads .env
  tool_translation.py      MCP Tool → {OpenAI,Anthropic,Gemini,Bedrock} schemas
  mcp_executor.py          in-process MCP dispatcher (imports server.call_tool)
  audit_emit.py            Python equivalent of .claude/hooks/{audit,guard}.sh
  errors.py                LLMAuthError, LLMRateLimitError, LLMBillingError, ...
  preflight.py             per-provider live-ping (replaces check-claude-auth.sh)
  adapters/
    anthropic_claude_code.py    wraps today's `claude -p` (default, zero risk)
    anthropic_sdk.py            direct anthropic SDK
    openai.py                   OpenAI SDK (GPT-5 / GPT-4o)
    azure_openai.py             Azure OpenAI deployment
    bedrock.py                  AWS Bedrock Converse API (Claude + Llama + Titan)
    gemini.py                   google-genai (direct + Vertex)
    github_models.py            OpenAI-compatible at models.inference.ai.azure.com
    ollama.py                   OpenAI-compatible local
    copilot_chat.py             GitHub Copilot Chat (experimental, gated)
  loops/
    openai_style.py          shared loop for OpenAI/Azure/GitHub/Ollama/Copilot
    anthropic_style.py       Anthropic Messages API loop
    gemini_style.py          Gemini functionCall loop
    bedrock_converse_style.py  Bedrock Converse (covers Claude/Llama/Titan)
```

### How `invoke_subagent` becomes provider-agnostic

`claude_node.py:invoke_subagent` keeps its name and signature (callers in `nodes/{triage,analyze,verifier_pass}.py` are **not modified**). New behavior:

1. Resolve provider: `--provider` flag > `MH_LLM_PROVIDER` env > `.env` `MH_LLM_PROVIDER` > default `anthropic_claude_code`.
2. If provider is `anthropic_claude_code` → preserve the existing subprocess code path bit-identical (`_legacy_claude_subprocess`).
3. Otherwise → run an in-process tool-use loop:
   - Load the agent spec (`data/agents/<name>.md` frontmatter + body).
   - Translate the agent's `tools:` list against the live MCP tool inventory.
   - Inject `tool_executor` callback wrapping `mcp_executor.run_mcp_tool` (which calls `protocol_sift_mcp.server.call_tool` in-process — no second stdio round-trip needed).
   - Wrap every tool call with `audit_emit.audit_append` + `_guard_check` (replicates `.claude/hooks/{audit,guard}.sh` effects).
   - Return a `SubagentResult` (existing dataclass — unchanged shape).

Existing `SubagentResult`, `should_stub`, `HeadlessBillingError` all stay; the latter becomes an alias for `errors.LLMBillingError` for back-compat.

### Configuration — `.env` at repo root (per your decision)

Single source of truth: a `.env` file at the project root, auto-loaded via `python-dotenv`. No TOML, no keychain (deferred to later if needed). Example:

```sh
# .env  (chmod 600; .gitignored)

# Which provider to use
MH_LLM_PROVIDER=openai          # anthropic_claude_code|anthropic_sdk|openai|azure_openai|bedrock|gemini|github_models|ollama|copilot_chat
MH_LLM_MODEL=gpt-5              # provider-specific; defaults baked per provider if unset

# Provider keys — only need the ones for providers you use
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://my-resource.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-5-prod
AWS_REGION=us-east-1            # boto3 picks up keys from standard AWS chain
GEMINI_API_KEY=...
GITHUB_TOKEN=ghp_...            # used by github_models AND copilot_chat
OLLAMA_ENDPOINT=http://localhost:11434/v1
OLLAMA_MODEL=llama3.1:70b-instruct

# Tunables
MH_TOOL_LOOP_CAP=16             # iterations per node before stop_reason=tool_loop_cap
MH_SYSTEM_PROMPT_TOKENS_MAX=8192
MH_INTEGRATION_BUDGET_USD=0.05  # cap for nightly contract tests
```

**New CLI subcommands** (single source: `bin/mh` + `orchestrator/.../configure.py`):

- `mh configure` — interactive wizard: walks each provider, asks for key, runs preflight, writes/updates `.env`.
- `mh configure add openai` — non-interactive single-provider add.
- `mh configure list` — table of configured providers + last preflight (keys redacted).
- `mh configure test [provider]` — preflight against one or all.
- `mh run --provider openai <case>` — per-run override.

`.env` is added to `.gitignore` (already standard) and chmod 600 on write.

### Per-provider preflight (replaces check-claude-auth.sh)

`scripts/check-claude-auth.sh` becomes a thin shim that calls `mh-orchestrate preflight anthropic_claude_code`, preserving its existing 0/1/2/3 exit-code contract (so `bin/mh:cmd_run`'s billing-gated fallback to `--interactive` keeps working unchanged).

`mh doctor` calls `preflight` on every configured provider in parallel and prints a table:

```
provider               auth     model              latency   note
─────────────────────────────────────────────────────────────────────────
anthropic_claude_code  ok      claude-opus-4-7    cli       /login active
openai                 ok      gpt-5              412 ms    OPENAI_API_KEY
bedrock                ok      claude-opus-4-7    687 ms    region=us-east-1
gemini                 ok      gemini-2.5-pro     531 ms    GEMINI_API_KEY
ollama                 ok      llama3.1:70b       89 ms     localhost:11434
copilot_chat           SKIP    -                  -         set MH_COPILOT_EXPERIMENTAL=1
```

### Trust contract preservation — invariant across providers

| Mechanism | How it's preserved on non-Claude providers |
|---|---|
| **`finding_record` rejects empty pins** | `audit_emit._guard_check` runs before every tool dispatch; rejects `finding_record(pins=[])` with the same wording as `.claude/hooks/guard.sh:L37`. The MCP server's schema validation is a second backstop. |
| **Verifier verdict enum** | Use constrained decoding where supported (OpenAI `response_format=json_schema`, Anthropic tool-only mode, Gemini `response_schema`); stop-sequence backstop for unconstrained models; unchanged `parse_error → dissent` fallback in `verifier_pass.py:L127`. |
| **Audit chain (SHA256-linked JSONL)** | `audit_emit.audit_append` calls into the same `protocol_sift_mcp.tools.audit.audit_append` the `.sh` hooks use. Identical wire format, identical chaining. |
| **Severity enum** | Strict membership test in `nodes/triage.py:L60` is unchanged. Non-matching reply → `severity="unknown"` (already in place). |
| **OS routing** | The byte-level memory-dump discrimination in `nodes/detect.py` is provider-agnostic. Same routing logic regardless of which LLM runs triage. |

A **per-provider verifier behavioral test** (see Verification section) catches drift: feed the same finding to every provider; assert verdict ∈ `{agree, dissent, revise}` at least 8/10 invocations.

---

## Critical files to modify

### Single dispatch point that changes shape
- `orchestrator/src/mh_orchestrator/claude_node.py` — `invoke_subagent` rewrites as provider-agnostic dispatcher. `SubagentResult`, `should_stub`, `HeadlessBillingError` all preserved.

### CLI seam
- `bin/mh` — `claude_run` becomes `provider_run`. Claude path is the unchanged subprocess code. Non-Claude path delegates to new `orchestrator/.../interactive.py` for the interactive UX. `cmd_doctor` calls the new preflight. `cmd_run` honors `--provider`.
- `orchestrator/src/mh_orchestrator/cli.py` — add `--provider`, new subcommands `preflight`, `configure`, `interactive`.

### Pattern repeated across many files (describe once, list reps)
- `.claude/agents/{verifier,windows-agent,macos-agent,linux-agent}.md` → relocated to `orchestrator/data/agents/<name>.md`; `.claude/agents/<name>.md` becomes a symlink so Claude Code still finds them. Same frontmatter (`name`, `description`, `tools:`), same body.
- `.claude/skills/<14 dirs>/SKILL.md` → same symlink treatment, target `orchestrator/data/skills/<name>/SKILL.md`.

### NOT modified (zero touch)
- **All of `mcp-server/`** — 44 tools, schemas, executors stay exactly where they are.
- **All of `orchestrator/.../nodes/`** — 20 node bodies untouched. They keep importing `invoke_subagent` from `claude_node`; the provider dispatch is invisible to them.
- **`graph.py`, `state.py`** — topology and IncidentState unchanged.
- **`.claude/hooks/*.sh`** — used by Claude path only; equivalent behavior replicated in `audit_emit.py` for non-Claude paths.

### Functions / utilities to reuse (no rewrite)

| Reuse target | Path | Why |
|---|---|---|
| `protocol_sift_mcp.tools.audit.audit_append` | `mcp-server/src/protocol_sift_mcp/tools/audit.py` | Single source of truth for chained JSONL audit; provider adapters call this directly so audit shape is identical across providers. |
| `protocol_sift_mcp.server.call_tool` | `mcp-server/src/protocol_sift_mcp/server.py:L779` | In-process MCP tool dispatcher — non-Claude providers call this directly via `anyio.run`, no second stdio round-trip. |
| `protocol_sift_mcp.server.list_tools` | same | Provides the 44-tool inventory the translation layer maps from. |
| `orchestrator.src.mh_orchestrator.nodes.__init__.record_audit` / `emit_message` | `orchestrator/src/mh_orchestrator/nodes/__init__.py` | Already replicate `session-start.sh` / `finalize.sh` effects from Python. The new `audit_emit.py` complements at the finer-grained PreToolUse / PostToolUse layer. |
| `claude_node.HeadlessBillingError` + regex | `orchestrator/src/mh_orchestrator/claude_node.py:L18-50` | The billing-error detection pattern + typed exception become the model for per-provider billing-error normalization. |
| Existing tier-completeness, ID-stability, anti-criteria patterns | `orchestrator/.../nodes/*.py` | No changes needed; the abstraction is below them. |

---

## Six-phase rollout (post-Jun-6 execution)

| Phase | Scope | Days | Behavior change |
|---|---|---|---|
| **1** | Abstraction skeleton; Claude wrapped as `adapters/anthropic_claude_code.py`; move agents/skills to `data/` with `.claude/*` symlinks; add `mh-orchestrate preflight` | 2 | **None.** All existing tests pass. Default provider still Claude, bit-identical behavior. |
| **2** | OpenAI adapter + `openai_style.py` loop + Python `interactive.py` + first contract test | 3 | Optional `--provider openai` now works. |
| **3** | AWS Bedrock adapter + `bedrock_converse_style.py` (covers Claude / Llama / Titan in one code path) | 2 | `--provider bedrock` works. |
| **4** | Azure OpenAI (lifts `openai_style.py`) + Gemini (`gemini_style.py`) — parallelizable | 2 | `--provider azure_openai`, `--provider gemini` work. |
| **5** | GitHub Models (reuses `openai_style.py`) + Ollama / LM Studio | 1.5 | `--provider github_models`, `--provider ollama` work. |
| **6** | GitHub Copilot Chat (experimental, gated by `MH_COPILOT_EXPERIMENTAL=1`) | 2 | `--provider copilot_chat` available behind opt-in flag. |
| **7** | Docs, README multi-provider section, optional `default_provider = "auto"` flip behind a config flag (existing default stays Claude unless user opts in) | 1 | None visible to existing users. |

**Total: 13.5 engineering days.** Demo-safe checkpoint: end of Phase 1 (2 days, zero behavior change). First non-Claude provider production-ready: end of Phase 2 (5 days).

---

## Risk register (top 6)

| Risk | Mitigation |
|---|---|
| **Verifier verdicts unparseable on smaller models (especially local Ollama)** | Constrained decoding where supported; stop-sequence backstop; the existing `parse_error → dissent` fallback at `verifier_pass.py:L127` is the final safety net. Per-provider verifier behavioral test catches drift. |
| **Tool schema quirks per provider** (Gemini rejects `additionalProperties: false`, Bedrock double-wraps, etc.) | `tool_translation.py` per-provider strip lists; contract test exercises every tool against every provider nightly. |
| **In-process MCP executor crashes the orchestrator** | Every `call_tool` wrapped in try/except → `LLMToolCallError`; `analyze.py` already treats tool failures as gap findings. |
| **Audit shape drift between Claude path (hooks-emitted) and non-Claude path (Python-emitted)** | Single source: `audit_emit.py` calls `protocol_sift_mcp.tools.audit.audit_append` — same function the `.sh` hooks call. Shape-equivalence test diffs sample events. |
| **`.env` key leakage** | chmod 600 on write; `.gitignore` already excludes; preflight warns if mode > 600; document keyring upgrade path for later. |
| **Cost spiral during integration testing** | `MH_INTEGRATION_BUDGET_USD` cap; tests run nightly not per-commit; use each provider's cheapest model in contract tests. |

---

## Verification

End-to-end testing happens at three layers:

### 1. Per-adapter unit tests (mocked SDKs)
Files: `orchestrator/tests/llm_provider/test_<provider>.py` per provider. Mock the SDK client; assert tool schema translation, tool-use loop, iteration cap, error mapping, guard rejection of un-pinned `finding_record`.

```bash
.venv/bin/python -m pytest orchestrator/tests/llm_provider -x -q
```

### 2. Cross-provider contract test (real-money, gated)
File: `orchestrator/tests/test_provider_contract.py`. Parametrized over every provider. Default skipped; runs in CI nightly with `MH_INTEGRATION=1` and `MH_INTEGRATION_BUDGET_USD=0.05`. One prompt: "Hash /tmp/x.txt with the `hash` tool, then call `finding_record` with the result, confidence=confirmed, one pin." Assert: ≥1 `hash` call, exactly one `finding_record` with `len(pins) >= 1`, non-empty `final_text`.

```bash
MH_INTEGRATION=1 MH_INTEGRATION_BUDGET_USD=0.05 \
  .venv/bin/python -m pytest orchestrator/tests/test_provider_contract.py -q
```

### 3. LangGraph end-to-end per provider
Reuses the existing `case-graph-smoke` fixture. For each configured provider, run:

```bash
MH_LLM_PROVIDER=<provider> ./bin/mh run case-graph-smoke
```

Confirm: exit 0, all 12 §11.4 output artifacts present, audit chain verifies (`mh verify case-graph-smoke`), `findings.json` contains the expected stub-mode-or-real findings shape.

### 4. Stub-mode universal coverage
`MH_NO_CLAUDE=1` renamed to `MH_NO_LLM=1` (back-compat alias kept). Every provider's adapter honors it; stub returns deterministic canned responses. Existing 259 orchestrator tests + 217 mcp-server tests remain green at Phase 1 end and at every subsequent phase.

### 5. Verifier behavioral test
File: `orchestrator/tests/test_verifier_cross_provider.py`. For each provider, dispatch 10 staged findings to the verifier and assert ≥8/10 produce a verdict in `{agree, dissent, revise}` without falling to `parse_error → dissent`. Flag any provider exceeding 50% parse-error rate as failing the trust contract.

---

## Out of scope (explicitly deferred)

- **OS keychain integration** — `.env` is the chosen config format. Keychain (`keyring` lib) can be added in a follow-up if multi-user machines demand it.
- **PTY-wrapped TUI under LangGraph** (the original "PTY trick" the user quoted). Different problem; would let LangGraph drive Claude under subscription billing, but the abstraction layer here is the broader solution.
- **MCP-over-HTTP** — current stdio works for both Claude Code and the in-process executor; no need to add an HTTP transport.
- **Streaming UI in the Python interactive mode** — Phase 2 ships line-buffered stdout. Real streaming (token-by-token with cursor management) is post-Phase-7 polish.
- **`.claude/hooks/*.sh` rewrite for the Claude path** — kept as-is; their effects are replicated for non-Claude paths in `audit_emit.py`.
- **README marketing updates** — Phase 7 only, after parity is real.

---

## Open questions to resolve before Phase 2 starts

1. **Model defaults per provider** — what's the recommended default for each? (OpenAI: `gpt-5`? `gpt-4o`? Gemini: `gemini-2.5-pro`? Bedrock: which Claude variant?) Resolve by running preflight latency + cost benchmarks at Phase 2 start.
2. **Should `default_provider = "auto"` ship at Phase 7?** Auto-walks the `auto_detect_order` list, picks the first one that passes preflight. Convenient but surprising. Default stays explicit unless user opts in.
3. **Local-model tool-calling capability matrix** — which Ollama / LM Studio models actually call tools reliably? Phase 5 will need a documented "tested-working" list (current candidates: Llama 3.1 70B+, Qwen 2.5 72B+, Mistral Large).
