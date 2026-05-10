# Sub-Plan 01: Chain-of-Custody Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the ed25519/hash-chain trust stack and replace with a plain append-only JSONL audit log + agent-to-agent message log, simplifying the codebase for internal-IR use while preserving the existing forensic tools and sandbox.

**Architecture:** Delete chain-of-custody primitives (`chain_init`, `chain_append`, `chain_verify`, `sign_findings`, `attest`, `generate_keypair`). Introduce `audit.py` module with two append-only JSONL writers: `audit_append` (tool calls) and `agent_message_append` (inter-agent messages). MCP server, hooks, CLI, and tests update to use the new module. Existing `hash_file`, `Finding`, `Pin`, sandbox, and forensic tools stay untouched.

**Tech Stack:** Python 3.11, pytest, Pydantic 2.5+. No new dependencies. `cryptography` package becomes optional (still in deps for now in case a future sub-plan re-enables signing).

**Source-of-truth files (read first):**
- `mcp-server/src/protocol_sift_mcp/tools/evidence.py` — current chain implementation (functions at lines 34, 38, 42, 46, 51, 64, 98, 130, 187, 198, 218, 265, 276)
- `mcp-server/src/protocol_sift_mcp/server.py` — registers chain tools (lines 43-90, 252-285)
- `mcp-server/src/protocol_sift_mcp/schema.py` — `ChainEvent`, `ChainEntry`, `Attestation` (lines 60-95)
- `mcp-server/tests/test_evidence.py` — chain tests to delete
- `.claude/hooks/{session-start,audit,finalize}.sh` — chain users
- `bin/mh` — `cmd_verify`, `cmd_demo`, `cmd_init` reference chain

---

## File Structure

**Create:**
- `mcp-server/src/protocol_sift_mcp/tools/audit.py` — new audit-log module
- `mcp-server/tests/test_audit.py` — tests for new module

**Modify:**
- `mcp-server/src/protocol_sift_mcp/tools/evidence.py` — keep `hash_file` only; delete the rest
- `mcp-server/src/protocol_sift_mcp/server.py` — drop 3 chain tools, add `audit_append` tool
- `mcp-server/src/protocol_sift_mcp/schema.py` — drop chain/attestation models
- `mcp-server/tests/test_evidence.py` — keep `hash_file` tests, drop the rest
- `.claude/hooks/session-start.sh`
- `.claude/hooks/audit.sh`
- `.claude/hooks/finalize.sh`
- `bin/mh` — drop `cmd_verify`, simplify `cmd_demo`, `cmd_init`, `cmd_status`, `cmd_tools`
- `mcp-server/pyproject.toml` — remove `cryptography` from required deps (keep as `[forensics]` extras only — actually drop entirely since no other code uses it)
- `README.md` — drop trust-stack section
- `docs/architecture.md` — drop attestation layer
- `docs/usage.md` — drop verify/tamper section

**Delete:**
- `keys/ed25519.priv`
- `keys/ed25519.pub`
- `keys/` directory itself
- `.claude/skills/chain-of-custody/`

---

## Pre-flight: Baseline

### Task 0: Capture baseline test state

**Files:** none modified

- [ ] **Step 1: Run full test suite, capture green baseline**

```bash
cd /Users/x00x/Desktop/SANS/memory-hound
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests -q --no-cov 2>&1 | tail -10
```

Expected: All 48 tests pass. Record exact pass count for later comparison.

- [ ] **Step 2: Confirm clean git state**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound status
```

Expected: clean tree (or document any uncommitted work).

- [ ] **Step 3: Branch for this work**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound checkout -b chain-removal
```

---

## Task 1: New audit module — TDD scaffold

**Files:**
- Create: `mcp-server/tests/test_audit.py`
- Create: `mcp-server/src/protocol_sift_mcp/tools/audit.py`

- [ ] **Step 1: Write failing test for `audit_append`**

Create `mcp-server/tests/test_audit.py`:

```python
"""Audit log tests. Plain append-only JSONL — no hash links, no signing."""
from __future__ import annotations

import json
from pathlib import Path

from protocol_sift_mcp.tools import audit


def test_audit_append_writes_one_jsonl_line(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    entry = audit.audit_append(log, event="tool_call", data={"tool": "os_detect", "path": "/input/x.plist"})
    assert log.exists()
    with log.open() as f:
        line = f.readline().strip()
    parsed = json.loads(line)
    assert parsed["event"] == "tool_call"
    assert parsed["data"]["tool"] == "os_detect"
    assert "ts" in parsed
    assert parsed["seq"] == 0
    assert entry == parsed


def test_audit_append_increments_seq(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    audit.audit_append(log, event="tool_call", data={"tool": "a"})
    audit.audit_append(log, event="tool_call", data={"tool": "b"})
    audit.audit_append(log, event="finding_recorded", data={"id": "F-001"})
    lines = log.read_text().strip().split("\n")
    assert len(lines) == 3
    seqs = [json.loads(line)["seq"] for line in lines]
    assert seqs == [0, 1, 2]


def test_audit_append_creates_parent_dir(tmp_path: Path) -> None:
    log = tmp_path / "deep" / "nested" / "audit.jsonl"
    audit.audit_append(log, event="tool_call", data={})
    assert log.exists()
```

- [ ] **Step 2: Run test, expect import failure**

```bash
cd /Users/x00x/Desktop/SANS/memory-hound
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_audit.py -v --no-cov
```

Expected: 3 ERRORS — `ModuleNotFoundError: No module named 'protocol_sift_mcp.tools.audit'`.

- [ ] **Step 3: Write minimal `audit.py`**

Create `mcp-server/src/protocol_sift_mcp/tools/audit.py`:

```python
"""Plain append-only JSONL audit log.

Replaces the prior hash-chained chain-of-custody. No cryptographic linking,
no signing, no attestation. Internal admin IR only — not legal-grade.
Every entry has seq + ts + event + data.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _next_seq(log_path: Path) -> int:
    if not log_path.exists() or log_path.stat().st_size == 0:
        return 0
    n = 0
    with log_path.open() as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def audit_append(log_path: Path, *, event: str, data: dict[str, Any]) -> dict[str, Any]:
    """Append a tool-call / lifecycle event to the audit log."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "seq": _next_seq(log_path),
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        "data": data,
    }
    with log_path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str) + "\n")
    return entry


def agent_message_append(
    log_path: Path,
    *,
    from_agent: str,
    to_agent: str,
    role: str,
    content: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append an inter-agent message. Required for hackathon multi-agent submissions."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "seq": _next_seq(log_path),
        "ts": datetime.now(UTC).isoformat(),
        "from_agent": from_agent,
        "to_agent": to_agent,
        "role": role,
        "content": content,
        "metadata": metadata or {},
    }
    with log_path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str) + "\n")
    return entry
```

- [ ] **Step 4: Run tests, expect pass**

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_audit.py -v --no-cov
```

Expected: 3 passed.

- [ ] **Step 5: Add inter-agent message test, expect pass first time (already implemented)**

Append to `mcp-server/tests/test_audit.py`:

```python
def test_agent_message_append(tmp_path: Path) -> None:
    log = tmp_path / "agent_messages.jsonl"
    e = audit.agent_message_append(
        log,
        from_agent="triage-orchestrator",
        to_agent="windows-agent",
        role="dispatch",
        content="Analyze NTUSER.DAT for persistence keys",
        metadata={"artifact": "/input/NTUSER.DAT"},
    )
    assert e["from_agent"] == "triage-orchestrator"
    assert e["to_agent"] == "windows-agent"
    assert e["role"] == "dispatch"
    assert e["metadata"]["artifact"] == "/input/NTUSER.DAT"
```

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_audit.py -v --no-cov
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add mcp-server/src/protocol_sift_mcp/tools/audit.py mcp-server/tests/test_audit.py
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "feat(audit): plain append-only JSONL audit + agent-message log"
```

---

## Task 2: MCP server — register `audit_append` tool, drop chain tools

**Files:**
- Modify: `mcp-server/src/protocol_sift_mcp/server.py`

- [ ] **Step 1: Add failing test for `audit_append` MCP tool registration**

Append to `mcp-server/tests/test_audit.py`:

```python
import asyncio

from protocol_sift_mcp.server import call_tool, list_tools


def test_mcp_tools_does_not_list_chain_tools() -> None:
    tools = asyncio.run(list_tools())
    names = {t.name for t in tools}
    assert "chain_append" not in names
    assert "chain_verify" not in names
    assert "chain_acknowledge_gap" not in names


def test_mcp_tools_lists_audit_append() -> None:
    tools = asyncio.run(list_tools())
    names = {t.name for t in tools}
    assert "audit_append" in names
```

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_audit.py -v --no-cov
```

Expected: 2 new tests FAIL (chain tools still registered, audit_append not yet registered).

- [ ] **Step 2: Edit `server.py` — drop chain Tool entries (lines 43-71 in current file)**

Open `mcp-server/src/protocol_sift_mcp/server.py`. In the `list_tools()` function, delete the three Tool entries: `chain_append`, `chain_verify`, `chain_acknowledge_gap`. Add a new Tool entry for `audit_append` immediately after `hash`:

```python
        Tool(
            name="audit_append",
            description=(
                "Append a tool-call or lifecycle event to the plain audit log. "
                "Use when an event needs durable record. Most events are auto-logged "
                "by the PostToolUse hook."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "event": {"type": "string"},
                    "data": {"type": "object"},
                },
                "required": ["event", "data"],
            },
        ),
```

- [ ] **Step 3: Edit `server.py` — drop chain handlers and add audit handler in `call_tool`**

In the same file's `call_tool` function, delete the three handler blocks (`chain_append`, `chain_verify`, `chain_acknowledge_gap`). Replace with a single `audit_append` block. Replace these lines:

```python
    if name == "chain_append":
        entry = ev.chain_append(
            CHAIN_PATH,
            event=arguments["event"],
            data=arguments["data"],
        )
        return [TextContent(type="text", text=str(entry))]
    if name == "chain_verify":
        ok, problems = ev.chain_verify(CHAIN_PATH)
        return [
            TextContent(
                type="text",
                text=f"ok={ok} problems={problems}",
            )
        ]
    if name == "chain_acknowledge_gap":
        entry = ev.chain_append(
            CHAIN_PATH,
            event="gap_acknowledged",
            data={
                "scope": arguments["scope"],
                "reason": arguments["reason"],
                "ts": datetime.now(UTC).isoformat(),
            },
        )
        return [TextContent(type="text", text=str(entry))]
```

with:

```python
    if name == "audit_append":
        entry = au.audit_append(
            AUDIT_PATH,
            event=arguments["event"],
            data=arguments["data"],
        )
        return [TextContent(type="text", text=str(entry))]
```

- [ ] **Step 4: Edit `server.py` — update imports + path constants**

At the top of `server.py`, change:

```python
from .tools import evidence as ev
```

to:

```python
from .tools import audit as au
from .tools import evidence as ev
```

Replace:

```python
OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "/output"))
CHAIN_PATH = OUTPUT_PATH / "chain-of-custody.jsonl"
FINDINGS_PATH = OUTPUT_PATH / "findings.json"
```

with:

```python
OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "/output"))
AUDIT_PATH = OUTPUT_PATH / "audit.jsonl"
FINDINGS_PATH = OUTPUT_PATH / "findings.json"
```

Drop the `from datetime import UTC, datetime` import if `datetime` is no longer referenced in server.py (it was only used by the deleted gap handler — verify with grep).

- [ ] **Step 5: Edit `server.py` — `finding_record` chain side-effect**

In the `finding_record` handler in `call_tool`, replace:

```python
    if name == "finding_record":
        record = fd.finding_record(FINDINGS_PATH, arguments)
        ev.chain_append(
            CHAIN_PATH,
            event="finding_recorded",
            data={"finding_id": record["finding_id"]},
        )
        return [TextContent(type="text", text=str(record))]
```

with:

```python
    if name == "finding_record":
        record = fd.finding_record(FINDINGS_PATH, arguments)
        au.audit_append(
            AUDIT_PATH,
            event="finding_recorded",
            data={"finding_id": record["finding_id"]},
        )
        return [TextContent(type="text", text=str(record))]
```

- [ ] **Step 6: Run server tests, expect pass**

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_audit.py -v --no-cov
```

Expected: 6 passed.

- [ ] **Step 7: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add mcp-server/src/protocol_sift_mcp/server.py mcp-server/tests/test_audit.py
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "feat(server): replace chain MCP tools with audit_append"
```

---

## Task 3: Strip chain functions from `evidence.py`

**Files:**
- Modify: `mcp-server/src/protocol_sift_mcp/tools/evidence.py`

- [ ] **Step 1: Delete chain tests from `test_evidence.py` first**

Open `mcp-server/tests/test_evidence.py`. Delete every test function except `test_hash_file_dual_algorithm`. Specifically delete:
- `test_chain_init_idempotent`
- `test_chain_append_links_correctly`
- `test_chain_verify_passes_on_clean_chain`
- `test_chain_verify_detects_data_tamper`
- All `test_sign_*`, `test_attest_*`, `test_generate_keypair*` tests
- All chain-related fixtures

Top imports — remove `cryptography` imports. Final file should look roughly:

```python
"""Hash file tests."""
from __future__ import annotations

from pathlib import Path

from protocol_sift_mcp.tools import evidence as ev


def test_hash_file_dual_algorithm(tmp_path: Path) -> None:
    f = tmp_path / "input" / "sample.bin"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(b"The quick brown fox jumps over the lazy dog")
    digest = ev.hash_file(f)
    assert digest["sha256"] == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    assert digest["sha1"] == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    assert digest["size"] == 43
```

- [ ] **Step 2: Run trimmed evidence tests, expect 1 pass**

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_evidence.py -v --no-cov
```

Expected: 1 passed.

- [ ] **Step 3: Strip chain functions from `evidence.py`**

Open `mcp-server/src/protocol_sift_mcp/tools/evidence.py`. Replace the entire file with:

```python
"""Evidence hashing primitives.

Reduced from the prior trust-stack module — chain-of-custody, signing, and
attestation were removed. Plain audit-log behavior lives in `audit.py`.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from ..sandbox import assert_input_path
from . import audit


HASH_ALGO = "sha256"


def hash_file(path: Path, *, chunk_size: int = 1 << 20) -> dict[str, str | int]:
    """Compute sha256 + sha1 of a file in one pass."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # noqa: S324 - dual-hash for collision resistance
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
            sha1.update(chunk)
            size += len(chunk)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "size": size}


def ingest_artifact(audit_path: Path, artifact: Path) -> dict:
    """Hash an evidence file and append an `evidence_ingest` entry to the audit log."""
    artifact = assert_input_path(artifact)
    digest = hash_file(artifact)
    return audit.audit_append(
        audit_path,
        event="evidence_ingest",
        data={"artifact": str(artifact), **digest},
    )


def main(argv: list[str] | None = None) -> int:
    """CLI: hooks call `python -m protocol_sift_mcp.tools.evidence ingest --audit <log> --artifact <path>`."""
    parser = argparse.ArgumentParser(prog="protocol_sift_mcp.tools.evidence")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest")
    p_ingest.add_argument("--audit", required=True, type=Path)
    p_ingest.add_argument("--artifact", required=True, type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "ingest":
        ingest_artifact(args.audit, args.artifact)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Add ingest test using new audit log**

Append to `mcp-server/tests/test_evidence.py`:

```python
def test_ingest_artifact_writes_to_audit_log(tmp_path: Path, monkeypatch) -> None:
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    artifact = input_dir / "sample.bin"
    artifact.write_bytes(b"hello")

    audit_log = tmp_path / "output" / "audit.jsonl"

    # ingest_artifact validates path is under EVIDENCE_PATH; force INPUT_ROOT for test.
    monkeypatch.setenv("EVIDENCE_PATH", str(input_dir))
    from protocol_sift_mcp import sandbox
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())

    entry = ev.ingest_artifact(audit_log, artifact)
    assert entry["event"] == "evidence_ingest"
    assert "sha256" in entry["data"]
    assert audit_log.exists()
```

- [ ] **Step 5: Run tests**

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests/test_evidence.py mcp-server/tests/test_audit.py -v --no-cov
```

Expected: all pass (2 + 6 = 8).

- [ ] **Step 6: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add mcp-server/src/protocol_sift_mcp/tools/evidence.py mcp-server/tests/test_evidence.py
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "refactor(evidence): drop chain/sign/attest, keep hash_file + ingest"
```

---

## Task 4: Strip chain models from `schema.py`

**Files:**
- Modify: `mcp-server/src/protocol_sift_mcp/schema.py`

- [ ] **Step 1: Delete `ChainEvent`, `ChainEntry`, `Attestation` from `schema.py`**

Open `mcp-server/src/protocol_sift_mcp/schema.py`. Delete the three blocks:

```python
ChainEvent = Literal[
    "chain_init",
    ...
]


class ChainEntry(BaseModel):
    ...


class Attestation(BaseModel):
    ...
```

Also remove `Literal` from the `from typing import` line if no other model uses it (check by grep).

- [ ] **Step 2: Run full test suite to confirm no regression**

```bash
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests -q --no-cov 2>&1 | tail -10
```

Expected: All tests pass. Total count = baseline minus deleted chain tests plus new audit/ingest tests.

- [ ] **Step 3: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add mcp-server/src/protocol_sift_mcp/schema.py
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "refactor(schema): drop ChainEvent/ChainEntry/Attestation models"
```

---

## Task 5: Replace `session-start.sh` hook

**Files:**
- Modify: `.claude/hooks/session-start.sh`

- [ ] **Step 1: Replace hook contents**

Overwrite `.claude/hooks/session-start.sh` with:

```bash
#!/usr/bin/env bash
# SessionStart hook — initialize the audit log and hash all input evidence.
# No chain hash, no signing — plain append-only JSONL.
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
OUTPUT_DIR="${OUTPUT_PATH:-${PROJECT_DIR}/output}"
INPUT_DIR="${EVIDENCE_PATH:-${PROJECT_DIR}/input}"
CASE_ID="${CASE_ID:-default-$(date -u +%Y%m%d%H%M%S)}"

mkdir -p "$OUTPUT_DIR"
AUDIT_LOG="$OUTPUT_DIR/audit.jsonl"

# Session-init entry.
python3 -c "
from pathlib import Path
from protocol_sift_mcp.tools import audit
audit.audit_append(
    Path('$AUDIT_LOG'),
    event='session_init',
    data={
        'case_id': '$CASE_ID',
        'evidence_path': '$INPUT_DIR',
        'agent_version': 'memoryhound@0.1.0',
        'model': '${MODEL_NAME:-claude-opus-4-7}',
    },
)
"

# Hash + record every input artifact.
if [[ -d "$INPUT_DIR" ]]; then
    while IFS= read -r -d '' artifact; do
        python3 -m protocol_sift_mcp.tools.evidence ingest \
            --audit "$AUDIT_LOG" \
            --artifact "$artifact"
    done < <(find "$INPUT_DIR" -type f -print0)
fi

echo "{\"hookSpecificOutput\": {\"hookEventName\": \"SessionStart\", \"additionalContext\": \"audit log initialized at $AUDIT_LOG, case=$CASE_ID\"}}"
```

- [ ] **Step 2: Make executable**

```bash
chmod +x /Users/x00x/Desktop/SANS/memory-hound/.claude/hooks/session-start.sh
```

- [ ] **Step 3: Smoke-test the hook directly**

```bash
cd /tmp && rm -rf mh-hook-test && mkdir -p mh-hook-test/input mh-hook-test/output
echo "test" > mh-hook-test/input/sample.txt
EVIDENCE_PATH=/tmp/mh-hook-test/input \
OUTPUT_PATH=/tmp/mh-hook-test/output \
CASE_ID=test-001 \
CLAUDE_PROJECT_DIR=/Users/x00x/Desktop/SANS/memory-hound \
PYTHONPATH=/Users/x00x/Desktop/SANS/memory-hound/mcp-server/src \
/Users/x00x/Desktop/SANS/memory-hound/.venv/bin/python -c "import sys; sys.path.insert(0, '/Users/x00x/Desktop/SANS/memory-hound/mcp-server/src'); exec(open('/Users/x00x/Desktop/SANS/memory-hound/.claude/hooks/session-start.sh').read().replace('python3', '/Users/x00x/Desktop/SANS/memory-hound/.venv/bin/python'))"
cat /tmp/mh-hook-test/output/audit.jsonl
```

Expected: 2 JSONL lines — one `session_init`, one `evidence_ingest` with sha256 of "test\n".

- [ ] **Step 4: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add .claude/hooks/session-start.sh
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "refactor(hooks): session-start writes plain audit log"
```

---

## Task 6: Replace `audit.sh` and `finalize.sh` hooks

**Files:**
- Modify: `.claude/hooks/audit.sh`
- Modify: `.claude/hooks/finalize.sh`

- [ ] **Step 1: Replace `audit.sh`**

Overwrite `.claude/hooks/audit.sh`:

```bash
#!/usr/bin/env bash
# PostToolUse hook — append every tool call to the plain audit log.
set -euo pipefail

INPUT_JSON=$(cat)
OUTPUT_DIR="${OUTPUT_PATH:-${CLAUDE_PROJECT_DIR}/output}"
AUDIT_LOG="$OUTPUT_DIR/audit.jsonl"

python3 -c "
import json, sys
from pathlib import Path
from protocol_sift_mcp.tools import audit
data = json.loads('''$INPUT_JSON''') if '''$INPUT_JSON'''.strip() else {}
audit.audit_append(Path('$AUDIT_LOG'), event='tool_call', data=data)
" 2>/dev/null || {
    echo "{\"hookSpecificOutput\": {\"hookEventName\": \"PostToolUse\", \"additionalContext\": \"audit append failed (non-fatal)\"}}"
    exit 0
}

echo '{"hookSpecificOutput": {"hookEventName": "PostToolUse"}}'
```

- [ ] **Step 2: Replace `finalize.sh`**

Overwrite `.claude/hooks/finalize.sh`:

```bash
#!/usr/bin/env bash
# Stop hook — close out the audit log with a session summary.
# No chain verification, no signing — plain append-only.
set -euo pipefail

OUTPUT_DIR="${OUTPUT_PATH:-${CLAUDE_PROJECT_DIR}/output}"
AUDIT_LOG="$OUTPUT_DIR/audit.jsonl"
CASE_ID="${CASE_ID:-unknown}"

python3 -c "
from pathlib import Path
from protocol_sift_mcp.tools import audit
audit.audit_append(
    Path('$AUDIT_LOG'),
    event='session_finalize',
    data={'case_id': '$CASE_ID'},
)
"

echo "{\"hookSpecificOutput\": {\"hookEventName\": \"Stop\", \"additionalContext\": \"audit log finalized for case $CASE_ID\"}}"
```

- [ ] **Step 3: Make both executable, smoke-test**

```bash
chmod +x /Users/x00x/Desktop/SANS/memory-hound/.claude/hooks/audit.sh /Users/x00x/Desktop/SANS/memory-hound/.claude/hooks/finalize.sh
echo '{"tool_name":"Read","tool_input":{"file_path":"/input/x"}}' | OUTPUT_PATH=/tmp/mh-hook-test/output PYTHONPATH=/Users/x00x/Desktop/SANS/memory-hound/mcp-server/src /Users/x00x/Desktop/SANS/memory-hound/.claude/hooks/audit.sh
tail -1 /tmp/mh-hook-test/output/audit.jsonl
```

Expected: last line is a `tool_call` event with the JSON payload.

- [ ] **Step 4: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add .claude/hooks/audit.sh .claude/hooks/finalize.sh
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "refactor(hooks): audit + finalize use plain audit log"
```

---

## Task 7: Update `bin/mh` — drop verify, simplify init/demo/status/tools

**Files:**
- Modify: `bin/mh`

- [ ] **Step 1: Drop `cmd_verify`**

Delete the entire `cmd_verify()` function from `bin/mh`. Remove the `verify) cmd_verify "$@" ;;` dispatch line. Remove the `verify <case-id>` line from `cmd_help`.

- [ ] **Step 2: Drop keypair generation in `cmd_init`**

In `cmd_init`, delete the entire keypair generation block:

```bash
    if [[ ! -f "${MH_KEYS_DIR}/ed25519.priv" ]]; then
        info "Generating ed25519 signing keypair"
        mkdir -p "$MH_KEYS_DIR"
        "$MH_PY" -m protocol_sift_mcp.tools.evidence keygen --out-dir "$MH_KEYS_DIR"
        chmod 600 "${MH_KEYS_DIR}/ed25519.priv"
        ok "Keypair at ${MH_KEYS_DIR}/"
    else
        ok "Keypair already exists at ${MH_KEYS_DIR}/"
    fi
```

Also delete `MH_KEYS_DIR="${MH_HOME}/keys"` near the top.

- [ ] **Step 3: Simplify `cmd_doctor`**

In `cmd_doctor`, delete the keypair check block (`if [[ -f "${MH_KEYS_DIR}/ed25519.priv" ]]`) and the cryptography import check. The remaining checks (Python, venv, claude, settings.json, MCP launcher) stay.

- [ ] **Step 4: Strip chain steps from `cmd_demo`**

The `cmd_demo` function has 8 chain-centric steps. Replace it with a simplified version that demonstrates ingest + parse + audit log without tamper test:

Replace the entire `cmd_demo()` function with:

```bash
cmd_demo() {
    local autonomous=0
    for arg in "$@"; do
        case "$arg" in
            --autonomous|--auto) autonomous=1 ;;
            -h|--help) echo "Usage: mh demo [--autonomous]"; return 0 ;;
        esac
    done

    info "MemoryHound demo — collects safe artifacts from THIS host, parses them, writes audit log."
    echo ""

    local demo_dir="${MH_CASES_DIR}/_demo"
    rm -rf "$demo_dir"
    mkdir -p "${demo_dir}/input" "${demo_dir}/output"

    info "Step 1: self-collect host artifacts"
    "${MH_HOME}/scripts/self-collect.sh" "${demo_dir}/input" 2>&1 | sed 's/^/    /'

    local audit_log="${demo_dir}/output/audit.jsonl"
    export EVIDENCE_PATH="${demo_dir}/input"
    export OUTPUT_PATH="${demo_dir}/output"

    info "Step 2: ingest each artifact (compute sha256+sha1, append to audit log)"
    local ingested=0
    while IFS= read -r f; do
        PYTHONPATH="${MH_HOME}/mcp-server/src" "$MH_PY" -m protocol_sift_mcp.tools.evidence ingest \
            --audit "$audit_log" --artifact "$f" >/dev/null
        ingested=$((ingested + 1))
    done < <(find "${demo_dir}/input" -type f)
    ok "    $ingested artifacts ingested"

    info "Step 3: classify each artifact with os_detect + parse"
    local classified=0
    while IFS= read -r f; do
        local rel="${f#${demo_dir}/input/}"
        PYTHONPATH="${MH_HOME}/mcp-server/src" "$MH_PY" -c "
from protocol_sift_mcp.tools import parse, macos, audit
from pathlib import Path
import json
path = '$f'
det = parse.os_detect(path)
result = {'rel': '$rel', 'os': det['os'], 'class': det['evidence_class'], 'conf': det['confidence']}
if det['evidence_class'] == 'plist':
    try:
        r = macos.mac_plist_get(path)
        result['format'] = r['format']
        result['root_keys_count'] = len(r['root_keys'])
    except Exception as e:
        result['parse_error'] = str(e)[:80]
audit.audit_append(Path('$audit_log'), event='tool_call', data={'tool': 'os_detect+parse', 'artifact': '$rel', 'result': result})
print(json.dumps(result))
" 2>&1 | sed 's/^/    /'
        classified=$((classified + 1))
    done < <(find "${demo_dir}/input" -type f)
    ok "    $classified artifacts classified, all logged to $audit_log"

    echo ""
    ok "Demo complete."
    info "Audit log: $audit_log ($(wc -l <"$audit_log") entries)"

    if [[ $autonomous -eq 1 ]]; then
        echo ""
        info "Autonomous phase requires LangGraph orchestrator (Sub-Plan 02). Skipping for now."
    fi
}
```

- [ ] **Step 5: Update `cmd_status`**

Replace the phase-detection section in `cmd_status` to remove attestation references:

```bash
        local phase="empty"
        if [[ -f "${case_dir}/output/findings.json" ]]; then
            phase="${GREEN}finished${NC}"
        elif [[ -f "${case_dir}/output/audit.jsonl" ]]; then
            phase="${YELLOW}in-progress${NC}"
        elif [[ -d "${case_dir}/input" ]] && [[ -n "$(ls -A "${case_dir}/input" 2>/dev/null)" ]]; then
            phase="staged"
        fi
```

- [ ] **Step 6: Update `cmd_tools`**

Replace the chain block in the `cmd_tools` cat heredoc:

```bash
  Audit / lifecycle:
    hash                       — sha256 + sha1 + size
    audit_append               — append to plain audit log
    finding_record             — register finding (rejects un-pinned)
```

Drop the entire `Trust stack:` section.

- [ ] **Step 7: Update `claude_run`'s allowedTools**

In `claude_run` function, replace the `allowed` variable:

```bash
    local allowed="mcp__protocol_sift__hash,mcp__protocol_sift__audit_append,mcp__protocol_sift__finding_record,mcp__protocol_sift__os_detect,mcp__protocol_sift__magic_check,mcp__protocol_sift__win_registry_get,mcp__protocol_sift__win_prefetch_parse,mcp__protocol_sift__win_evtx_query,mcp__protocol_sift__win_lnk_parse,mcp__protocol_sift__mac_plist_get,mcp__protocol_sift__mac_knowledgec_query,Read,Glob,Grep,TodoWrite"
```

- [ ] **Step 8: Smoke-test mh CLI**

```bash
cd /Users/x00x/Desktop/SANS/memory-hound
./bin/mh help | head -25
./bin/mh tools
./bin/mh doctor 2>&1 | tail -15
```

Expected: `verify` command absent from help; `tools` lists `audit_append` not `chain_*`; `doctor` no longer mentions keypair.

- [ ] **Step 9: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add bin/mh
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "refactor(mh): drop verify cmd, strip chain from init/demo/status/tools"
```

---

## Task 8: Delete keys/ + chain-of-custody skill

**Files:**
- Delete: `keys/ed25519.priv`, `keys/ed25519.pub`, `keys/`
- Delete: `.claude/skills/chain-of-custody/`

- [ ] **Step 1: Delete keys directory**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound rm -r keys
```

- [ ] **Step 2: Delete chain-of-custody skill**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound rm -r .claude/skills/chain-of-custody
```

- [ ] **Step 3: Search for any remaining references**

```bash
grep -rn "chain-of-custody\|chain_init\|chain_append\|chain_verify\|attestation\|ed25519\|keys/ed25519" /Users/x00x/Desktop/SANS/memory-hound --include="*.py" --include="*.sh" --include="*.md" --include="*.json" --include="*.yml" --exclude-dir=.venv --exclude-dir=.git --exclude-dir=docs 2>/dev/null | head -30
```

Expected: hits only inside `docs/` and `README.md` (handled in Task 9).

- [ ] **Step 4: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add -A
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "chore: remove keys/ and chain-of-custody skill"
```

---

## Task 9: Update README, docs/architecture.md, docs/usage.md

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/usage.md`

- [ ] **Step 1: Update README — drop trust-stack tagline + 7-layer table**

Open `README.md`. Replace line 3 (current: `**Drop-in DFIR superpowers for Claude Code.** Autonomous, cross-OS incident response triage with verifiable findings, signed attestations, and a tamper-evident audit trail.`) with:

```markdown
**Drop-in DFIR superpowers for Claude Code.** Autonomous, cross-OS incident response triage with structured findings and a plain audit trail.
```

Delete the entire `## Trust Stack — 7 Layers` section (the table with 7 rows).

In the `## What's Real vs Stub` table, delete these rows:
- `Trust stack (hash chain, ed25519 sign, attestation)`
- Any rows referencing "signed" or "attestation".

Update the architecture diagram block to remove the `EvidenceCustodian` and `Verifier` boxes' bottom-row "(hash chain, sign)" annotation; replace with "(plain audit log)".

In the `## CLI Reference`, delete:
- `mh verify <case-id>` row.

In the Quickstart, delete step 4: `# 4. Verify the chain + signature` and the `./bin/mh verify case-001` line.

In the output table, delete:
- `chain-of-custody.jsonl` row → replace with `audit.jsonl | Plain append-only audit log`
- `case-<id>.attestation.json` row entirely.

Replace `## See It Work In 60 Seconds (No API Key Needed)` section's bullet list — drop tamper-detect steps:

```markdown
```
» Step 1: self-collect safe host artifacts            ✓
» Step 2: ingest, hash, write to audit log            ✓
» Step 3: classify each artifact with os_detect       ✓
» Step 4: parse plist contents                        ✓
```
```

- [ ] **Step 2: Update docs/architecture.md**

Open `docs/architecture.md`. Find any sections referencing chain-of-custody, ed25519, attestation, SLSA, in-toto, signing — delete or rewrite to reference the plain audit log. (Read first; specific edits depend on current content.) Run:

```bash
grep -n "chain\|attest\|ed25519\|SLSA\|in-toto\|sign" /Users/x00x/Desktop/SANS/memory-hound/docs/architecture.md | head -40
```

Replace each hit with audit-log-equivalent prose.

- [ ] **Step 3: Update docs/usage.md**

Replace the `## Verifying A Run` section content with:

```markdown
## Verifying A Run

The audit log lives at `output/audit.jsonl`. Inspect with:

```bash
head -5 output/audit.jsonl | jq .
wc -l output/audit.jsonl
```

Each line is one event: `session_init`, `evidence_ingest`, `tool_call`, `finding_recorded`, `session_finalize`. Sequence numbers increment monotonically.
```

Delete the entire `## Live Tamper Demo` section.

- [ ] **Step 4: Verify all references removed**

```bash
grep -rn "chain-of-custody\|chain_verify\|attestation\|ed25519" /Users/x00x/Desktop/SANS/memory-hound --include="*.md" --exclude-dir=.venv --exclude-dir=.git
```

Expected: zero hits (or only the IR_FRAMEWORKS_REFERENCE.md and master spec which intentionally mention them in framework context).

- [ ] **Step 5: Commit**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound add README.md docs/architecture.md docs/usage.md
git -C /Users/x00x/Desktop/SANS/memory-hound commit -m "docs: rewrite chain-of-custody references to plain audit log"
```

---

## Task 10: Final validation — full test suite + smoke test demo

**Files:** none modified

- [ ] **Step 1: Full test suite**

```bash
cd /Users/x00x/Desktop/SANS/memory-hound
PYTHONPATH=mcp-server/src .venv/bin/python -m pytest mcp-server/tests -q --no-cov 2>&1 | tail -10
```

Expected: All pass. Total = (baseline 48) − (5 deleted chain tests) + (5 new audit/ingest tests) = 48 ± a few. Confirm zero failures.

- [ ] **Step 2: Run `mh demo` end-to-end**

```bash
./bin/mh demo
```

Expected output:
- Self-collects ~5-10 host artifacts.
- Ingests each, prints sha256.
- Classifies each via `os_detect` + parses plists.
- Reports `Demo complete. Audit log: ./cases/_demo/output/audit.jsonl (N entries)`.
- No errors, no chain verification step, no attestation file produced.

- [ ] **Step 3: Inspect audit log structure**

```bash
head -3 cases/_demo/output/audit.jsonl | python3 -m json.tool --no-ensure-ascii
wc -l cases/_demo/output/audit.jsonl
```

Expected: each line valid JSON with `seq`, `ts`, `event`, `data` keys; no `prev_hash`, `hash`, `signature`.

- [ ] **Step 4: Confirm absence of chain artifacts**

```bash
ls cases/_demo/output/
```

Expected: `audit.jsonl` present; `chain-of-custody.jsonl` absent; `case-*.attestation.json` absent.

- [ ] **Step 5: Final commit (if any pending tweaks)**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound status
git -C /Users/x00x/Desktop/SANS/memory-hound log --oneline chain-removal ^main 2>/dev/null | head -15
```

Expected: ~9 commits on the chain-removal branch since branching.

- [ ] **Step 6: Tag completion**

```bash
git -C /Users/x00x/Desktop/SANS/memory-hound tag sub-plan-01-complete
```

---

## Acceptance Summary

After this plan completes:

✅ `mcp-server/src/protocol_sift_mcp/tools/audit.py` exists with `audit_append` + `agent_message_append`
✅ MCP server registers `audit_append` tool, no longer registers `chain_*` tools
✅ `evidence.py` reduced to `hash_file` + `ingest_artifact` + CLI `ingest` subcommand
✅ `schema.py` no longer defines `ChainEvent`, `ChainEntry`, `Attestation`
✅ Hooks write to plain `audit.jsonl`; no hash linking, no signing
✅ `bin/mh` no longer has `verify` command; `init`/`demo`/`status`/`tools` simplified
✅ `keys/` directory deleted
✅ `.claude/skills/chain-of-custody/` deleted
✅ All Markdown docs updated
✅ Full test suite passes (audit tests + hash tests + sandbox tests + parse tests + Windows tests + macOS tests)
✅ `mh demo` runs end-to-end without errors

---

## Self-Review

**Spec coverage:**
- Master spec sub-plan 01 acceptance items mapped to Task 10 verification steps. All 4 acceptance items (output files present/absent, tests pass, new audit test exists) covered.
- Master spec blast radius items mapped to Tasks 2-9. All 14 blast-radius items addressed.

**Placeholder scan:** No "TBD" / "implement later" / "similar to" / "add appropriate" markers. Every step shows exact code or exact command.

**Type consistency:**
- `audit_append(log_path, event, data)` signature consistent across Tasks 1, 2, 3, 5, 6.
- `agent_message_append(log_path, from_agent, to_agent, role, content, metadata)` defined Task 1, used by future Sub-Plan 02 (no usage in this plan).
- `AUDIT_PATH` constant introduced Task 2 in `server.py`; same path layout used by hooks Task 5/6 (`$OUTPUT_PATH/audit.jsonl`).
- `evidence.ingest_artifact(audit_path, artifact)` signature in Task 3 matches CLI subcommand `--audit` flag.
