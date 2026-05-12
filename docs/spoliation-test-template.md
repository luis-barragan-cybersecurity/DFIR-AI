# Spoliation Test — Template

> Append this section to every case's `output/accuracy-report.md`. It is
> the empirical answer to the hackathon's "evidence integrity" rubric and
> the auditor's first question.

## Pre-run baseline

| Artifact | size_bytes | sha256 |
|---|---:|---|
| `<relative/path>` | `<bytes>` | `<sha256-hex>` |

Capture this by running:
```
./bin/mh orchestrate <case-id>      # writes output/manifest.json
cat cases/<case-id>/output/manifest.json | jq -r '.entries[] | [.path, .size_bytes, .sha256] | @tsv'
```

## Post-run re-verification

```
$ ./bin/mh verify <case-id>
» Verifying case <case-id>

» 1/3  Manifest re-hash
✓     manifest matches input/ (no spoliation detected)
» 2/3  Audit log hash chain
✓     audit chain intact (<N> entries)
» 3/3  Agent messages hash chain
✓     agent_messages chain intact

✓ Verification PASSED — case <case-id> chain-of-custody intact
```

Paste the actual output of `mh verify` above. Exit code 0 is the
required outcome.

## What "passing" proves

1. Every input artifact's sha256 is byte-identical to when it was first
   ingested. The agent did not write back over evidence.
2. The append-only audit log's `prev_hash` chain is unbroken from
   genesis to the most recent entry. No entry was tampered, reordered,
   or deleted.
3. The agent_messages stream (inter-agent communication transcript) is
   similarly intact.

## What a fail looks like

```
✗     manifest mismatch — see lines above
  sha256-changed: input/Rocba-Memory.raw
      manifest: 7a4f2b1c…
      on-disk : 8e92d11a…
✗ Verification FAILED — review breaks above
```

Common causes (none acceptable for hackathon scoring):
- A tool wrote to `/input` instead of `/output` — should be impossible
  given the sandbox; if it happens, it's a `sandbox.py` regression.
- An analyst manually edited evidence files between runs — out of scope
  for the autonomous-execution rubric.
- Disk corruption — re-image and rerun.

## Implementation references

- Manifest builder: `orchestrator/src/mh_orchestrator/nodes/manifest_ingest.py`
- Audit hash chain: `mcp-server/src/protocol_sift_mcp/tools/audit.py`
  (`audit_append`, `verify_audit_chain`)
- CLI re-verify: `scripts/verify-manifest.py` (called by `bin/mh verify`)
- Sandbox enforcement: `mcp-server/src/protocol_sift_mcp/sandbox.py`
  (`assert_input_path` is read-only; `assert_output_path` is the only
  write surface)
