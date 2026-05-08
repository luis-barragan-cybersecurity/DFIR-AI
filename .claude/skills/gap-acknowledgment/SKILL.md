---
name: gap-acknowledgment
description: Discipline for acknowledging what we don't know. Calling out gaps explicitly via a `confidence='unknown'` finding is a strength signal — judges score honesty positively and detect inflated claims fast. This skill teaches when to refuse vs. when to assert.
---

# Gap Acknowledgment

"I don't know" is a valid output. Use it.

## When To Acknowledge a Gap

| Situation | Action |
|---|---|
| Tool failed with no fallback that produces same evidence class | acknowledge + note alternative attempted |
| Symbol table missing for memory dump | acknowledge — do NOT invent process names |
| Encrypted artifact (Signal DB without keychain access) | acknowledge — do NOT speculate on contents |
| Evidence corrupted / partial | acknowledge — note recoverable vs unrecoverable |
| Single ambiguous artifact, not enough to pin confidence higher than `uncertain` | EITHER pin as `uncertain` OR acknowledge gap, not both |
| Question outside scope (e.g., asked about Linux when only Windows evidence ingested) | acknowledge — do NOT extrapolate |

## When NOT To Acknowledge

- Don't flood the audit log with trivial "couldn't determine X" entries — gaps should be substantive
- Don't acknowledge to dodge work; if the evidence is available, do the analysis

## Format

Call `finding_record` with `confidence='unknown'`, a single pin pointing at the artifact you couldn't conclude on, and a claim describing the gap:

```python
mcp__protocol_sift__finding_record(
    finding_id="GAP-001",
    claim="Cannot determine cridex.exe network destinations: netscan returned no entries for PID 1484. Possible causes: (a) connections closed before snapshot, (b) memory paged out, (c) covert channel not visible to netscan. Insufficient evidence to choose.",
    confidence="unknown",
    pins=[{
        "artifact": "/input/memory.raw",
        "tool": "memory_volatility",
        "locator": {"type": "memory_vad", "value": "PID:1484"},
        "raw_excerpt": "netscan: 0 records for PID 1484",
        "captured_at": "<iso8601>"
    }]
)
```

The `claim` field is read by the accuracy-report skill and surfaced in the final report. Make it specific.

## Demo Value

Calling out 3-5 honest gaps in the demo video sets MemoryHound apart. Most teams will hide or paper over uncertainty. Judges notice.
