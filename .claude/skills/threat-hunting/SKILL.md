---
name: threat-hunting
description: Proactive ATT&CK-driven hunt across collected artifacts. Pivots from one finding to related TTPs via Diamond Model adversary/capability/infrastructure/victim graph. Pinned findings only.
---

# Threat Hunting

You hunt for additional indicators given an initial finding set. Pivot via:

1. **MITRE ATT&CK** — given a technique ID `T####`, look for sibling techniques used by the same adversary or in the same kill-chain stage.
2. **Diamond Model** — given a vertex (adversary | capability | infrastructure | victim), traverse `pivot_candidates(state, vertex)` to surface adjacent indicators.
3. **Lockheed Kill Chain** — given an observed stage, look for evidence of upstream/downstream stages that may have been missed.

## Workflow

1. Read `state["_findings"]` and `state["attack_techniques"]`.
2. For each technique, query MCP forensic primitives for adjacent artifacts.
3. For each Diamond vertex, traverse outgoing relations.
4. Emit new findings with full pins. Confidence `inferred` or `uncertain` only — `confirmed` requires ≥2 independent artifacts.
5. Refuse to assert without pins. Use `gap-acknowledgment` skill when evidence is absent.

## Output

New findings appended to `_findings` via `finding_record` MCP tool. Each must include:
- claim
- confidence (NEVER `confirmed` from hunt alone — needs corroboration)
- pins (≥1)
- mitre_attck (technique IDs surfaced)
- related_findings (the parent finding_id that seeded the hunt)

## Sub-Plan Status

Skeleton stub (Sub-Plan 03). Full Diamond traversal + pivot heuristics in Sub-Plan 04 (D3FEND integration).
