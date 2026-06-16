# Sample Output Files

Real deliverables from a MemoryHound run, published so reviewers can inspect the
actual artifacts the tool produces (not a mockup).

## `rocba-memory/`

A run against a challenge Windows memory image (`Rocba-Memory.raw`, ~19 GB) with a
published case brief, so the findings can be checked against known ground truth.

| File | What it is |
|------|------------|
| `findings.json` | The 16 pinned findings — every claim tied to specific tool calls and artifacts |
| `accuracy-report.md` | Honest accuracy accounting: 9 confirmed, 4 inferred, 1 uncertain, 2 unknown, 5 named gaps |
| `narrative.md` | Investigative narrative of the incident |
| `exec-report.md` | One-page executive summary |
| `findings-supplemental.md` | Supplemental detail on the findings |
| `audit.jsonl` | SHA256-chained audit log of the run |

Raw run internals (verifier stdout traces, full state history, agent message logs)
are intentionally omitted here for readability.
