# Name Overlap Decision — `protocol_sift_mcp` vs. `teamdfir/protocol-sift`

> **TL;DR.** `teamdfir/protocol-sift` is Rob Lee's project, published **2026-03-24**, ~32 days before MemoryHound first used the `protocol_sift_mcp` name on **2026-04-25**. They predate us. The repo has **no LICENSE = all rights reserved**. MemoryHound's own `docs/architecture.md` already calls itself a "Direct Agent Extension of Protocol SIFT," confirming the name is intentionally borrowed from Rob Lee's project. Risk is **LOW** legally (different packaging surface, no PyPI collision, name describes a concept not a trademarked product) but **MEDIUM** reputationally if we don't attribute. **Recommendation: keep the name, add explicit attribution + relationship statement in README and `mcp-server/README.md`.** Do not rename — that throws away the intentional lineage signal and breaks the 392-line README + 16 internal docs.

---

## 1. Timeline — Who Used the Name First

| Date (UTC) | Repo | Evidence |
|---|---|---|
| **2026-03-24 16:29:51Z** | `teamdfir/protocol-sift` first commit `feat: protocol-sift` (sha `a9c0e824`) | `gh api /repos/teamdfir/protocol-sift/commits` — oldest commit |
| 2026-03-24 16:00:41Z | `teamdfir/protocol-sift` repo created | `gh api /repos/teamdfir/protocol-sift` → `"created_at"` |
| 2026-03-25 19:24:45Z | `teamdfir/protocol-sift` last push (`Update README.md`) | repo `pushed_at` field — **dormant since** |
| **2026-04-25** | MemoryHound first commit `44fcd2b` `W1: scaffold MemoryHound — cross-OS DFIR triage agent` introducing `mcp-server/src/protocol_sift_mcp/` | `git log --reverse --format='%h %ad' --date=short mcp-server/pyproject.toml \| head -1` |
| 2026-05-08 | `docs/architecture.md` rewritten with explicit phrase `Direct Agent Extension of Protocol SIFT` | commit `802814d` per `git log --format='%h %ad %s' --date=short -- docs/architecture.md` |

**Conclusion:** `teamdfir/protocol-sift` predates `protocol_sift_mcp` by **~32 days**. The name was not parallel coinage on our side — `docs/architecture.md:7` openly frames MemoryHound as an *extension* of Protocol SIFT, which means whoever wrote the scaffold knew about Rob Lee's project.

---

## 2. License Posture

| Project | License | Source |
|---|---|---|
| **MemoryHound** | **Apache-2.0** | `/Users/x00x/Desktop/SANS/memory-hound/LICENSE` — full Apache 2.0 text, `Copyright 2026 MemoryHound Contributors` |
| **teamdfir/protocol-sift** | **No license file** → defaults to "all rights reserved" under US copyright | `https://raw.githubusercontent.com/teamdfir/protocol-sift/main/LICENSE` → HTTP 404; `gh api /repos/teamdfir/protocol-sift` → `"license": null` |

**Implications:**

- We have **not copied any code** from `teamdfir/protocol-sift`. Its content (a Claude Code skill installer for SIFT — `install.sh`, `analysis-scripts/`, `case-templates/`, `global/`, `skills/`) is structurally disjoint from MemoryHound's MCP server (typed forensic primitives in Python). License risk on copied code: **none**.
- "Protocol SIFT" as a **name** is not a registered trademark (no USPTO record, no `™`/`®` on the repo, no SANS trademark register entry — SANS trademarks "SIFT Workstation" and "SIFT," not "Protocol SIFT"). Names alone are generally not copyrightable; trademark would require actual commercial use in commerce and likelihood-of-confusion. Rob Lee's repo is dormant, non-commercial, no license, no `™`.
- **PyPI namespace check:** `protocol-sift-mcp` (HTTP 404) and `protocol-sift` (HTTP 404) — neither package is registered. We can publish `protocol-sift-mcp` without collision.
- The Rob Lee repo's README explicitly states: *"Rob Lee developed Protocol SIFT and all the files found within this repository."* That is an authorship claim, not a license grant. To be safe, we should not redistribute or repackage any of *his* files (we don't).

---

## 3. Is "Protocol SIFT" a Generic Term?

Short answer: **partially**. "SIFT" is widely used in DFIR — SANS SIFT Workstation, SIFT toolkit, SIFT mailing list. "Protocol" + "SIFT" is a plausible compound describing "structured protocol for SIFT-style forensics." However:

- The phrase "Protocol SIFT" as a named project **only appears** in Rob Lee's repo (and now MemoryHound). It is not a generic DFIR term that predates 2026-03.
- SANS course material, the official SIFT Workstation docs, and the FOR508/FOR500 curricula do not use "Protocol SIFT" as a label.
- This makes it a **coined term**, not generic — even though both elements ("protocol," "SIFT") are generic.

Verdict: not parallel coinage. We adopted Rob Lee's term.

---

## 4. Risk Assessment

| Risk vector | Level | Reasoning |
|---|---|---|
| **Copyright infringement (code)** | None | No code copied from `teamdfir/protocol-sift`. Different surfaces entirely. |
| **Trademark infringement** | Low | No registered mark on "Protocol SIFT." SANS owns SIFT-related marks, not this compound. Rob Lee has not asserted a mark. |
| **PyPI / package namespace collision** | None | Neither `protocol-sift` nor `protocol-sift-mcp` exists on PyPI. |
| **DFIR-community reputational risk** | Medium | Rob Lee is the SANS Fellow who *created* the SIFT Workstation. Submitting to a SANS hackathon (FIND EVIL!) with a name borrowed from his project, without attribution, looks bad if anyone notices — and SANS reviewers will notice. |
| **Confusion among users** | Low-Medium | The projects don't overlap functionally (his = skill installer for SIFT host; ours = MCP server for Claude Code DFIR agent). But the name plus the DFIR + Claude Code intersection invites mix-ups. |
| **Loss of the lineage signal if renamed** | n/a but worth noting | `docs/architecture.md:7` and the MCP server `__init__.py` docstring "MemoryHound Protocol SIFT MCP server" deliberately position MemoryHound as a follow-on. Renaming erases that. |

**Overall risk: LOW–MEDIUM, dominated by reputational exposure to the SANS judging panel.**

---

## 5. Decision Matrix

| Option | Pros | Cons |
|---|---|---|
| **A. Keep `protocol_sift_mcp` as-is, no changes** | Zero rework. Preserves lineage framing. PyPI slot is open. | Looks like we are trading on Rob Lee's name without acknowledging it. SANS judges may see this as poor citation hygiene — exactly the kind of "claim without evidence" the hackathon scoring rubric penalizes (per `accuracy-report` skill). |
| **B. Keep the name, add explicit attribution** (README + `mcp-server/README.md` + `__init__.py` docstring + LICENSE-style NOTICE entry) | Zero code rework. Keeps the intentional lineage signal. Reframes the name as homage / extension, not appropriation. Aligns with MemoryHound's own existing framing in `docs/architecture.md:7`. Cheapest path to closing the reputational gap. Models the "honesty wins points" discipline the `accuracy-report` skill enforces. | Requires reaching out to Rob Lee, or at minimum publicly naming him in the attribution (mild social friction). Does not eliminate the small confusion-among-users risk. |
| **C. Rename to `memoryhound_mcp` / `mh_mcp`** | Eliminates all overlap. Cleaner naming for a standalone project — the MCP server's name now matches the product (MemoryHound), which is the more discoverable brand. No dependency on Rob Lee at all. | Breaks 16+ internal doc references, 392-line README, all test imports, `mh orchestrate` CLI wiring, `mcp__protocol_sift__*` permission strings in case templates, and the architecture.md ASCII diagram. Throws away the deliberate "extension of Protocol SIFT" framing. Higher rework cost than B by an order of magnitude. PyPI release ergonomics do improve. |
| **D. Rename + keep "Inspired by Protocol SIFT" attribution** | Best of both: clean name, credit preserved. | Highest rework cost. Still requires the attribution writeup from Option B. Only worth it if we expect long-term standalone life past the hackathon. |

---

## 6. Recommendation

**Adopt Option B: Keep `protocol_sift_mcp`, add explicit attribution.**

Reasoning:

1. **The lineage framing is already in the codebase** (`docs/architecture.md:7`, `__init__.py:1`) — the cheapest move is to surface that framing prominently, not erase it.
2. **Rob Lee's repo is dormant** (last push 2026-03-25) and **unlicensed-by-default** (= all rights reserved on his files, but nothing prevents us from using a *name* he never trademarked). The legal surface is genuinely small.
3. **The SANS hackathon scoring rubric rewards honesty and citation discipline** (see `accuracy-report` skill: "Honesty wins points; inflated claims lose them"). Naming a Protocol SIFT extension "Protocol SIFT MCP" *with attribution* reads as careful sourcing; doing it *without* attribution reads as appropriation. Same code, different optics.
4. **Renaming costs are non-trivial:** ~30 files reference `protocol_sift_mcp`, including test imports, MCP permission strings (`mcp__protocol_sift__*`), case-template `settings.json` snippets, and the README's tool-count infographic. Doable but not free, and not required.
5. **Reach out to Rob Lee** (optional but recommended): a one-line email / GitHub issue saying "we built a Claude Code MCP server in your project's spirit and named it `protocol_sift_mcp` with attribution to you — wanted to flag it before hackathon submission" buys goodwill at zero cost. If he objects, we still have Option C as a fallback.

### Concrete next steps

1. Add to `/Users/x00x/Desktop/SANS/memory-hound/README.md` (top of "Acknowledgments" or a new "Attribution" section):

   > MemoryHound's MCP server is named `protocol_sift_mcp` in deliberate continuity with [**Protocol SIFT**](https://github.com/teamdfir/protocol-sift) by Rob Lee (SANS Fellow, creator of the SIFT Workstation). Rob Lee's Protocol SIFT is a Claude Code skill installer for the SANS SIFT Workstation; MemoryHound extends that direction with typed forensic primitives, an MCP server, and an autonomous LangGraph triage agent. MemoryHound is an independent project, Apache-2.0 licensed, and is not affiliated with, endorsed by, or derived from Rob Lee's repository — no code is shared. The naming is homage.

2. Add a similar paragraph to `/Users/x00x/Desktop/SANS/memory-hound/mcp-server/README.md` (if that README exists; if not, add it to the `mcp-server/src/protocol_sift_mcp/__init__.py` docstring).

3. Update `mcp-server/src/protocol_sift_mcp/__init__.py:1` from `"""MemoryHound Protocol SIFT MCP server."""` to `"""MemoryHound Protocol SIFT MCP server — named in homage to Rob Lee's Protocol SIFT (https://github.com/teamdfir/protocol-sift). Independent project, Apache-2.0."""`.

4. (Optional) Open a courtesy issue on `teamdfir/protocol-sift` titled "Heads up: extension project using the Protocol SIFT name with attribution" linking back. If Rob Lee objects, fall back to Option C with ~1 day of rename work.

5. **Do not** publish `protocol-sift-mcp` to PyPI under that exact name until step 4 has a response, OR until after 2026-06-15 (post-hackathon). For internal use and the hackathon submission, the local module name is fine.

---

## Appendix — Raw Evidence

**MemoryHound first use of `protocol_sift_mcp`:**

```
$ git log --follow --reverse --format='%h %ad %s' --date=short mcp-server/pyproject.toml | head -1
44fcd2b 2026-04-25 W1: scaffold MemoryHound — cross-OS DFIR triage agent
```

**teamdfir/protocol-sift oldest commit:**

```
$ curl -sL https://api.github.com/repos/teamdfir/protocol-sift/commits?per_page=100 | grep -E '"(date|message|sha)"' | tail
"sha": "a9c0e824ea9f8dede4a7e219c5253363ba4da545"
"date": "2026-03-24T16:29:51Z"
"message": "feat: protocol-sift"
```

**teamdfir/protocol-sift repo metadata:**

```
$ curl -sL https://api.github.com/repos/teamdfir/protocol-sift | grep -E '"(created_at|pushed_at|license|name)"'
"name": "protocol-sift"
"created_at": "2026-03-24T16:00:41Z"
"pushed_at": "2026-03-25T19:24:46Z"
"license": null
```

**teamdfir/protocol-sift LICENSE check:**

```
$ curl -sL -o /dev/null -w "%{http_code}\n" https://raw.githubusercontent.com/teamdfir/protocol-sift/main/LICENSE
404
```

**PyPI namespace check:**

```
$ curl -sL -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/protocol-sift-mcp/json
404
$ curl -sL -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/protocol-sift/json
404
```

**MemoryHound's existing lineage statement (docs/architecture.md line 7):**

```
│   Claude Code (Direct Agent Extension of Protocol SIFT)          │
```

**MemoryHound LICENSE (Apache-2.0, line 189):**

```
   Copyright 2026 MemoryHound Contributors
```
