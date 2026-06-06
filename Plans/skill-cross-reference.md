# Skill Cross-Reference: protocol-sift to MemoryHound

Date: 2026-05-19
Inputs: 5 protocol-sift skill files in `/tmp/ps-skills/`, 14 MemoryHound skills in `/Users/x00x/Desktop/SANS/memory-hound/.claude/skills/`.

**Scope note.** protocol-sift's skills are SIFT-workstation command-runbooks: they tell an analyst what binary to invoke with what flags. MemoryHound's skills are MCP-bound subagent contracts: they tell a constrained LLM what MCP tool to call, what pin to attach, and how to grade confidence. The two are not symmetric — protocol-sift is wider on *artifact coverage* and *command literacy*; MemoryHound is deeper on *trust, pin discipline, and confidence rationale*. The borrowing opportunity runs almost entirely one direction: MemoryHound can lift artifact lists, anomaly heuristics, and EID/registry-key tables.

---

## 1. Summary Table

| protocol-sift skill | Closest MH counterpart | Status | Headline |
|---|---|---|---|
| `memory-analysis.md` | `memory-forensics/SKILL.md` | **minor-borrow** | MH already has the workflow; lift the "Process Anomaly Indicators" table and the baselining concept |
| `plaso-timeline.md` | *(none — closest is `triage-orchestrator` workflow)* | **new-skill candidate** | MH has no super-timeline skill at all |
| `sleuthkit.md` | *(none — closest is `windows-triage` artifact extraction)* | **new-skill candidate** | MH has no disk-image / filesystem skill; tier-1 evidence path unspecified |
| `windows-artifacts.md` | `windows-triage/SKILL.md` | **clear-win** | MH skill is denser on registry paths; ps is denser on EIDs, ASEP red flags, and tool-output post-processing |
| `yara-hunting.md` | `threat-hunting/SKILL.md` | **clear-win** | MH `threat-hunting` is a 33-line stub; ps has full YARA syntax, IOC sweep workflow, Velociraptor pivots |

---

## 2. Per-Skill Detail

### 2.1 `memory-analysis.md` -> `memory-forensics/SKILL.md`

**Closest counterpart:** `/Users/x00x/Desktop/SANS/memory-hound/.claude/skills/memory-forensics/SKILL.md`

**Coverage delta**

| Topic | protocol-sift | MemoryHound |
|---|---|---|
| Per-OS plugin sequencing | Windows only, with renderer flags and explicit shell snippets | All three OSes (Windows/macOS/Linux), tighter but no command syntax |
| Process anomaly indicator table | **11-row table** of red flags (wrong path, wrong parent, conhost child, taskhostw sibling, RWX VAD without file backing, etc.) | Implicit in "Confirmation Patterns" — only three patterns, less catalogued |
| Hidden-process detection | `psscan` vs `pslist` `diff` recipe, plus `windows.timeliner --create-bodyfile` integration | Mentioned as a confirmation pattern but no diff recipe |
| Code-injection workflow | `windows.malfind --dump`, then VAD inspection, then `vadyarascan --yara-rules` chain | `windows.malfind` listed once, no chain |
| Memory Baseliner (`/opt/memory-baseliner/baseline.py`) | **Full workflow** — proc/drv/svc compare, `--loadbaseline`, `--savebaseline`, stacking flags | **Absent entirely.** No baseline-diff concept in MH |
| String hunting from process memory | Three-step `memmap --dump` -> `strings -a -n 8` -> `grep -Ei "(https?://...)"` pipeline | Absent |
| Error handling (symbol downloads hanging, `--offline`, ISF placement) | Explicit `--offline` fail-fast recipe | The "Symbol-Table Note" at the bottom is honest but not actionable |
| Handle-dump discipline (cloud-sync, browser, mail processes) | **Absent** — ps has no equivalent | **MH wins decisively here.** The Rocba case lesson, the high-value handle registry, and the pre-finding gate are unique to MH and arguably the single best piece of prompt engineering in either set |

**Prompt-engineering gems worth borrowing**

1. **The Process Anomaly Indicators table (lines 311-325).** Eleven concrete IOCs as a two-column lookup. This is the form MH already uses for execution-evidence confidence — extending it to memory-side process anomalies would slot in naturally next to "Confirmation Patterns".
2. **The Six-Step Analysis Methodology (lines 300-308).** Numbered playbook tied to plugins. MH's existing per-OS sequencing list is close but doesn't bind steps to a *methodology name* — naming it makes it auditable in agent transcripts.
3. **Hidden-process `diff` recipe** (lines 73-76). One-liner that turns the abstract "psscan minus pslist = hidden" rule into a runnable comparison; MH's MCP wrapper can expose this as a dedicated derived field.
4. **Baseliner concept.** The idea of comparing a suspect image against a saved JSON baseline of process/driver/service state is missing from MH. Even without adopting the binary, the *concept* (and a pin type like `locator.type=baseline_diff`) belongs in MH.

**Concrete suggestions**

- Add a `## Process Anomaly Indicators` section to `memory-forensics/SKILL.md` mirroring lines 311-325 of `memory-analysis.md` — but as MH-style claim+rationale rows rather than command outputs. Example row: `"svchost.exe parent != services.exe" -> claim="possible process hollowing" -> required corroboration="dlllist + malfind + handles"`.
- Add an explicit `## Hidden Process Detection` subsection under Windows sequencing, naming the `psscan minus pslist` rule and giving the confidence verdict (`confirmed` if the delta is non-empty AND the missing PID has a recoverable EPROCESS object).
- Add a `## Baseline Diff (future Sub-Plan)` placeholder section noting that comparison against a saved process/driver baseline would upgrade `inferred` findings to `confirmed`. Don't ship the workflow yet — just flag the gap so the schema can grow a `baseline_diff` pin locator type.

---

### 2.2 `plaso-timeline.md` -> *(no MemoryHound counterpart)*

**Closest counterpart:** None. The phrase "timeline" appears in MH only in three contexts: `windows.timeliner` Volatility plugin (memory-forensics line 22), "Win10 Timeline" the `ActivitiesCache.db` artifact (windows-triage line 20), and "Attack Timeline" in `exec-report` (a Mermaid kill-chain rendering, not a super-timeline).

**Coverage delta**

MH has **no super-timeline capability**. There is no skill describing:
- Ingesting a disk image / mounted filesystem into a unified event stream
- The bodyfile -> mactime -> timeline pipeline
- Multi-source merge (disk + memory bodyfile + EVTX into one chronological export)
- Date/parser/keyword filtering of a timeline
- The `--slice <datetime>` pivot-around-a-known-timestamp pattern

This is a real gap. The MH `triage-orchestrator` LangGraph topology has a `kill_chain` node and an `analyze` node, but neither sits on top of a super-timeline data structure — they're driven by individual pinned findings.

**Prompt-engineering gems worth borrowing**

1. **Parser preset table (lines 60-69)** — `win10` / `win7` / `win_gen` / `linux` / `webhist` / `android`. The presets are a clean OS-routing primitive; MH's `os_detect` could feed parser-preset selection.
2. **The "post-ingest validation" rule (line 133)** — *"Always run `pinfo.py` after `log2timeline.py` to confirm parser hit counts. Zero hits from expected parsers indicates wrong parser set or a mount problem."* This is the verifier pattern MH already enforces elsewhere; restating it for timeline ingest is exactly the kind of self-correction loop that fits MH's audit log.
3. **`--slice` semantic** (lines 178-183) — "events within 5 min of this timestamp" is a *pivot primitive*. MH's `threat-hunting` skill talks about pivoting via ATT&CK/Diamond/Kill-Chain but has no temporal pivot. A `timeline_slice(timestamp, window)` MCP tool with this semantic would be a high-leverage primitive.
4. **The merge invariant** (lines 187-198) — that `psort.py` accepts multiple `.plaso` files is a clean cross-evidence-source join. MH today merges evidence by emitting parallel findings; a true timeline merge would let the verifier pass detect temporal contradictions.

**Concrete suggestions**

- **New skill candidate: `timeline-synthesis/SKILL.md`.** Scope: take pinned findings + raw artifact rows and produce a unified, chronologically-sorted event stream. Define a `TimelineEvent` schema (`timestamp_utc`, `source_artifact`, `actor`, `action`, `pin_id`). The skill's job is to materialize this in `/output/timeline.csv` and enforce that every row carries a pin_id back to the original finding.
- Until that skill exists, add a `## Temporal Pivoting` section to `threat-hunting/SKILL.md` describing the `+/- 5 minute slice` pivot as a fourth pivot mode (alongside MITRE / Diamond / Kill-Chain).
- Add `--slice` style time-window querying to whatever future MCP tool surfaces timeline data. Pin format: `locator.type=time_window`, `locator.value="2023-01-25 14:52:00 +/-5m"`.

---

### 2.3 `sleuthkit.md` -> *(no MemoryHound counterpart)*

**Closest counterpart:** Partial overlap with `windows-triage/SKILL.md` section "Investigation Order" (it names registry hives, EVTX, prefetch — but assumes those have already been extracted from the image).

**Coverage delta**

MH has **no disk-image / filesystem skill**. There is no MH guidance on:
- E01 verification (`ewfinfo` / `ewfverify`) before analysis — evidence-integrity gate
- Read-only mounting (`ewfmount`, `mount -o ro,loop,norecovery,offset=`)
- Partition / sector-size discovery (`mmls`, `img_stat`, 4K-sector trap)
- Filesystem navigation (`fls -r -p -m`) and inode-level extraction (`icat`, `istat`, `ffind`)
- Bulk recovery (`tsk_recover -e`) including deleted/unallocated content
- Carving (`bulk_extractor`, `photorec`)
- The bodyfile / mactime pipeline
- VSS (Volume Shadow Copy) access via TSK

The `windows-triage` skill assumes the artifacts (`exports/registry/`, `exports/evtx/`, etc.) are *already on disk* — but says nothing about how they got there. In a real case this is a real gap: pin integrity starts at "did the analyst mount read-only?"

**Prompt-engineering gems worth borrowing**

1. **The verify-image-before-analysis rule (lines 36-49).** `ewfverify must complete without errors before any analysis proceeds.` This is a pre-pin integrity rule. MH already enforces `verify_excerpt` server-side after extraction — the missing piece is image-hash verification before extraction even begins. This belongs in `evidence-pin/SKILL.md` as a `pre_extraction_check`.
2. **The sector-size trap (lines 67-76).** *"`img_stat` before `mmls` catches 4K sector drives — wrong sector size = wrong byte offset."* This is exactly the kind of failure mode that produces silently-wrong pins, because the offset will still parse but will point at the wrong bytes. MH's anti-hallucination rules don't cover this class of error.
3. **The `norecovery` mount option** (line 110). *"norecovery mount option prevents NTFS journal replay that could alter analysis."* This is an evidence-integrity invariant; without it, the act of analysis changes the artifact.
4. **The artifact-extraction recipe block (lines 264-318)** — concrete `find` / `cp` invocations for every Windows artifact MH already names in `windows-triage` (EVTX, all four config hives, NTUSER per user, UsrClass per user, Prefetch, MFT, UsnJrnl, Amcache, SRUM, browser, Recycle Bin, Tasks, PowerShell transcripts). This is a checklist MH currently doesn't have.
5. **`icat` over `cp` for extraction** (line 406). Bypasses OS file locking and VSS visibility — preserves evidence the way the filesystem actually sees it.

**Concrete suggestions**

- **New skill candidate: `disk-image-handling/SKILL.md`.** Scope: define the evidence-integrity prelude every other skill assumes. Mandatory checks: `ewfverify` pass, read-only mount, sector size confirmed, hash recorded in audit log. Output: a manifest at `/output/image_manifest.json` with image hashes, partition table, mount offsets, sector size. This becomes a precondition for any `windows-triage` / `linux-triage` / `macos-triage` run.
- Add an `## Image Verification Gate` section to `evidence-pin/SKILL.md` requiring that pins sourced from a disk image cite the image manifest entry (so a `verify_excerpt` failure can be traced back to a hash mismatch on the image itself, not just on the extracted byte range).
- Add to `windows-triage/SKILL.md` a small `## Required Extractions` checklist (the artifact list from `sleuthkit.md` lines 264-318) so the orchestrator can detect "this case is missing UsnJrnl" before findings are emitted.

---

### 2.4 `windows-artifacts.md` -> `windows-triage/SKILL.md`

**Closest counterpart:** `/Users/x00x/Desktop/SANS/memory-hound/.claude/skills/windows-triage/SKILL.md`

**Coverage delta**

| Topic | protocol-sift | MemoryHound |
|---|---|---|
| Registry artifact paths | Compact table of 14 key locations | **Richer.** MH lists explicit hive + sub-tree per artifact and gives ROT-13 / ESE-table-id internals (e.g. `{973F5D5C}` SRUM Network table) |
| Execution evidence | Prefetch / Shimcache / Amcache / BAM as separate sections with EZ-tool flags | Same set + Win10 Timeline (`ActivitiesCache.db`) — **MH is one artifact ahead** |
| EVTX coverage | **~75 EIDs across 8 log channels** with descriptions (Security, PowerShell, RDP, Defender, System, Tasks, WMI) | **Smaller subset** — covers Security EIDs (logon/auth/account/process/object) but misses PowerShell 4103/4104, RDP 1149, Defender 1116-5001, WMI 5860/5861, Scheduled-Task 106/129/200/201 |
| Confidence rule for execution | Implicit | **Explicit and MH-original**: 2 or more of [Prefetch, BAM, UserAssist, SRUM, Win10 Timeline] = `confirmed`. This is exactly the right shape and ps doesn't have it |
| ASEP (autoruns) analysis | **Strong section** — CLI post-processing of Autorunsc CSV, Timeline Explorer filtering workflow, driver baseline against VanillaWindowsReference, **6 red-flag examples** | **Absent entirely** — MH has no autoruns / ASEP discussion |
| USB artifact chain | Full chain: USBSTOR + USB + MountedDevices + MountPoints2 + Volume GUID | Present + adds Win10 Partition/Diagnostic EID 1006 — **MH is one artifact ahead** |
| Cloud connector artifacts | Mentions browser profiles only | **MH wins decisively** — OneDrive AODL, Drive FS protobuf, Box streemsfs.db, Dropbox nucleus.sqlite3 with full paths |
| Shellbags | Two hives (NTUSER + UsrClass), SBECmd `--dedupe` and `--tz UTC` | Same coverage, less command syntax |
| Recycle Bin / Thumbcache / Windows.edb | Recycle Bin only | **MH wins** — adds Thumbcache and Windows.edb |

**Prompt-engineering gems worth borrowing**

1. **The EVTX EID matrix (lines 566-659).** Eight subtables — Logon, Account/Privilege, Process, Object Access, PowerShell Operational, Windows PowerShell, RDP, Defender, System, Scheduled Tasks, WMI. MH's `windows-triage` EID list under "Account / Authentication Activity" stops at the Security log. Importing the missing channels — especially **PowerShell 4104 (script block logging, "highest value"), WMI 5861 (permanent subscription = persistence), Defender 5001 (real-time protection disabled), Service 7045 (new service installed)** — would close real detection gaps.
2. **The ASEP red-flag list (lines 492-498).** Six concrete patterns: typosquatted exe in `C:\Windows\`, unsigned service/driver, driver absent from VanillaWindowsReference baseline, "File not found" in image path, task running from `%TEMP%` or `%APPDATA%`, WMI subscription absent from baseline. This is exactly MH's preferred form — claim + corroboration recipe.
3. **The VanillaWindowsReference baseline pattern** (lines 484-490). External known-good list as the corroboration source for "anomalous driver" findings. MH has no concept of a baseline; this is the smallest path to introducing one.
4. **"Shimcache file absent from filesystem = deleted malware" rule** (line 716). One-liner heuristic that ties two artifacts together with a specific verdict.
5. **"UsnJrnl is the best source for file system activity after an event — predates Prefetch"** (line 720). Tiebreaker / source-ranking heuristic. MH's tier-1/tier-2/tier-3 system is already this kind of pattern; extending it to *within* tier-2 with these ranking rules is a natural next step.

**Concrete suggestions**

- **Expand the EVTX section of `windows-triage/SKILL.md`** with the missing channels. Specifically add EIDs: `4103/4104/400/600/800` (PowerShell), `1149/4778/4779` (RDP), `1116/1117/1118/1119/5001` (Defender), `7034/7035/7036/7040/7045` (Service control), `106/129/200/201` (Scheduled tasks), `5857/5858/5860/5861` (WMI). Flag 4104 and 5861 as `confirmed`-class single-source artifacts (script content / permanent persistence) — the rest are corroborators.
- **Add an `### 9. Autoruns / ASEP` section to `windows-triage/SKILL.md`**, mirroring the ps red-flag list. Form: claim row + required pin sources. Tie to a future `win_autorun_parse` MCP tool.
- **Add "VanillaWindowsReference baseline" as a baseline-diff source.** Define a pin locator type `locator.type=baseline_absent` with `value="driver_name@windows_build"`. This generalizes — a Linux equivalent could reference distro package fingerprints.
- **Promote the "Shimcache without filesystem entry = deleted malware" pattern** to MH's confirmation rules. It's a two-pin rule (Shimcache present + filesystem absent) that produces a strong claim; add it as an example under `## Confirmation Patterns`.

---

### 2.5 `yara-hunting.md` -> `threat-hunting/SKILL.md`

**Closest counterpart:** `/Users/x00x/Desktop/SANS/memory-hound/.claude/skills/threat-hunting/SKILL.md`

**Coverage delta**

This is the most lopsided pairing.

- **MH's `threat-hunting/SKILL.md` is 33 lines** and is explicitly marked as a "Skeleton stub (Sub-Plan 03). Full Diamond traversal + pivot heuristics in Sub-Plan 04."
- **ps `yara-hunting.md` is 339 lines** and covers full YARA syntax with PE/math/hash modules, condition-ordering performance rules, IOC sweep workflow, false-positive testing, community ruleset locations, and a Velociraptor VQL hunt reference.

What MH has that ps doesn't:
- Diamond Model / MITRE ATT&CK / Kill-Chain pivot framing (the entire conceptual layer)
- The "confidence NEVER `confirmed` from hunt alone" rule
- Tie-back to `_findings` state and `finding_record` MCP pin enforcement

What ps has that MH doesn't:
- Any actual YARA rule structure / module usage
- IOC sweep workflow (8 steps from build -> test -> scan -> cross-reference -> export)
- Performance ordering (`uint16(0) == 0x5A4D` first, `math.entropy` last)
- Compiled-rule caching with `yarac`
- Velociraptor hunt deployment via web console + VQL
- Community ruleset sources (Neo23x0/signature-base, Elastic protections-artifacts)

**Prompt-engineering gems worth borrowing**

1. **The IOC sweep workflow (lines 228-237).** Eight numbered steps — build IOC list -> write rules -> test for FP -> scan evidence -> scan memory -> scan extracted files -> cross-reference timeline -> export findings. This is exactly the form MH's `threat-hunting` skill should take.
2. **Condition-ordering rule (lines 207-216).** *"Put cheap, specific checks FIRST."* This generalizes far beyond YARA — it's the right ordering rule for any pin-validation pipeline. Belongs in the MCP server's tool implementation, not just docs.
3. **False-positive testing methodology (lines 239-249).** Test rules against `/usr/bin/` and similar known-good directories before sweeping evidence. MH should require this for any hunt rule the agent generates.
4. **Velociraptor VQL examples (lines 322-339).** *"Find processes with no parent"*, *"Find network connections to non-private IPs"*, *"Hunt for scheduled tasks with suspicious paths"* — three concrete queries that map directly onto MH's existing memory-forensics confirmation patterns. The query semantics could become MCP-tool-level helpers.
5. **The `Windows.Detection.Yara.*` artifact family** (lines 304-308). Three deployment surfaces — Process memory, File on disk, Raw NTFS — that should be three different MH pin locators if YARA hunting is ever wired in.

**Concrete suggestions**

- **Rewrite `threat-hunting/SKILL.md`** from a 33-line stub to a fuller workflow. Keep the Diamond / ATT&CK / Kill-Chain pivot framing (MH's unique value), but add a `## IOC Sweep Workflow` section mirroring ps lines 228-237 — with each step bound to an MCP tool (build IOC list -> `ioc_list_build`, scan -> `yara_scan`, etc.). Add `## False-Positive Testing` as a precondition.
- **Add a `yara_scan` MCP tool surface** (or document its absence). The skill currently has no path to actually running a hunt — it describes pivoting via abstract framework graphs. A `yara_scan(target, rules_path, mode={file|process_memory|ntfs_raw})` primitive with three pin types (`file_offset`, `memory_vad`, `ntfs_extent`) closes the loop.
- **Add condition-ordering as an MCP-tool implementation rule.** The "cheap checks first" pattern belongs in the YARA-scan tool implementation. Document it in the skill so the agent knows it's there.
- **Move the Velociraptor VQL pivot queries into MH's hunt-pivot library**, even if not actually deployed. They're literal codifications of "process orphan", "non-private external connection", "scheduled task with suspicious binary path" — all three are MH-pin-compatible findings.

---

## 3. Top 5 Concrete Edits to Apply (Ranked by Leverage)

| Rank | Edit | File | Effort | Leverage |
|---|---|---|---|---|
| 1 | **Rewrite `threat-hunting/SKILL.md`** from 33-line stub to full IOC-sweep workflow with FP testing, condition-ordering, three YARA scan surfaces (file / process memory / NTFS raw), and Velociraptor-style pivot queries (orphan process, non-private external, suspicious scheduled-task path). Keep MH's Diamond/ATT&CK/Kill-Chain layer on top. | `.claude/skills/threat-hunting/SKILL.md` | Medium (~150-line rewrite) | **Highest.** The skill is a known stub blocking Sub-Plan 04. ps provides 90% of the missing content as ideas to lift. |
| 2 | **Expand the EVTX section** of `windows-triage/SKILL.md` with PowerShell (4103/4104), WMI (5860/5861), Defender (1116-5001), Service (7034-7045), Scheduled-Task (106-201), RDP (1149/4778/4779) channels. Mark 4104 and 5861 as `confirmed`-class single-source artifacts; the rest as corroborators. | `.claude/skills/windows-triage/SKILL.md` (after line 26, the existing Security-EID list) | Low (table extension) | **High.** Closes real detection gaps — PowerShell script-block content (4104) and WMI permanent subscriptions (5861) are persistence/RCE evidence MH currently can't claim. |
| 3 | **Add a Process Anomaly Indicators table** to `memory-forensics/SKILL.md` (after current "Confirmation Patterns"), mirroring ps's 11-row red-flag matrix but rewritten as MH claim+rationale rows: wrong path, wrong parent, RWX VAD without file backing, SeDebugPrivilege in unexpected process, orphan PPID, conhost child (hands-on-keyboard), unsigned kernel module in modscan minus modules. | `.claude/skills/memory-forensics/SKILL.md` | Low | **High.** Gives the orchestrator a concrete set of claims the memory subagent can emit and that the Verifier can independently re-check. Today these patterns are implicit. |
| 4 | **Add `### 9. Autoruns / ASEP` section** to `windows-triage/SKILL.md` with ps's six red-flag patterns (typosquatted `C:\Windows\` exe, unsigned service/driver, driver absent from VanillaWindowsReference baseline, "File not found" image path, `%TEMP%` / `%APPDATA%` scheduled task, WMI subscription absent from baseline). Introduce `locator.type=baseline_absent` pin format. | `.claude/skills/windows-triage/SKILL.md` | Low | **Medium-high.** ASEP coverage is a hole in MH today and Autoruns CSVs are common Velociraptor / live-response output. Introducing the baseline-absent pin type unlocks driver/service/WMI persistence claims. |
| 5 | **Promote two single-rule heuristics** to MH's confirmation rules: (a) `Shimcache present + filesystem absent = deleted malware (inferred)`, and (b) `psscan minus pslist non-empty + EPROCESS recoverable = hidden process (confirmed)`. Both go in their respective skills' `## Confirmation Patterns` sections with explicit two-pin requirements. | `.claude/skills/windows-triage/SKILL.md`, `.claude/skills/memory-forensics/SKILL.md` | Trivial | **Medium.** Tiny edits, large clarity gains. Today the agent has to derive these from context; with the rule explicit, the Verifier can grade them deterministically. |

---

## 4. New-Skill Candidates (Coverage Holes)

Two protocol-sift skills have **no MemoryHound analog** and represent real gaps in MH's tool surface, not just thin documentation:

### 4.1 `timeline-synthesis` (new skill)

**Why.** MH today emits findings as parallel artifacts. There is no unified chronological event stream, no temporal pivot primitive (`+/-5min slice`), no merge of disk + memory + EVTX into one sortable view. The `triage-orchestrator` LangGraph has an `analyze` node but no timeline data structure underneath it. This is the single most useful piece of context an investigator-facing report could carry, and `ir-narrative` is currently building it ad-hoc from `_findings` order.

**Scope.** Take pinned findings (and optionally raw artifact rows) and produce `/output/timeline.csv` with schema `(timestamp_utc, source_artifact, actor, action, finding_id, pin_id)`. Every row pin-traceable back to original evidence. Add an MCP tool `timeline_slice(timestamp, window_minutes)` returning all events in window — the `--slice` pivot primitive.

**Source patterns to lift from ps `plaso-timeline.md`:** parser-preset routing (lines 60-69), post-ingest hit-count validation (line 133), the `--slice` semantic (lines 178-183), multi-source merge invariant (lines 187-198).

### 4.2 `disk-image-handling` (new skill)

**Why.** Every existing MH triage skill assumes the artifacts are *already extracted* to a working directory. There is no MH guidance on E01 verification, read-only mounting, sector-size discovery, the 4K-sector trap, the `norecovery` NTFS invariant, or `icat`-over-`cp` for evidence-preserving extraction. This is a real pre-pin integrity gap — a hash-mismatched image produces silently-wrong pins that `verify_excerpt` cannot catch (the bytes match what was extracted; what was extracted was wrong).

**Scope.** Run pre-analysis checks on every disk image: `ewfverify` pass, hashes recorded, partition table parsed, sector size confirmed, mount offset computed, read-only mount established. Emit `/output/image_manifest.json` that every downstream pin can reference via `locator.type=image_manifest`. This becomes a precondition for `windows-triage` / `linux-triage` / `macos-triage` runs against disk evidence (memory-only cases skip it).

**Source patterns to lift from ps `sleuthkit.md`:** the verify-before-analysis rule (lines 36-49), sector-size trap (67-76), `norecovery` mount option (line 110), the artifact-extraction checklist (264-318), `icat`-over-`cp` invariant (line 406), VSS handling note (line 408).

---

## 5. Honesty Notes

- **protocol-sift's skills are shallower on trust architecture.** They have no pin format, no confidence enum, no verifier discipline, no MCP sandbox constraint. They assume a human analyst is reading the output. MH's pin schema, `confidence_rationale` field, handle-dump pre-finding gate (`memory-forensics` line 23, `triage-orchestrator` lines 54-66), and tier-1/2/3 routing (`triage-orchestrator` lines 68-78) are all original to MH and have no protocol-sift equivalent. **Do not regress these by importing ps's looser style.**
- **protocol-sift wins on artifact-coverage breadth, not on schema or correctness rigor.** The EID matrix, the EZ-tool flag tables, the Autoruns red-flag list, and the YARA module reference are all wider catalogues than MH currently carries. They are catalogues, not arguments — lift the contents, not the framing.
- **Licensing / attribution.** Per the brief, lift ideas and structure, not text. The EID tables and registry-path lists in particular are factual (Microsoft documents these EIDs identically), so paraphrasing into MH-style claim+rationale rows is straightforward and clean.
- **Don't add the SIFT-specific paths.** ps repeatedly references `/opt/zimmermantools/`, `/opt/volatility3-2.20.0/`, `/opt/memory-baseliner/`. MH runs MCP-bound, not shell-bound — these paths shouldn't enter MH's skill files. Lift the *artifact knowledge* (what `AppCompatCacheParser.dll` parses, not how to invoke it) into MH-form.

---

## 6. Final Numbers

- **5 concrete edits** proposed (Section 3), ranked by leverage.
- **2 new-skill candidates** flagged (Section 4): `timeline-synthesis` and `disk-image-handling`.
- **Top recommendation:** rewrite `threat-hunting/SKILL.md` from its current 33-line stub to a full IOC-sweep workflow. It's the largest known gap in MH's skill set (already marked as a Sub-Plan 03 stub), and ps's `yara-hunting.md` provides the highest-density borrowable content — IOC-sweep workflow steps, condition-ordering, FP testing methodology, three YARA scan surfaces, and Velociraptor pivot queries that map directly onto MH-pin-compatible findings.
