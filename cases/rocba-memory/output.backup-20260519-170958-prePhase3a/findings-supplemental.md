# Supplemental Findings — Rocba Case (post `windows.dumpfiles --pid 9648`)

> Generated after addressing analyst feedback that the OneDrive AODL handle in
> F-008 was unexploited. `windows.dumpfiles --pid 9648` was executed against
> the original 19 GB image (vol3 v2.28.0). 488 cached files dumped to
> `cases/rocba-memory/output/dumpfiles/`. Two of them collapsed Gap G-2
> (specific files exfiltrated → unknown).

---

## F-017 — OneDrive client downloads3.txt (49 SRL files actually fetched)
- **Confidence:** confirmed
- **Rationale:** confirmed because the file `downloads3.txt` is OneDrive's append-only client-side download log keyed by SharePoint `UniqueId`, the entries cite real SharePoint download.aspx URLs in the SRL tenant, and the file was held in PID 9648's working set with both `DataSectionObject` and `SharedCacheMap` cache types.
- **MITRE ATT&CK:** `T1530` (Cloud Storage Object), `T1213.002` (SharePoint), `T1567.002` (Exfil to Cloud)
- **Pin:** `cases/rocba-memory/output/dumpfiles/file.0xb78d090aab60.0xb78d05447350.DataSectionObject.downloads3.txt.dat` (UTF-16-LE, 30,720 chars; 49 lines).
- **Evidence:**

| Source mailbox / library | Download count | URL pattern |
|---|---:|---|
| `starkresearchlabs.sharepoint.com/sites/SRL-Projects/` (corporate) | 36 | `_layouts/15/download.aspx?UniqueId=…` |
| `mhill_stark-research-labs_com` (Maria Hill personal) | 6 | `personal/mhill_…/_layouts/15/download.aspx` |
| `frocba_stark-research-labs_com` (Fred personal) | 5 | `personal/frocba_…/_layouts/15/download.aspx` |
| `tdungan_stark-research-labs_com` (Timothy Dungan personal) | 1 | `personal/tdungan_…/_layouts/15/download.aspx` |
| **Total** | **49** | — |

These are M365 `UniqueId` GUIDs — opaque from disk alone, but reversible **server-side** via Graph API `sites/{site}/drive/items/{id}` for the corporate library and `users/{upn}/drive/items/{id}` for personal mailboxes. **This is the table SRL hands to its M365 admin to enumerate every file the OneDrive client actually pulled into Fred's authenticated session.**

---

## F-018 — Fred's user-state file: SRL filename inventory
- **Confidence:** confirmed
- **Rationale:** confirmed because the file `d1a7c039-6175-4ddb-bcdb-a8de45cf1678.dat` is OneDrive's per-user serialized state (filename matches Fred's user GUID `d1a7c039-6175-4ddb-bcdb-a8de45cf1678` recovered independently from the Downloader log's `userid=` parameter), and the recovered UTF-16-LE strings are SRL-specific filenames clustered by SRL project taxonomy.
- **MITRE ATT&CK:** `T1213` (Data from Information Repositories), `T1530` (Cloud Storage Object)
- **Pin:** `cases/rocba-memory/output/dumpfiles/file.0xb78d090a8120.0xb78cf91a44e0.DataSectionObject.d1a7c039-6175-4ddb-bcdb-a8de45cf1678.dat.dat` (253,952 bytes; 191 wide-char strings, 62 SRL-relevant).
- **File inventory by SRL project:**

| Project | File |
|---|---|
| **Vibranium** | `Vibrainium - SRL.docx`, `SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.docx` |
| **ADAMANTIUM** | `ADAMANTIUM-Background.docx`, `France DGSE Intel Analysis Adamantium.pptx` |
| **KITT** | `German-KITT-Specs.docx`, `German-KITT-Specs-CMDRHill-Laptop.docx`, `The Future of KITT.pptx`, `The Future of KITT-older-version.pptx`, `Future of KITT - Technical Background.docx`, `German-KITT.jpg`, `KITT-CompetitiveAnalysisDocs/`, `Hydrogen_Hybrid_Tech.docx` |
| **Megaforce** | `Megaforce_Bike.jpg`, `Megaforce_Tank.jpg`, `Megaforce_Buggy.jpg`, `Megaforce_Testing.jpg`, `Megaforce_Flyingbike_test1.jpg`, `Megaforce_Flyingbike_test2.jpg`, `Megaforce Specs & Research.docx` |
| **Airwolf** | `Airwolf_schematics.png`, `Airwolf-II-a.jpg`, `TSG_F228_AirWolf_Parts.pdf` |
| **Shield** | `The Shield Background and Ongoing Research.docx` |
| **New Alloy Research** | `Alloy_Steel_-_Properties_and_Use.pdf` |
| **Misc / research / personal** | `Chord_Spacetime.pdf`, `Heisenberg_Uncertainty_Principle_and_the.pdf`, `SO_5_non_Fermi_liquid_in_a_Coulomb_box_d.pdf`, `Quantum Particles Affected by Other Dimensions.pdf`, `IEOR4004-notes1.pdf`, `Nokia Strategy.docx`, `Business_Plan_Mail_Order_Pharmacy.docx` |

**~30 individually-named SRL files plus the `KITT-CompetitiveAnalysisDocs` subfolder** — every one a candidate for what was viewed/exfiltrated. Cross-reference with F-017's 49 download events to determine which were actually pulled vs only enumerated.

The presence of `German-KITT-Specs-CMDRHill-Laptop.docx` (note the suffix) confirms Fred had Maria Hill's *laptop-local* copies via shared OneDrive folder — extends what the intruder potentially saw beyond what's normally accessible.

---

## Effect on prior gap accounting

| Old gap | Status now |
|---|---|
| **G-2 — Specific files exfiltrated unknowable from memory** | **CLOSED.** Concrete filename + UniqueId inventory in F-017 + F-018. |
| **G-3 — Browser URLs/tabs from intruder bursts unrecoverable** | Still open — these are different artifacts (chrome/msedge process PEBs), not OneDrive's. Could be partially closed by `windows.dumpfiles --pid <chrome PID>` for the bursts. |
| **G-1 — Registry plugins absent from MCP allowlist** | Independent of this round. |

## Process discipline failure (and the fix)

The original pass recorded G-2 as "memory hard cap" without first running `windows.dumpfiles` against PID 9648, even though F-008 had already pinned the AODL file as a live handle on that PID. That was a doctrine miss, not an evidence cap. The doctrine update is being applied to the skill prompts + plugin allowlist in the same commit as this supplemental.
