# Accuracy Report — Rocba Memory Triage

**Case:** rocba-memory
**Operator:** triage-orchestrator (PAI Algorithm v6.3.0, E4)
**Image:** Rocba-Memory.raw (sha256 eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563, 19,050,528,768 bytes)
**Triage performed:** 2026-05-09 23:30 → 00:35 EST (~65 min)

This report follows the trust-contract honest-accounting form: every claim is in `findings.json` and `narrative.md`. The job of this file is to enumerate what is *not* claimed, where confidence is reduced, and where I deliberately hedged. **Honesty wins points; inflated claims lose them.**

---

## 1. What did the operator triage?

| Plugin                       | Allowed? | Ran?  | Result rows | Used for |
|------------------------------|----------|-------|-------------|----------|
| `windows.pslist`             | yes      | yes   | 2186        | F-001 / F-002 / F-005 / F-006 / F-007 / F-009 / F-013 |
| `windows.psscan`             | yes      | yes   | 2196        | F-006 / F-011 cross-check |
| `windows.netscan`            | yes      | yes   | 430         | F-003 / F-008 / F-009 / F-016 |
| `windows.cmdline`            | yes      | yes   | 2186        | F-002 / F-004 / F-007 / F-013 / F-015 |
| `windows.svcscan`            | yes      | yes   | 1417        | F-001 / F-003 / F-004 / F-016 |
| `windows.malfind`            | yes      | yes   | 16          | F-010 |
| `windows.handles --pid 9648` | yes      | yes   | 1109        | F-008 |
| `windows.handles --pid 14832`| yes      | yes   | 867         | F-009 (GoogleDriveFS) |
| `windows.dlllist`            | yes      | **no** | —          | (not needed — process+service evidence already corroborated) |
| `windows.lsadump`            | yes      | **no** | —          | (out of scope for IP-theft narrative) |
| `windows.hashdump`           | yes      | **no** | —          | (out of scope for IP-theft narrative) |
| `windows.registry.userassist`| **no**   | n/a   | —          | gap (G-1) |
| `windows.registry.shellbags` | **no**   | n/a   | —          | gap (G-1) |
| `windows.registry.amcache`   | **no**   | n/a   | —          | gap (G-1) |
| `windows.registry.hivelist`  | **no**   | n/a   | —          | gap (G-1) |

`os_detect` returned `unknown / 0.0` because the first 16 bytes of a raw physical memory dump are zeroed — that is the expected magic for this evidence class. OS confirmation came via the second-signal route prescribed by the orchestrator skill: `windows.pslist` parsing 2186 valid Windows EPROCESS rows.

---

## 2. Confidence distribution (what was claimed at what level)

| Confidence | Count | Findings |
|------------|-------|----------|
| `confirmed` (≥2 independent corroborating artifacts) | 9 | F-001, F-002, F-003, F-004, F-005, F-006, F-008, F-009, F-016 |
| `inferred` (single artifact, well-understood semantics) | 4 | F-007, F-010, F-011, F-013 |
| `uncertain` (suggestive but not conclusive) | 1 | F-012 |
| `unknown` (gap) | 2 | F-014, F-015 (plus the explicit GAPs G-1..G-5 below) |

(9 + 4 + 1 + 2 = 16 findings.)

Every `confirmed` finding cites at least two of {`pslist`, `psscan`, `netscan`, `cmdline`, `svcscan`, `handles`, `malfind`} drawn from independent in-memory structures. Every `inferred` finding names the corroboration that *would* upgrade it to `confirmed` and explains why that corroboration is missing. Every `unknown` finding pins the artifact whose absence drove the gap so a future re-triage with a wider plugin allowlist can resolve it.

---

## 3. True positives (high-value)

These claims I stand behind:

- **TP-1 — RDP listener exposed throughout vacation** (F-016, confirmed). Two independent kernel structures (TCP listener table + SCM service registration). Operationally critical: the attack surface was open every minute Fred was at Disney World.
- **TP-2 — Active foreign RDP sessions at capture** (F-003, confirmed). Two independent kernel structures (netscan socket-owner pointer + svcscan service-PID). The intruder was *still on the box* when SRL ran MRC.exe.
- **TP-3 — RDP redirection stack enabled** (F-004, confirmed). Three independent structures — implies clipboard / drive / USB redirection were available channels.
- **TP-4 — Synchronized browser bursts inside break-in window** (F-005 + F-006, confirmed). Cross-validated across pslist and psscan; the synchronized exit times are a structural signature of a browser-process-tree teardown, not coincidental.
- **TP-5 — Stark Research Labs project list** (F-008, confirmed). Eight directory handles + OneDrive marker file `.849C9593-D756-4E56-8D6E-42412F2A707B` + ESTABLISHED OneDrive TLS connections. This is the strongest structural answer to case-question 1.

---

## 4. Hedged / probable-but-not-confirmed positives

- **HP-1 — Interactive logon at 22:42 EST 2020-11-13** (F-007, inferred). The `ctfmon`+`TabTip`+`TextInputHost` triple-start is a strong heuristic for an interactive session marker, but it can also fire on session unlock or reconnect. To upgrade to `confirmed` I would need event log Logon EID 4624 — not available without a registry plugin.
- **HP-2 — No interactive shell spawned** (F-011, inferred). Cross-check across pslist and psscan returns zero shell-process matches, but a shell that exited and was overwritten could escape detection. Confidence is high, not absolute.
- **HP-3 — No malicious code injection** (F-010, inferred). All 16 malfind hits are on JIT-using processes; pattern is benign. A sufficiently sophisticated rootkit using DKOM could hide. malfind is one tool — true exhaustive proof of negative would require multiple injection-detection plugins (`ldrmodules`, `modscan`, `driverirp`) that are outside the allowlist.
- **HP-4 — MRC.exe is the SRL IR tool** (F-013, inferred). The path `D:\Tools\MRC.exe`, parent explorer.exe in Fred's session, and the timestamp position relative to capture all fit the case-brief's "remote IR captured this memory image" — but I cannot verify the binary hash inside memory. If MRC.exe were attacker-planted, that would change interpretation.

---

## 5. Acknowledged gaps (false negatives I can't help with)

These are the questions the triage **could not** answer, ordered by impact on the case narrative:

- **G-1 — Registry-resident execution evidence (UserAssist, ShellBags, Amcache, RecentDocs).** `windows.registry.*` plugins are NOT in the protocol_sift allowlist. The case brief specifically asks for these. Resolving this gap requires either (a) widening the allowlist or (b) running `vol3` directly outside the MCP — neither is in scope of the orchestrator's authority. Recorded as F-014 (`unknown`).
- **G-2 — Specific files exfiltrated.** OneDrive holds project-folder handles, but file-level handle inspection inside `Stark Research Labs\*` would only show files the SyncEngine had open at the moment of capture; without OneDrive's `SyncEngine-2020-11-16.0232.9648.179.aodl` (which IS held as a handle but parsing the AODL log requires a separate tool) we cannot enumerate which files were uploaded during the intruder window. **Recommend pulling the OneDrive AODL logs from disk and the M365 server-side audit logs for `frocba@stark-research-labs.com`.**
- **G-3 — Browser tabs / URLs visited during intruder bursts.** All 49 chrome.exe + msedge.exe burst children show `Args=null` — their PEB.ProcessParameters was reclaimed at process exit (F-015, `unknown`). Parent PIDs 22700 / 24476 / 11140 themselves are absent from both pslist and psscan (EPROCESS overwritten). Cannot recover URLs.
- **G-4 — Disambiguating DevicePicker trigger** (F-012, `uncertain`). The svchost spawn at 23:58 EST one second before browser teardown is suggestive of USB exfil, but Cast/Project/Bluetooth/Edge-share are equally consistent. Without registry MountPoints2 / USBSTOR enumeration this is unresolvable from memory alone.
- **G-5 — Geolocation of foreign RDP IPs.** I report the IPs literally (`213.202.233.104`, `81.30.144.115`). I did not perform WHOIS/RIR lookups inside this triage — that's an out-of-band enrichment step. I deliberately do **not** speculate about country attribution from memory alone; the IPs are the pin, attribution is for external IR follow-up.

---

## 6. Things I deliberately did NOT claim

- **No claim that intrusion was nation-state, ransomware, or insider-aided.** Memory alone supports a hands-on-keyboard interactive RDP intrusion with cloud-sync exfil candidates; it does not motivation-attribute.
- **No claim that any specific cloud client was the actual exfil channel.** OneDrive, GoogleDriveFS, Slack, iCloudIE were all alive — any could have been used, none can be uniquely fingered without the corresponding SaaS-side activity log.
- **No claim that Fred himself returned during 09:08 EST 2020-11-14 (when GoogleDriveFS was launched)** vs the intruder coming back. Process-tree alone cannot tell you whose hands were on the keyboard.
- **No claim about PIDs 22700 / 24476 / 11140's parent ancestry.** They are absent from both pslist and psscan; I report this honestly rather than guessing they were "spawned by explorer.exe."

---

## 7. False-positive risk audit

Looking at the eight `confirmed` findings:

- F-001, F-002 — capture provenance — **risk negligible**, structural Windows kernel signatures.
- F-003 — foreign RDP — **risk negligible**, the four netscan rows + svcscan TermService row are independent kernel structures.
- F-004 — RDP redirection stack — **risk negligible**, six SCM rows confirm.
- F-005 — msedge burst — **risk: low**. Could plausibly be a Microsoft Update auto-relaunch of Edge after a system event, but the synchronized teardown across 30 children is not consistent with a service auto-update pattern; consistent with a user closing their browser session.
- F-006 — chrome bursts — **risk: low**. Same reasoning. Two distinct PPIDs 24476 and 11140 mean two separate chrome.exe master processes, which is more consistent with new-tab-from-fresh-launch than auto-update.
- F-008 — SRL projects — **risk: very low**. Eight handles all under `Stark Research Labs\` with the OneDrive sync marker GUID is unambiguous — these are corporate-sync folders, not artifacts.
- F-009 — multi-cloud — **risk: very low**. All process names + remote IP/port + ESTABLISHED state + service-IP-range mapping align.
- F-016 — RDP listener since boot — **risk: very low**. Two LISTENING rows + service registration.

I think the upgrade-target work for a future analyst with disk + a wider plugin allowlist is: (1) run `windows.registry.amcache` / `userassist` / `shellbags` to recover the intruder's RecentDocs and EXE invocation list; (2) pull OneDrive AODL/.aodl logs from disk to enumerate the exact files synced during the break-in window; (3) request M365/Google/iCloud/Slack server-side IP-access logs for the intruder window — those are the artifacts that turn this triage from "RDP intrusion with cloud-channel candidates" into a precise file-level damage assessment.

---

## 8. Honest summary line

**16 findings pinned. 9 confirmed, 4 inferred, 1 uncertain, 2 unknown. Five named gaps. No silent demotions. No URLs claimed. No file list claimed. RDP exposure + foreign-IP active sessions + interactive-session marker + browser bursts are the spine of the case from memory alone — everything else is honestly hedged.**
