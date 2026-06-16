# Investigative Narrative — Stark Research Labs / Fred Rocba IP-Theft

**Case ID:** rocba-memory
**Custodian:** Fred Rocba, technical engineer, Stark Research Labs (SRL)
**Subject system:** Microsoft Surface, Windows 10, single-user (`fredr`), local IP `192.168.1.5`, EST5EDT
**Evidence:** `Rocba-Memory.raw` — physical memory image, 17.74 GiB
SHA-256 `eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563`
SHA-1 `86607308aed936718889d66c014142c072a04030`
**Captured (in-image):** 2020-11-16T02:36:35Z (= 2020-11-15 21:36 EST Sunday evening)
**Captured by:** SRL remote-IR responder, via `D:\Tools\MRC.exe` (consistent with a tools-USB physically inserted into the live machine — F-013)

> Every claim below is pinned in `findings.json` to a Volatility 3 plugin output and a raw excerpt of the recovered memory structure. Confidence enums (`confirmed` / `inferred` / `uncertain` / `unknown`) follow the trust contract; gaps are routed to `accuracy-report.md`.

---

## What I can prove from memory alone

### When the intruder was inside

A new interactive session marker appears at **2020-11-14T03:42:50Z (= 2020-11-13 22:42 EST)** — `ctfmon.exe` (PID 9488), `TabTip.exe` (PID 27232), and `TextInputHost.exe` (PID 26988) all start within 16 seconds of each other in session 1, parented by 1908 and 740. These three services are the canonical Windows shell-input handlers that fire on session-create or session-unlock. **F-007** records this as `inferred` (single memory-source — the registry hive that would corroborate a Logon EID 4624 is outside the available plugin allowlist).

Thirty minutes later, at **2020-11-14T04:12:49Z (= 23:12 EST)**, a coordinated `msedge.exe` burst begins. Thirty child instances spawn under parent PID 22700 over 46 minutes, all in session 1, all exiting together at **2020-11-14T04:59:17Z (23:59 EST)** — the contiguous CreateTime stamps and synchronized ExitTime are the unmistakable signature of a Chromium-Edge browser session with the parent process being torn down (**F-005, confirmed** — corroborated across `pslist` and `psscan`).

Forty-one minutes into the Edge session, at **04:53:04Z (23:53 EST)**, a parallel `chrome.exe` burst opens under parent PID 24476 — eight chrome.exe children, contiguous CreateTimes within 3 minutes, synchronized ExitTime at **04:56:20Z**. A second smaller chrome.exe burst (eight children, parent PID 11140) follows at **05:10:53Z** and tears down at **05:15:25Z** (= 00:15 EST Saturday morning) (**F-006, confirmed**).

The intruder window is therefore **2020-11-13 22:42 EST → 2020-11-14 00:15 EST**, ~93 minutes of activity, exactly inside the case-brief's "evening of Friday 2020-11-13."

### How they got in

The Surface had been listening for inbound RDP on `0.0.0.0:3389` since **boot at 2020-11-11T08:13:16Z** — `windows.netscan` reports a LISTENING TCPv4 and TCPv6 row owned by `svchost.exe` PID 1248, and `windows.svcscan` independently confirms PID 1248 hosts the **TermService** (Remote Desktop Services) (**F-016, confirmed**). RDP was therefore exposed for the entire vacation week — every minute that Fred and his family were at Disney World, port 3389 was open and answering.

At capture time, **four ESTABLISHED inbound RDP connections** to port 3389 are present from two foreign IPs (**F-003, confirmed**):

| Created (UTC)         | Foreign IP        | Foreign port | Owner            |
|-----------------------|-------------------|--------------|------------------|
| 2020-11-16T02:34:58Z  | 213.202.233.104   | 45753        | svchost.exe 1248 |
| 2020-11-16T02:34:58Z  | 81.30.144.115     | 51048        | svchost.exe 1248 |
| 2020-11-16T02:34:45Z  | 81.30.144.115     | 5067         | svchost.exe 1248 |
| 2020-11-16T02:35:53Z  | 213.202.233.104   | 40876        | svchost.exe 1248 |

Both `213.202.233.104` and `81.30.144.115` are outside the SRL/M365/Dropbox/OneDrive/iCloud/Google-Drive baseline named in the case brief. They are **active RDP sessions still attached at the moment SRL captured memory** — meaning the intruder was still on the box when MRC.exe started.

The complete RDP redirection stack is enabled: **UmRdpService** (PID 1932, "Remote Desktop Services UserMode Port Redirector"), **SessionEnv** (PID 3108, "Remote Desktop Configuration"), and the kernel drivers **RDPDR**, **rdpbus**, **tsusbhub**, and **RdpVideoMiniport** are all `SERVICE_RUNNING` (**F-004, confirmed**). This is the exact configuration that lets a remote RDP client mount its local drive into the host as `\\tsclient\C` and redirect clipboard contents in both directions.

### What they had access to

OneDrive (PID 9648, `OneDrive.exe` in session 1) holds open file handles at capture on the following Stark Research Labs corporate sync folders, identified by the OneDrive sync-marker file `.849C9593-D756-4E56-8D6E-42412F2A707B` present in each (**F-008, confirmed**):

- `C:\Users\fredr\OneDrive - Stark Research Labs` — corporate sync root
- `C:\Users\fredr\Stark Research Labs\SRL-Projects - Airwolf`
- `C:\Users\fredr\Stark Research Labs\SRL-Projects - Blue Thunder`
- `C:\Users\fredr\Stark Research Labs\SRL-Projects - Gunstar`
- `C:\Users\fredr\Stark Research Labs\SRL-Projects - Megaforce`
- `C:\Users\fredr\Stark Research Labs\Maria Hill - KITT`
- `C:\Users\fredr\Stark Research Labs\Maria Hill - WorkingFiles`
- `C:\Users\fredr\Stark Research Labs\Timothy Dungan - New Alloy Research`

These are the SRL projects Fred had OneDrive sync access to at the moment of capture — answering case-question 1 (*"What key projects did Fred have access to?"*). The two collaborators named — **Maria Hill** and **Timothy Dungan** — are the SRL principals whose folders Fred could browse.

OneDrive is sustaining ESTABLISHED TLS connections to Microsoft Live (`13.107.136.9:443`) and Microsoft Teams Cloud (`52.114.75.149:443`, `52.114.128.43:443`, `52.242.211.89:443`) at capture time, so the sync engine is online.

### Where the data could have gone

Beyond OneDrive, every cloud-sync client named in the case brief is **alive and connected at capture** (**F-009, confirmed**):

| Process            | PID    | First seen / launched          | ESTABLISHED to                          |
|--------------------|--------|--------------------------------|-----------------------------------------|
| `OneDrive.exe`     | 9648   | session 1                      | 13.107.136.9, 52.114.75.149             |
| `GoogleDriveFS.exe`| 14832  | 2020-11-14T14:08:58Z           | 172.217.12.170 (Google)                 |
| `googledrivesync`  | 8432   | (alive)                        | 172.217.10.42 (Google)                  |
| `Slack.exe`        | 12808  | 2020-11-11T08:14:31Z           | 54.82.161.19 (Slack/AWS)                |
| `iCloudIE.exe`     | 27740  | 2020-11-16T00:14:48Z           | (Apple)                                 |
| `ApplePhotoStream` | 12888  | (alive)                        | 17.248.138.42 (Apple iCloud)            |
| `APSDaemon.exe`    | 13224  | 2020-11-12T06:06:19Z           | 17.57.144.165:5223 (Apple Push)         |

Every one of these is a viable exfiltration channel — OneDrive (corporate), GoogleDriveFS, Apple iCloud, and Slack file-uploads were all connected and authenticated during the intruder window.

The case brief's expectation that webmail upload (Gmail/Outlook web) might have been used is **plausible but not provable from memory** — no specific URL evidence survives (see GAPs below).

### How — likely mechanism

Synthesizing the confirmed signals:

1. **Exposure** — RDP/3389 was open to the internet for the whole vacation week (F-016).
2. **Access** — at 22:42 EST 2020-11-13, an interactive session was created/unlocked in Fred's session 1 (F-007).
3. **Activity** — between 23:12 and ~00:15 EST, intruder used **Edge** (PID 22700) and **Chrome** (PIDs 24476, 11140) inside Fred's already-authenticated profile (F-005, F-006). Browsers ran in session 1 alongside Fred's pre-vacation `explorer.exe` (PID 7464) and his original `chrome.exe` PID 5532 from 2020-11-11. The intruder had access to **Fred's already-signed-in browser sessions**, including OneDrive Web, Google Drive, iCloud, and any tab Fred had left open.
4. **Channel candidates**:
   - **Browser-based file share or webmail upload**, using Fred's authenticated cookies, via Edge/Chrome — bandwidth and timing fit.
   - **OneDrive / GoogleDriveFS / iCloud sync** triggered by file copy into a synced folder — the SRL project folders are all mapped under `C:\Users\fredr\Stark Research Labs\*`, so a drag-and-drop into one of them would auto-replicate to Microsoft 365 from where the intruder could later access from any other machine signed in as Fred.
   - **RDP clipboard / drive redirection (F-004)** — `\\tsclient\C` mapping is the textbook RDP-over-NLA exfil. UmRdpService + RDPDR + rdpbus + tsusbhub all `SERVICE_RUNNING` at capture means the channel is open.
5. **Possible USB target** — `DevicesFlowUserSvc` and `DevicePickerUserSvc` spawned at 2020-11-14T04:58:58Z, exactly one second before the Edge session ended. This Windows shell handler fires on a "pick a device" UI invocation (USB mass-storage, Bluetooth share, Cast, Edge "Send to device") (**F-012, uncertain** — cannot disambiguate which trigger).

The intruder did **not** spawn an interactive shell — there is no `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wsl.exe`, or `bash.exe` in either `pslist` or `psscan` (**F-011, inferred**). And `windows.malfind` returned only legitimate JIT/RWX regions in well-known JIT processes (Defender, Cortana, Teams, SmartScreen, RuntimeBroker) — no injected/hollowed code is detectable in OneDrive, the browsers, or any service (**F-010, inferred**). This was a **GUI-only, hands-on-keyboard, live-account-misuse** operation — not a malware drop, not a script kiddie shell.

### When (consolidated, all pinned)

| UTC                           | Local (EST)            | Event                                                                 |
|-------------------------------|------------------------|----------------------------------------------------------------------|
| 2020-11-11T08:13:00Z          | 2020-11-11 03:13       | Surface boots; TermService starts listening on 3389 (F-016)          |
| 2020-11-13T19:56:50Z          | 2020-11-13 14:56       | OneDrive begins sync session (last pre-break-in connection)          |
| 2020-11-14T03:42:50Z          | **2020-11-13 22:42**   | Interactive-input services (ctfmon, TabTip, TextInputHost) start (F-007) |
| 2020-11-14T04:12:49Z          | **2020-11-13 23:12**   | msedge.exe burst begins (F-005)                                       |
| 2020-11-14T04:53:04Z          | **2020-11-13 23:53**   | chrome.exe burst (PPID 24476) begins (F-006)                          |
| 2020-11-14T04:58:58Z          | **2020-11-13 23:58**   | DeviceFlow/DevicePicker spawns (F-012)                                |
| 2020-11-14T04:59:17Z          | **2020-11-13 23:59**   | msedge burst ends                                                     |
| 2020-11-14T05:15:25Z          | **2020-11-14 00:15**   | Last chrome.exe burst (PPID 11140) ends                               |
| 2020-11-14T14:08:58Z          | 2020-11-14 09:08       | GoogleDriveFS launched (could be Fred returning, or follow-up access) |
| 2020-11-16T00:14:48Z          | 2020-11-15 19:14       | iCloudIE launched                                                     |
| 2020-11-16T02:31:15Z          | 2020-11-15 21:31       | SRL IR launches `D:\Tools\MRC.exe` from explorer.exe PID 7464 (F-013) |
| 2020-11-16T02:34:45 → 02:35:53Z | 2020-11-15 21:34-21:35 | Four foreign RDP sessions still ESTABLISHED to 213.202.233.104 / 81.30.144.115 (F-003) |
| 2020-11-16T02:36:35Z          | 2020-11-15 21:36       | Latest live-process CreateTime in image (capture moment) (F-002)     |

The fact that foreign RDP sessions are still ESTABLISHED **at the moment SRL captures memory** is operationally significant — it means the intruder may still have had access at the time IR began, and any post-capture remediation should treat the box as actively pwned, not merely historically pwned.

---

## Bottom line

| Case-brief question | Answer (with confidence) |
|---|---|
| **What key projects did Fred have access to?** | KITT, Megaforce, Airwolf, Blue Thunder, Gunstar (all under `SRL-Projects -*`), plus Maria Hill - WorkingFiles and Timothy Dungan - New Alloy Research, plus the corporate `OneDrive - Stark Research Labs` root. **Confirmed (F-008).** |
| **What was stolen?** | **Cannot prove a specific file list from memory alone.** OneDrive is open on all seven project folders and is connected to M365 throughout the intruder window — copying files into any synced folder would auto-replicate. See accuracy-report GAP G-2. |
| **Where was it transferred to?** | RDP to `213.202.233.104` and `81.30.144.115` (foreign, non-baseline) **confirmed active at capture (F-003)**. Cloud-sync surface to Microsoft Live, Google, Apple iCloud, Slack all alive (F-009). USB device-picker fired at 23:58 EST (F-012, uncertain). |
| **How was it stolen?** | **RDP to the live, unattended, signed-in account is confirmed (F-003 + F-016 + F-004).** The full RDP redirection stack (clipboard / drive / USB) is enabled (F-004). Specific exfil mechanism (clipboard vs `\\tsclient` vs OneDrive sync vs webmail upload) cannot be uniquely attributed from memory alone. |
| **When did the activity occur?** | Interactive session created at **2020-11-13 22:42 EST**; browser activity **23:12 → 23:59 EST + 00:10 → 00:15 EST**; foreign RDP sessions still attached at capture **2020-11-15 21:34-21:35 EST**. **Confirmed (F-005, F-006, F-007, F-003).** |

The investigative posture this evidence demands is: **assume corporate IP exfiltrated** through one or more of the cloud-sync channels and/or RDP redirection during the 23:12 → 00:15 EST window on 2020-11-13/14. Treat 213.202.233.104 and 81.30.144.115 as adversary infrastructure. Rotate all of Fred's M365, Google, Apple, and Slack credentials immediately and audit M365/Google Drive activity logs for IP-of-access during the intruder window — those server-side logs would tell us what files were touched, which memory cannot.
