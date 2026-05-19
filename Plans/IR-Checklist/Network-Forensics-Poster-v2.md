# Network Forensics and Analysis Poster — MemoryHound Coverage Audit (v2 — post Phase 3a)

> Source: `~/Desktop/sift-pdfs/Network-Forensics-Poster.pdf` (SANS DFIR — FOR572, Phil Hagen, DFPS-FOR572_v1.9_03-21)
> Audited against: MemoryHound `feat/install-ux` branch — post Phase 3a build (13 new primitives, 2026-05-19)
> Original audit: `Network-Forensics-Poster.md` (17.8%)

## 1. Phase 3a Delta — What Shipped

Group A — Pcap distillation: `pcap_to_zeek`, `pcap_to_netflow`, `pcap_to_passivedns`
Group B — Pcap toolkit: `pcap_info`, `pcap_slice_time`, `pcap_merge`, `pcap_filter_bpf`, `tcp_reassemble`
Group C — NetFlow: `nfdump_query`
Group D — Pure-Python analytics: `beacon_score`, `conn_top_talkers`, `dns_summarize`, `http_ua_profile`

All 13 primitives sandbox-asserted, typed-error-on-missing-binary, server-registered, test-covered.

## 2. Updated Coverage Table

| # | PDF Prescription | v1 | v2 | Where in MemoryHound |
|---|------------------|----|----|----------------------|
| 1 | Read pcap with tshark, extract fields, apply display filter | ✅ | ✅ | `network.py:tshark_extract` |
| 2 | Read Zeek NSM logs (TSV `#fields` header) | ✅ | ✅ | `network.py:zeek_log_read` |
| 3 | conn.log — TCP/UDP/ICMP connection summaries | ✅ | ✅ | `network.py:zeek_log_read` |
| 4 | dns.log — DNS query/response artifacts | ✅ | ✅ | `network.py:zeek_log_read` |
| 5 | http.log — URLs, User-Agents, Referrers, MIME types | ✅ | ✅ | `network.py:zeek_log_read` |
| 6 | ssl.log / x509.log — TLS metadata and certificates | 🟡 | 🟡 | unchanged — Phase 3b adds JA3/cert analytics |
| 7 | files.log — extracted file metadata | 🟡 | 🟡 | unchanged — Phase 3b adds cross-protocol object extraction |
| 8 | weird.log / signatures.log / etc. | 🟡 | 🟡 | unchanged |
| 9 | **Distill pcap → Zeek logs (`zeek -r`)** | ❌ | **✅** | `network.py:pcap_to_zeek` |
| 10 | **Distill pcap → NetFlow with `nfpcapd`** | ❌ | **✅** | `network.py:pcap_to_netflow` |
| 11 | **NetFlow analysis with `nfdump`** | ❌ | **✅** | `network.py:nfdump_query` (CSV output parsed) |
| 12 | **Distill pcap → PassiveDNS** | ❌ | **✅** | `network.py:pcap_to_passivedns` |
| 13 | Live capture / port-mirror / tap-based collection | ➖ | ➖ | out of scope |
| 14 | NetFlow router export collection | ➖ | ➖ | out of scope |
| 15 | **`tcpdump` BPF capture/read/filter** | ❌ | **✅** | `network.py:pcap_filter_bpf` (BPF allowlist enforced) |
| 16 | **`editcap` — time-slice, dedupe, size-split** | ❌ | **✅** | `network.py:pcap_slice_time` (ISO timestamps) |
| 17 | **`mergecap` — merge multiple pcaps chronologically** | ❌ | **✅** | `network.py:pcap_merge` |
| 18 | **`capinfos` — pcap summary stats** | ❌ | **✅** | `network.py:pcap_info` (key/value parsed) |
| 19 | **`tcpflow` — TCP stream reassembly** | ❌ | **✅** | `network.py:tcp_reassemble` |
| 20 | `tcpxtract` — carve files from streams | ❌ | ❌ | unchanged — Phase 3b |
| 21 | NetworkMiner — protocol-aware extraction | ❌ | ❌ | unchanged — not in roadmap (GUI tool) |
| 22 | `ngrep` — regex match against payload | ❌ | ❌ | unchanged — Phase 3b |
| 23 | `zeek-cut` — extract specific fields | 🟡 | 🟡 | unchanged — `zeek_log_read` returns all fields as dicts |
| 24 | `jq` — parse/transform JSON Zeek logs | ❌ | ❌ | unchanged — Phase 3b (JSON reader) |
| 25 | `calamaris` — web proxy summary | ❌ | ❌ | unchanged — Phase 3b |
| 26 | `grep` family — pattern search | ➖ | ➖ | out of scope (shell concern) |
| 27 | Wireshark GUI | ➖ | ➖ | out of scope (headless/MCP) |
| 28 | SOF-ELK ingest + KQL queries | ❌ | ❌ | unchanged — Phase 3c |
| 29 | Arkime full-packet ingest, SPI, Hunt | ❌ | ❌ | unchanged — Phase 3c |
| 30 | **Workflow: Ingest and Distill** | 🟡 | **✅** | `evidence.py:ingest_artifact` + Phase-3a distillation |
| 31 | **Workflow: Reduce and Filter** | 🟡 | **✅** | `pcap_slice_time` + `pcap_filter_bpf` + `tshark_extract -Y` |
| 32 | Workflow: Establish Baselines | ❌ | ❌ | unchanged — Phase 3c (needs persistent state) |
| 33 | Workflow: Analyze and Explore | 🟡 | 🟡 | improved by analytics — still single-pcap-at-a-time |
| 34 | Workflow: Scope and Scale | ❌ | ❌ | unchanged — Phase 3c |
| 35 | Workflow: Extract Indicators and Objects | 🟡 | 🟡 | unchanged — Phase 3b adds stream carving |
| 36 | Anomaly: HTTP GET vs POST ratio | ❌ | 🟡 | `http_ua_profile` exposes method_distribution; ratio is caller-side derivation |
| 37 | **Anomaly: Top-talking IP addresses** | ❌ | **✅** | `network_analytics.py:conn_top_talkers` (by=bytes/connections/duration) |
| 38 | **Anomaly: HTTP User-Agent profiling** | ❌ | **✅** | `network_analytics.py:http_ua_profile` (top_user_agents) |
| 39 | **Anomaly: Top DNS domains queried** | ❌ | **✅** | `network_analytics.py:dns_summarize` (top_queries + nxdomain_top) |
| 40 | Anomaly: HTTP return-code ratio | ❌ | 🟡 | `http_ua_profile.status_code_distribution` exposes it; ratio is derivation |
| 41 | Anomaly: Newly-observed / NRD domains | ❌ | ❌ | unchanged — needs WHOIS / external service |
| 42 | Anomaly: External infrastructure usage | ❌ | 🟡 | partial via `conn_top_talkers` + `dns_summarize`; no policy engine |
| 43 | Anomaly: Typical port/protocol baselines | ❌ | ❌ | unchanged — Phase 3c |
| 44 | Anomaly: DNS TTL values + RR counts | ❌ | ❌ | unchanged — Phase 3b |
| 45 | Anomaly: Autonomous System (ASN) | ❌ | ❌ | unchanged — Phase 3b (needs IP→ASN data) |
| 46 | **Anomaly: Periodic traffic volume (beaconing)** | ❌ | **✅** | `network_analytics.py:beacon_score` (CV + entropy + count composite) |
| 47 | Use case: Continuous IR / Threat Hunting | 🟡 | 🟡 | unchanged — pcap-at-a-time, no SIEM |
| 48 | Use case: Post-Incident reactive detection | ✅ | ✅ | unchanged |

## 3. Updated Coverage Score

- **Covered (✅): 18 / 48** (was 3)
- **Partial (🟡): 8 / 48** (was 10 — 2 promoted to ✅, then 3 new partials: rows 36/40/42)
- **Missing (❌): 19 / 48** (was 32)
- **N/A: 3 / 48** (unchanged)

Conservative weighted score (✅ = 1.0, 🟡 = 0.5):
- (18 + 0.5 × 8) / 45 = **22 / 45 = 48.9%**

If we count partial-promotions strictly (rows 36/40/42 add 0.5 each):
- 18 + 0.5 × 8 = 22 → 48.9%

**Delta vs original audit: +31.1pp** (from 17.8% → 48.9%).

## 4. What's Now Possible That Wasn't

Given a single pcap, MemoryHound can now:

1. **Distill** the pcap into Zeek logs (conn/dns/http/ssl/files/x509) — the foundation for everything downstream.
2. **Convert** the pcap to NetFlow v5 records, then query them with aggregation (`-A srcip,dstip`), top-N (`-c 100`), and BPF filters.
3. **Generate** PassiveDNS log entries from the pcap.
4. **Slice** by time window (editcap), **filter** by BPF (tcpdump), **merge** multiple pcaps chronologically.
5. **Summarize** pcap stats (capinfos: packet count, time window, byte rate, file hashes).
6. **Reassemble** TCP streams into per-flow payload files (tcpflow).
7. **Score** beaconing candidates from conn.log — periodic outbound connections with low interval variance and low entropy. This is the FOR572 "Periodic Traffic Volume" anomaly and the most common C2 indicator.
8. **Rank** top talkers by bytes / connections / duration from conn.log.
9. **Aggregate** DNS: top queries, top qtypes, NXDOMAIN count and top NXDOMAIN queries (DGA tell), unique resolver count.
10. **Profile** HTTP: top user-agents, method distribution, status distribution, top hosts/URIs, **flag URIs ending in `.exe`/`.dll`/`.scr`/`.ps1`/`.bat`/`.cmd`/`.vbs`/`.jar`** for payload-delivery detection.

## 5. What's Still Missing (Phase 3b/3c Roadmap)

### Phase 3b (Mid-priority — 5-8 more primitives)

- **TLS/JA3 fingerprinting + cert analytics** over ssl.log/x509.log (row 6)
- **`tcpxtract` / `ngrep`** — file carving from streams + payload regex (rows 20, 22)
- **JSON Zeek log reader** — auto-detect TSV vs JSON output (row 24)
- **`calamaris`** — web proxy summary (row 25)
- **DNS TTL anomaly + fast-flux detection** (row 44)
- **ASN/GeoIP enrichment** with offline data file (row 45)

### Phase 3c (Heavy — infra-shaped, post-hackathon)

- **SOF-ELK adapter** — export MemoryHound artifacts in SOF-ELK-readable format (row 28)
- **Arkime export adapter** (row 29)
- **Baselining engine** — persistent "normal" pattern store (row 32, 43)
- **Newly-registered domain check** — WHOIS / passive DNS first-seen registry (row 41)
- **Policy engine for external-infra detection** (row 42)

## 6. Anti-criteria preserved

- No live-capture, no port-mirror, no router NetFlow ingest — explicitly out of scope.
- No external service calls (WHOIS / GeoIP / VirusTotal / AbuseIPDB) — Phase 3b will add explicit auth gating.
- No SOF-ELK / Arkime / Elasticsearch — Phase 3c.
- No numpy / pandas / scipy — analytics are stdlib-only (statistics + math + collections.Counter).

## 7. Test Posture

- 43 new tests pass on first run (28 in `test_network_phase3a.py`, 15 in `test_network_analytics.py`).
- Full mcp-server pytest suite: **185 passed, 1 skipped** — zero regressions.
- `ruff check` clean on all five touched files (`network.py`, `network_analytics.py`, `server.py`, both test files).
- Network coverage on `tools/network.py`: 82%. Coverage on `network_analytics.py`: 91%.
