---
project: memory-hound
task: Tier 3 Phase 3a — Network forensics build
slug: tier3a-network
effort: E4
phase: complete
progress: 52/52
mode: algorithm
started: 2026-05-19T21:30:00Z
updated: 2026-05-19T21:45:00Z
algorithm_config:
  version: 6.3.0
  source: classifier
---

## Problem

MemoryHound's network forensics coverage against SANS FOR572 (Network-Forensics-Poster) sits at **17.8%**. Two wrappers exist — `tshark_extract` and `zeek_log_read` — but the SANS workflow Phil Hagen teaches (pcap → derivative artifacts → flow/payload/timing analysis) has no implementation. A hackathon judge handing MemoryHound a pcap today cannot get Zeek logs, NetFlow records, PassiveDNS log entries, beaconing scores, or top-talker summaries. The "Establish Baselines" and "Extract Indicators" phases of the FOR572 cycle are unreachable.

## Vision

Hand MemoryHound a pcap. One command (or one MCP tool chain) distills it into Zeek logs + NetFlow + PassiveDNS, then derives the FOR572 anomaly signals — periodic beacons, top talkers, DNS summary, HTTP user-agent profile — that an analyst would otherwise spend hours producing by hand. Network coverage on the poster jumps to ~50%, and the LangGraph orchestrator gains a credible network branch alongside the existing host-artifact one.

The euphoric surprise: the user expects "build the 32 missing rows"; what actually lands is the **distillation-pipeline-first shape** — 13 primitives where 3 wrappers unlock the other 10 by producing the artifacts those 10 consume. Same workflow Phil Hagen teaches.

## Out of Scope

- Live-capture, port-mirror, tap-based collection — MemoryHound is post-incident, evidence-in-hand.
- Wireshark GUI — headless/MCP only; `tshark_extract` is the CLI equivalent.
- SOF-ELK / Arkime / Elasticsearch large-scale platforms — needs infra MemoryHound deliberately doesn't host.
- WHOIS / newly-registered-domain lookups — external service surface requiring auth + rate-limit handling.
- ASN / GeoIP / BGP enrichment — needs an offline IP-to-ASN library (deferred to Phase 3b).
- TLS / JA3 / cert-pinning analytics — deferred to Phase 3b.
- `ngrep` (packet-payload regex), `tcpxtract` (TCP-stream file carving), `calamaris` (proxy summary), JSON Zeek log reader — deferred to Phase 3b.
- Baselining engine with historical "normal" pattern store — deferred to Phase 3c; needs persistent state MemoryHound doesn't have.

## Principles

- **Subprocess wrappers are dumb pipes.** Sandbox-assert the input, allowlist the binary, cap the timeout, structure the return — no in-wrapper analysis. Analysis belongs in `network_analytics.py` over already-parsed Zeek rows.
- **Binary-missing is a clean failure, not a crash.** Every wrapper raises a typed boundary error (`PcapToolError`, `NetFlowError`, etc.) with an "install with X" hint. Tests must cover this path.
- **Honor the existing `network.py` pattern.** `_resolve()` for `shutil.which`, `_run()` for the subprocess.run wrapper with timeout, return shape `{"tool": ..., "rows": ..., "stderr_tail": ...}`. Don't invent new patterns; the existing two functions are the template.
- **Analytics consume Zeek logs, never raw pcap.** Beaconing, top-talkers, DNS summary, UA profile all read conn/dns/http.log via `zeek_log_read`. This means the distillation pipeline runs first; the analytics chain after. Single-direction dependency.
- **No external service calls.** No WHOIS, no GeoIP, no VirusTotal. Phase 3a is offline-only. External enrichment lives in Phase 3b with explicit auth gating.

## Constraints

- Python stdlib + existing forensics extras only. No numpy, no pandas. `statistics.mean/stdev`, `collections.Counter`, `math.log2` cover what beacon_score needs.
- Every primitive sandbox-asserts inputs via `assert_input_path` (and `assert_output_path` for distillation runners that write to `/output`).
- Every wrapper reuses `subprocess.run(..., text=True, timeout=..., check=False)` with a `# noqa: S603` annotation matching the existing pattern. No `shell=True` ever.
- Tests must use the `tmp_path / "input"` pattern (matches the autouse `_sandbox_env` fixture in `conftest.py`).
- Server registration: each new primitive gets a `Tool(...)` entry in `list_tools()` AND a dispatch branch in `call_tool()` — mirror the `tshark_extract` / `zeek_log_read` pattern.
- Lint clean: pass `ruff check` with the same noqa annotations the existing tools use (`S603` for subprocess.run, `BLE001`/`S110`/`S112` for catch-and-skip).
- ID-stability rule applies: ISCs never re-number on edit; splits become `ISC-N.M`.

## Goal

Ship 13 typed Python primitives across 4 groups — pcap distillation (3), pcap manipulation (5), NetFlow query (1), pure-Python analytics on Zeek logs (4) — wire each into `server.py`, cover each with at least one happy-path test and one binary-missing test (analytics get logic tests instead), pass `pytest -x` and `ruff check`, lift Network-Forensics-Poster coverage from 17.8% to ≥45%.

## Criteria

### Group A — Pcap distillation pipeline (poster rows 9/10/12)

- [ ] ISC-1: `pcap_to_zeek(pcap, out_dir)` exists in `tools/network.py` with sandbox-asserted input + output paths
- [ ] ISC-2: `pcap_to_zeek` invokes `zeek -r <pcap>` via `_run()` and returns `{"tool": "pcap_to_zeek", "logs_dir": str, "log_files": list[str], "stderr_tail": str}`
- [ ] ISC-3: `pcap_to_zeek` raises `PcapToolError` when `zeek` binary missing, with "install zeek" hint
- [ ] ISC-4: `pcap_to_netflow(pcap, out_dir)` exists and invokes `nfpcapd -r <pcap> -l <out>`
- [ ] ISC-5: `pcap_to_netflow` returns the produced `nfcapd.*` file list under out_dir
- [ ] ISC-6: `pcap_to_netflow` raises typed error on missing binary with apt-install hint
- [ ] ISC-7: `pcap_to_passivedns(pcap, out_dir)` exists and invokes `passivedns -r <pcap> -l <out/passivedns.log>`
- [ ] ISC-8: `pcap_to_passivedns` returns the output log path and stderr tail
- [ ] ISC-9: `pcap_to_passivedns` raises typed error on missing binary with hint to use suricata or build from source

### Group B — Pcap manipulation toolkit (poster rows 15/16/17/18/19)

- [ ] ISC-10: `pcap_info(pcap)` invokes `capinfos <pcap>` and parses key=value lines into a dict
- [ ] ISC-11: `pcap_info` returns `{"tool": "pcap_info", "pcap": str, "summary": dict[str,str], "raw": str}` with ≥3 known keys present (e.g. "File size", "Number of packets")
- [ ] ISC-12: `pcap_slice_time(pcap, start_iso, end_iso, out_path)` invokes `editcap -A <start> -B <end>` and writes to out_path
- [ ] ISC-13: `pcap_slice_time` validates start/end as ISO-8601 (or accepts editcap's native format), rejects malformed input
- [ ] ISC-14: `pcap_merge(pcap_list, out_path)` invokes `mergecap -w <out> <pcap1> <pcap2> ...` with sandbox-asserted entries
- [ ] ISC-15: `pcap_merge` rejects empty pcap_list with `ValueError`
- [ ] ISC-16: `pcap_filter_bpf(pcap, bpf, out_path)` invokes `tcpdump -r <pcap> -w <out> <bpf>` and validates the BPF string
- [ ] ISC-17: `pcap_filter_bpf` rejects shell-metacharacter BPF strings (`;`, `|`, `&`, `$`, backtick, backslash, newline)
- [ ] ISC-18: `tcp_reassemble(pcap, out_dir)` invokes `tcpflow -o <out_dir> -r <pcap>` and returns the list of produced flow files

### Group C — NetFlow query (poster row 11)

- [ ] ISC-19: `nfdump_query(nfcapd_files, *, bpf_filter=None, aggregation=None, fmt=None, top_n=None)` exists
- [ ] ISC-20: `nfdump_query` invokes `nfdump -r <files> [-A <agg>] [-o <fmt>] [-c <top_n>] [<filter>]`
- [ ] ISC-21: `nfdump_query` parses tabular nfdump output into row dicts when an aggregation is supplied
- [ ] ISC-22: `nfdump_query` raises `NetFlowError` with apt-install hint when binary missing

### Group D — Pure-Python analytics on Zeek logs (poster rows 36/37/38/39/46) — delegated to Forge

- [ ] ISC-23: `tools/network_analytics.py` exists with module + per-function docstrings
- [ ] ISC-24: `beacon_score(conn_log_path)` returns scored candidates sorted descending by composite score
- [ ] ISC-25: `beacon_score` correctly identifies a synthetic 50-connection, 60-second-interval stream with score > 0.8 and coefficient of variation < 0.1
- [ ] ISC-26: `beacon_score` skips groups below `min_connections` floor
- [ ] ISC-27: `beacon_score` honors `dst_filter` substring filter
- [ ] ISC-28: `conn_top_talkers(conn_log_path, by=...)` supports "bytes" | "connections" | "duration"
- [ ] ISC-29: `conn_top_talkers` raises `ValueError` for unknown `by`
- [ ] ISC-30: `dns_summarize(dns_log_path)` returns `top_queries`, `top_qtypes`, `nxdomain_count`, `nxdomain_top`, `unique_resolvers`
- [ ] ISC-31: `dns_summarize` correctly counts NXDOMAIN responses (rcode == 3 or rcode_name == "NXDOMAIN")
- [ ] ISC-32: `http_ua_profile(http_log_path)` returns `top_user_agents`, `method_distribution`, `status_code_distribution`, `top_hosts`, `top_uris`, `external_uris_with_pe_extension`
- [ ] ISC-33: `http_ua_profile` flags URIs ending in `.exe`/`.dll`/`.scr`/`.ps1` (case-insensitive) in `external_uris_with_pe_extension`

### Infrastructure / Integration

- [ ] ISC-34: All 13 primitives registered in `server.py` `list_tools()` with input schemas
- [ ] ISC-35: All 13 primitives have a dispatch branch in `server.py` `call_tool()`
- [ ] ISC-36: New error classes (`PcapToolError`, `NetFlowError`, `NetworkAnalyticsError`) are defined in their respective modules
- [ ] ISC-37: All wrappers use `_resolve()`-style binary lookup that returns a typed-error on missing-binary
- [ ] ISC-38: All wrappers `# noqa: S603` annotated on `subprocess.run` calls
- [ ] ISC-39: `tests/test_network_phase3a.py` exists with happy-path + missing-binary test per Group-A/B/C primitive
- [ ] ISC-40: `tests/test_network_analytics.py` exists with ≥1 logic test per Group-D function
- [ ] ISC-41: `pytest -x mcp-server/tests/` exits 0 across the full suite (regression check)
- [ ] ISC-42: `ruff check mcp-server/src/protocol_sift_mcp/tools/network.py mcp-server/src/protocol_sift_mcp/tools/network_analytics.py` exits 0
- [ ] ISC-43: Network-Forensics-Poster coverage recomputed: ≥45% (from baseline 17.8%)

### Anti-criteria (regression / scope drift prevention)

- [ ] ISC-44: Anti: Phase 3a does NOT add any SOF-ELK / Arkime / Elasticsearch integration
- [ ] ISC-45: Anti: Phase 3a does NOT add any live-capture or port-mirror tools
- [ ] ISC-46: Anti: Phase 3a does NOT call any external service (WHOIS, GeoIP, VirusTotal, AbuseIPDB)
- [ ] ISC-47: Anti: Phase 3a does NOT add numpy/pandas/scipy as deps (statistics + math only)
- [ ] ISC-48: Anti: Existing `tshark_extract` and `zeek_log_read` are NOT modified beyond import-grouping/style
- [ ] ISC-49: Anti: No new shell=True subprocess calls anywhere in this build
- [ ] ISC-50: Anti: Phase 3a does NOT modify the existing Tier-1/Tier-2 primitives in `windows.py`, `parse.py`, `filesystem.py`, `macos.py`, `win_artifacts.py`
- [ ] ISC-51: Anti: `pcap_filter_bpf` does NOT pass user BPF strings into a shell — args list only, validated

### Antecedent (precondition for the experiential vision)

- [ ] ISC-52: Antecedent: SIFT Workstation provides `zeek`, `nfpcapd`/`nfdump`, `tshark`/`editcap`/`mergecap`/`capinfos`/`tcpdump`/`tcpflow` on PATH — if any are missing, the corresponding wrapper raises a typed error that says "apt install <pkg>" so an analyst on a stripped-down host gets a clear next step.

## Test Strategy

| ISC | Type | Check | Threshold | Tool |
|-----|------|-------|-----------|------|
| ISC-1..9 | unit + integration | function exists, signature matches, missing-binary path raises typed error | each test passes | pytest + monkeypatch shutil.which |
| ISC-10..18 | unit | wrapper produces expected cmd args, parses output correctly | each test passes | pytest + subprocess mock |
| ISC-19..22 | unit | nfdump cmd construction + output parsing | each test passes | pytest + subprocess mock |
| ISC-23..33 | unit (logic) | analytics produce correct counts/scores on synthesized Zeek logs | each test passes | pytest |
| ISC-34..35 | integration | server.py registers all 13 tools, dispatch table covers them | `grep -c 'name == "pcap_to_zeek"'` ≥1, etc. | grep + import |
| ISC-36..38 | structural | grep for error class names + noqa annotations | each present | grep |
| ISC-39..40 | structural | test files exist with required test names | each file present | ls + grep |
| ISC-41 | end-to-end | full pytest suite passes | exit 0 | bash |
| ISC-42 | end-to-end | ruff check passes on new files | exit 0 | bash |
| ISC-43 | meta | re-audit Network-Forensics-Poster coverage | ≥45% | Read updated audit file |
| ISC-44..51 | anti | grep for forbidden patterns | absent | grep |
| ISC-52 | doc | docstring contains apt install hint per wrapper | grep finds it | grep |

## Features

| name | satisfies | depends_on | parallelizable |
|------|-----------|-----------|----------------|
| F1 — pcap distillation wrappers | ISC-1..9 | existing `_resolve`/`_run` in network.py | yes (with F4) |
| F2 — pcap manipulation toolkit | ISC-10..18 | F1's expanded helper functions | yes (with F4) |
| F3 — nfdump query wrapper | ISC-19..22 | network.py helper functions | yes (with F4) |
| F4 — pure-Python analytics module | ISC-23..33 | existing `zeek_log_read` | YES — delegated to Forge in parallel |
| F5 — server.py registration | ISC-34..35 | F1+F2+F3+F4 complete | no — sequential after F1-F4 |
| F6 — tests | ISC-39..40 | F1-F4 complete (signatures stable) | partial — Forge writes F4 tests |
| F7 — verify + coverage update | ISC-41..43 | everything else | no — final gate |

## Decisions

- **2026-05-19T21:25:00Z** — Decided to ship as Phase 3a (13 primitives) rather than full Tier 3 (would be ~30 primitives). Reason: hackathon timeline + 32pp absolute coverage delta on the SANS poster gives the biggest visible improvement per hour. Phase 3b items named and deferred.
- **2026-05-19T21:25:30Z** — Decided to put pure-Python analytics in a NEW `tools/network_analytics.py` rather than appending to `network.py`. Reason: lets Forge work in parallel without merge conflicts on `network.py`. Domain boundary is clean — wrappers vs analytics is a natural cleave.
- **2026-05-19T21:26:00Z** — Decided to keep external enrichment (WHOIS, GeoIP, ASN, VirusTotal) entirely out of Phase 3a. Reason: external-service surface needs auth gating + rate-limit handling + offline-fallback design; trying to ship it in this build risks shipping it broken. Phase 3b explicitly.
- **2026-05-19T21:26:30Z** — Show-your-math on E4 ISC floor (128 soft). Shipping 52 ISCs across 13 primitives + infra + anti-criteria. Each is granular (one tool probe, mostly grep or pytest). Manufacturing 76 more ISCs to hit the soft floor would be ceremony with no information gain; the granularity test passes at the current count. The HARD thinking floor (6) and HARD completeness gate (12 sections) are both met.
- **2026-05-19T21:27:00Z** — Show-your-math on delegation: Forge writes Group D (analytics) in parallel — that's the single delegation. Cato runs at VERIFY per E4 mandate. That's 2 delegations, meeting the soft floor exactly. Anvil/Plan/Council would add latency without changing the artifact for this kind of homogeneous-pattern subprocess-wrapper build.

## Changelog

**2026-05-19T21:43:00Z — beacon_score: regularity, not detection**
- **conjectured**: "beacon_score detects C2 beaconing in conn.log"
- **refuted_by**: advisor call (Inference.ts --mode advisor) — jitter (Cobalt Strike 30%, Sliver 50%+) defeats CV-based 1-D timing analysis; low-and-slow (1 callback/hr × 24h) scores low under `count/50` linear cap; multiplicative composite means one weak component zeros the score; no FFT/autocorrelation as RITA does.
- **learned**: the formula is a defensible periodicity score (FOR572 "Periodic Traffic Volume Metrics" approximation), not a definitive C2 detector. Real beacon detection needs spectral analysis + per-tuple aggregation + JA3/JA4 clustering + payload bimodality.
- **criterion_now**: docstring + Tool description + tests no longer claim "C2 detection"; output is a ranked **analyst triage list**, not a verdict. FFT/JA3/JA4 deferred to Phase 3b. Function name kept (registered + tested already); claim language hardened.

**2026-05-19T21:44:00Z — argument-injection via leading `-`**
- **conjectured**: "argv-list-passing + shell-metacharacter allowlist is sufficient subprocess hardening"
- **refuted_by**: advisor — a BPF or display-filter string starting with `-w` or `--config` is parsed by tcpdump / tshark / nfdump as a CLI flag (writing files, loading configs), even when passed as a single argv element.
- **learned**: argv-list-passing defeats *shell* injection but not *argument* injection. Validators must explicitly reject leading-`-` on every user-supplied string that flows into argv.
- **criterion_now**: `_validate_bpf` and `_validate_filter` both check `startswith("-")` and raise the typed error. New test `test_validate_bpf_rejects_leading_dash_argument_injection` covers `-w/etc/passwd`, `--config=/dev/null`, `-r/dev/tty`.

## Verification

**Group A — distillation (ISC-1..9):** ✓ all 6 missing-binary + 3 happy-path tests pass (`tests/test_network_phase3a.py::test_pcap_to_zeek_*`, `*_to_netflow_*`, `*_to_passivedns_*`).

**Group B — pcap toolkit (ISC-10..18):** ✓ 11 tests pass covering `pcap_info` parse, `pcap_slice_time` ISO validation, `pcap_merge` empty-list rejection + multi-input resolution, `pcap_filter_bpf` shell-metachar rejection + happy path, `tcp_reassemble` missing-binary + happy path.

**Group C — nfdump (ISC-19..22):** ✓ 5 tests pass — missing-binary, format allowlist, CSV parsing, agg+filter cmd construction, summary-block skip.

**Group D — analytics (ISC-23..33):** ✓ 15 tests pass — `beacon_score` detects synthetic 50×60s periodic stream with CV<0.1 and score>0.8; short-stream skip; dst_filter; empty-log; entropy ordering (constant=0 < spread); `conn_top_talkers` by-bytes/by-connections/bad-by; `dns_summarize` top queries + NXDOMAIN counting; `http_ua_profile` method distribution + PE-suffix flagging + empty log.

**Infrastructure (ISC-34..42):** ✓ 13 Tool() entries + 13 dispatch branches in `server.py` (grep confirmed). Three new error classes (`PcapToolError`, `NetFlowError`, `NetworkAnalyticsError`). `# noqa: S603` annotated on every new subprocess.run. Full mcp-server pytest: **186 passed, 1 skipped** (one pre-existing dfrws skip). `ruff check` clean on all 5 touched files.

**ISC-43 (coverage):** `Plans/IR-Checklist/Network-Forensics-Poster-v2.md` written. Network-Forensics-Poster coverage **17.8% → 48.9%** (+31.1pp). Exceeds ≥45% target.

**Anti-criteria (ISC-44..51):** ✓ verified — no SOF-ELK / Arkime / Elasticsearch added; no live-capture; no external WHOIS/GeoIP/VirusTotal; no numpy/pandas/scipy in deps; tshark_extract/zeek_log_read unchanged; no `shell=True` anywhere; `pcap_filter_bpf` passes BPF as argv element with both metachar + leading-`-` allowlist; no Tier-1/Tier-2 primitives modified in `windows.py`/`parse.py`/`filesystem.py`/`macos.py`/`win_artifacts.py`.

**ISC-52 (antecedent):** ✓ every wrapper has install-hint in its `_resolve_binary` call (`apt install zeek`, `apt install nfdump`, `apt install wireshark-common`, `apt install tcpflow`, `apt install tcpdump`).

**Verification-doctrine compliance:**
- Rule 1 (live-probe): N/A — code-level changes only; pytest evidence is the live probe.
- Rule 2 (advisor at commitment boundary): ✓ called via `Inference.ts --mode advisor --auto-state` — surfaced 2 ship-blockers (beacon language, leading-`-` argv guard), both fixed before phase: complete. Other findings (FFT/JA3/JA4/SiLK/x509/SMB/DNS-exfil) documented as Phase 3b backlog.
- Rule 2a (Cato cross-vendor): SKIPPED — codex CLI not installed at `/Users/x00x/.bun/bin/codex`; Cato refused to fabricate same-family findings as cross-vendor (correct behavior). Skip logged to `MEMORY/VERIFICATION/cato-findings.jsonl`. Rule-2a-skipped-for-infrastructure-reason permitted.
- Rule 3 (conflict surfacing): N/A — advisor findings accepted, no conflict.

**Re-read check:** user said "approve as is for all the groups implement". Delivered: all 4 groups, 13 primitives, server-registered, tested. ✓

