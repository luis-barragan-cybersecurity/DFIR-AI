"""Pure-Python anomaly analytics over already-parsed Zeek logs.

The wrappers in `network.py` distill a pcap into Zeek conn/dns/http/ssl logs.
This module consumes those logs and derives the FOR572 anomaly signals an
analyst would otherwise hand-roll: beaconing scores, top-talker rankings,
DNS summaries, HTTP user-agent profiles.

No subprocess. No external network. Stdlib-only — `statistics`, `math`,
`collections.Counter`. The single point of contact with the rest of the
system is `zeek_log_read` for the file-format parsing.

Each function sandbox-asserts its input path via the existing `assert_input_path`
boundary so analytics inherit the same evidence-isolation guarantees the
wrappers have.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter
from typing import Any

from ..sandbox import assert_input_path
from .network import zeek_log_read


class NetworkAnalyticsError(Exception):
    """Malformed Zeek log, missing required column, or analytic precondition unmet."""


def _to_float(v: str | None) -> float:
    """Coerce a Zeek cell to float. '-' and empty are Zeek nulls → 0.0."""
    if v is None or v == "" or v == "-":
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _to_int(v: str | None) -> int:
    """Coerce a Zeek cell to int. '-' and empty are Zeek nulls → 0."""
    if v is None or v == "" or v == "-":
        return 0
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _require_field(rows: list[dict[str, Any]], field: str, log_kind: str) -> None:
    """Raise NetworkAnalyticsError if the named column is missing in the first row."""
    if not rows:
        return
    if field not in rows[0]:
        raise NetworkAnalyticsError(
            f"required field {field!r} not found in {log_kind} log headers: {sorted(rows[0].keys())}"
        )


def beacon_score(
    conn_log_path: str,
    *,
    dst_filter: str | None = None,
    min_connections: int = 8,
    top_n: int = 50,
) -> dict[str, Any]:
    """Periodicity score for `(src, dst, dport)` tuples in conn.log.

    **What this is.** A FOR572 "Periodic Traffic Volume Metrics" approximation: a
    1-D timing-regularity score over inter-arrival intervals. Composite in [0, 1]
    multiplies three terms:
      * Coefficient of variation (stdev / mean of intervals) — low CV → metronomic
        spacing → potential beacon.
      * Shannon entropy of an 8-bin histogram of intervals — low entropy → intervals
        clustered → potential beacon.
      * Connection count — more datapoints → higher confidence (linear up to 50).

    **What this is NOT.** A definitive C2-beacon detector. Modern C2 frameworks
    (Cobalt Strike at 30% jitter, Sliver/Mythic/Havoc at 50%+) deliberately raise CV
    to defeat exactly this kind of regularity check, and low-and-slow beacons (1
    callback per hour over 24h) score low under the `count/50` linear cap. Real C2
    detection needs spectral analysis (FFT peak prominence), JA3/JA4 TLS clustering,
    per-tuple aggregation across multiple log types, and payload-size bimodality —
    deferred to Phase 3b.

    Treat the score as a **ranked candidate list for analyst triage**, not a verdict.

    Args:
        conn_log_path: Path to a Zeek conn.log under the evidence sandbox.
        dst_filter: Optional substring filter applied to `id.resp_h`.
        min_connections: Floor below which a group is too short to score (default 8).
        top_n: Cap on returned candidates.
    """
    _ = assert_input_path(conn_log_path)
    parsed = zeek_log_read(conn_log_path)
    rows = parsed["rows"]
    if not rows:
        return {
            "tool": "beacon_score",
            "log_path": conn_log_path,
            "candidates_examined": 0,
            "candidates": [],
        }
    for f in ("ts", "id.orig_h", "id.resp_h", "id.resp_p"):
        _require_field(rows, f, "conn")

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for r in rows:
        src = r.get("id.orig_h", "")
        dst = r.get("id.resp_h", "")
        if dst_filter and dst_filter not in dst:
            continue
        dport = r.get("id.resp_p", "")
        groups.setdefault((src, dst, dport), []).append(r)

    candidates: list[dict[str, Any]] = []
    for (src, dst, dport), grp in groups.items():
        if len(grp) < min_connections:
            continue
        ts_sorted = sorted(_to_float(r.get("ts")) for r in grp)
        intervals = [b - a for a, b in zip(ts_sorted, ts_sorted[1:], strict=False) if (b - a) > 0]
        if len(intervals) < 2:
            continue
        mean_iv = statistics.mean(intervals)
        if mean_iv <= 0:
            continue
        stdev_iv = statistics.pstdev(intervals)
        cv = stdev_iv / mean_iv if mean_iv > 0 else 1.0
        entropy = _interval_entropy(intervals, bins=8)
        bytes_total = sum(_to_int(r.get("orig_bytes")) for r in grp)
        score = (
            (1.0 - min(cv, 1.0))
            * (1.0 - min(entropy / 3.0, 1.0))
            * min(len(grp) / 50.0, 1.0)
        )
        candidates.append({
            "src": src,
            "dst": dst,
            "dst_port": dport,
            "connection_count": len(grp),
            "mean_interval_sec": round(mean_iv, 4),
            "interval_stdev": round(stdev_iv, 4),
            "coefficient_of_variation": round(cv, 6),
            "interval_entropy": round(entropy, 4),
            "bytes_sent_total": bytes_total,
            "score": round(score, 6),
        })

    candidates.sort(key=lambda c: c["score"], reverse=True)
    return {
        "tool": "beacon_score",
        "log_path": conn_log_path,
        "candidates_examined": len(groups),
        "candidates": candidates[:top_n],
    }


def _interval_entropy(intervals: list[float], *, bins: int = 8) -> float:
    """Shannon entropy of intervals binned uniformly between min and max.

    Returns 0.0 when all intervals fall in a single bin (perfect periodicity).
    """
    if not intervals or len(intervals) == 1:
        return 0.0
    lo = min(intervals)
    hi = max(intervals)
    if hi <= lo:
        return 0.0
    width = (hi - lo) / bins
    counts = [0] * bins
    for v in intervals:
        idx = min(int((v - lo) / width), bins - 1)
        counts[idx] += 1
    total = sum(counts)
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        h -= p * math.log2(p)
    return h


_TOP_TALKERS_BY: frozenset[str] = frozenset({"bytes", "connections", "duration"})


def conn_top_talkers(
    conn_log_path: str,
    *,
    k: int = 20,
    by: str = "bytes",
) -> dict[str, Any]:
    """Top-k `(src, dst)` pairs from conn.log ranked by `by`.

    `by` ∈ {"bytes", "connections", "duration"}.
    Bytes = orig_bytes + resp_bytes (Zeek nulls coerced to 0).
    """
    _ = assert_input_path(conn_log_path)
    if by not in _TOP_TALKERS_BY:
        raise ValueError(f"by={by!r} not in {sorted(_TOP_TALKERS_BY)}")

    parsed = zeek_log_read(conn_log_path)
    rows = parsed["rows"]
    if not rows:
        return {"tool": "conn_top_talkers", "log_path": conn_log_path, "by": by, "k": k, "pairs": []}
    for f in ("id.orig_h", "id.resp_h"):
        _require_field(rows, f, "conn")

    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = (r.get("id.orig_h", ""), r.get("id.resp_h", ""))
        a = agg.setdefault(key, {"bytes": 0, "connections": 0, "duration_sec": 0.0})
        a["bytes"] += _to_int(r.get("orig_bytes")) + _to_int(r.get("resp_bytes"))
        a["connections"] += 1
        a["duration_sec"] += _to_float(r.get("duration"))

    if by == "bytes":
        def sort_key(kv: tuple[Any, dict[str, Any]]) -> Any:
            return kv[1]["bytes"]
    elif by == "connections":
        def sort_key(kv: tuple[Any, dict[str, Any]]) -> Any:
            return kv[1]["connections"]
    else:
        def sort_key(kv: tuple[Any, dict[str, Any]]) -> Any:
            return kv[1]["duration_sec"]

    ranked = sorted(agg.items(), key=sort_key, reverse=True)[:k]
    pairs = [
        {
            "src": src,
            "dst": dst,
            "bytes": a["bytes"],
            "connections": a["connections"],
            "duration_sec": round(a["duration_sec"], 4),
        }
        for (src, dst), a in ranked
    ]
    return {"tool": "conn_top_talkers", "log_path": conn_log_path, "by": by, "k": k, "pairs": pairs}


def dns_summarize(
    dns_log_path: str,
    *,
    k: int = 20,
) -> dict[str, Any]:
    """Aggregate dns.log into top queries, qtypes, NXDOMAIN counts, distinct resolvers."""
    _ = assert_input_path(dns_log_path)
    parsed = zeek_log_read(dns_log_path)
    rows = parsed["rows"]
    if not rows:
        return {
            "tool": "dns_summarize",
            "log_path": dns_log_path,
            "row_count": 0,
            "top_queries": [],
            "top_qtypes": [],
            "nxdomain_count": 0,
            "nxdomain_top": [],
            "unique_resolvers": 0,
        }

    query_counter: Counter[str] = Counter()
    qtype_counter: Counter[str] = Counter()
    nxdomain_query_counter: Counter[str] = Counter()
    resolvers: set[str] = set()
    nxdomain_count = 0

    qtype_field = "qtype_name" if "qtype_name" in rows[0] else "qtype"

    for r in rows:
        q = r.get("query") or ""
        if q and q != "-":
            query_counter[q] += 1
        qt = r.get(qtype_field) or ""
        if qt and qt != "-":
            qtype_counter[qt] += 1
        resp = r.get("id.resp_h") or ""
        if resp and resp != "-":
            resolvers.add(resp)
        rcode = r.get("rcode") or ""
        rcode_name = (r.get("rcode_name") or "").upper()
        if rcode == "3" or rcode_name == "NXDOMAIN":
            nxdomain_count += 1
            if q and q != "-":
                nxdomain_query_counter[q] += 1

    return {
        "tool": "dns_summarize",
        "log_path": dns_log_path,
        "row_count": len(rows),
        "top_queries": [{"query": q, "count": c} for q, c in query_counter.most_common(k)],
        "top_qtypes": [{"qtype": t, "count": c} for t, c in qtype_counter.most_common(k)],
        "nxdomain_count": nxdomain_count,
        "nxdomain_top": [{"query": q, "count": c} for q, c in nxdomain_query_counter.most_common(k)],
        "unique_resolvers": len(resolvers),
    }


_PE_LIKE_SUFFIXES: tuple[str, ...] = (".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".jar")
_PE_EXT_CAP = 50


def http_ua_profile(
    http_log_path: str,
    *,
    k: int = 20,
) -> dict[str, Any]:
    """Profile http.log: top UAs, method distribution, status distribution, top hosts/URIs,
    and URIs whose path ends in a PE-like suffix.
    """
    _ = assert_input_path(http_log_path)
    parsed = zeek_log_read(http_log_path)
    rows = parsed["rows"]
    if not rows:
        return {
            "tool": "http_ua_profile",
            "log_path": http_log_path,
            "row_count": 0,
            "top_user_agents": [],
            "method_distribution": {},
            "status_code_distribution": {},
            "top_hosts": [],
            "top_uris": [],
            "external_uris_with_pe_extension": [],
        }

    ua_counter: Counter[str] = Counter()
    method_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    host_counter: Counter[str] = Counter()
    uri_counter: Counter[str] = Counter()
    pe_hits: list[dict[str, str]] = []

    for r in rows:
        ua = r.get("user_agent") or ""
        if ua and ua != "-":
            ua_counter[ua] += 1
        method = r.get("method") or ""
        if method and method != "-":
            method_counter[method] += 1
        status = r.get("status_code") or ""
        if status and status != "-":
            status_counter[status] += 1
        host = r.get("host") or ""
        uri = r.get("uri") or ""
        if host and host != "-":
            host_counter[host] += 1
        if uri and uri != "-":
            uri_counter[uri] += 1
            uri_lower = uri.lower().split("?", 1)[0]
            if uri_lower.endswith(_PE_LIKE_SUFFIXES) and len(pe_hits) < _PE_EXT_CAP:
                pe_hits.append({"host": host, "uri": uri})

    return {
        "tool": "http_ua_profile",
        "log_path": http_log_path,
        "row_count": len(rows),
        "top_user_agents": [{"user_agent": u, "count": c} for u, c in ua_counter.most_common(k)],
        "method_distribution": dict(method_counter),
        "status_code_distribution": dict(status_counter),
        "top_hosts": [{"host": h, "count": c} for h, c in host_counter.most_common(k)],
        "top_uris": [{"uri": u, "count": c} for u, c in uri_counter.most_common(k)],
        "external_uris_with_pe_extension": pe_hits,
    }
