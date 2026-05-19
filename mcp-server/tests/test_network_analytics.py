"""Tests for Phase 3a Group D — pure-Python analytics over Zeek logs.

Synthesizes conn/dns/http logs inline using the Zeek TSV `#fields\\t...` header
pattern. No subprocess dependencies — purely tests the analytic logic.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from protocol_sift_mcp.tools.network_analytics import (
    NetworkAnalyticsError,
    _interval_entropy,
    beacon_score,
    conn_top_talkers,
    dns_summarize,
    http_ua_profile,
)

# ─── helpers ─────────────────────────────────────────────────────────────────


def _write_conn_log(p: Path, rows: list[dict[str, str]]) -> Path:
    """Synthesize a Zeek-style conn.log with the standard column set we test against."""
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
              "proto", "duration", "orig_bytes", "resp_bytes"]
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["#separator \\x09", "#fields\t" + "\t".join(fields)]
    for r in rows:
        lines.append("\t".join(r.get(f, "-") for f in fields))
    p.write_text("\n".join(lines) + "\n")
    return p


def _write_dns_log(p: Path, rows: list[dict[str, str]]) -> Path:
    fields = ["ts", "uid", "id.orig_h", "id.resp_h", "query", "qtype", "qtype_name",
              "rcode", "rcode_name"]
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["#fields\t" + "\t".join(fields)]
    for r in rows:
        lines.append("\t".join(r.get(f, "-") for f in fields))
    p.write_text("\n".join(lines) + "\n")
    return p


def _write_http_log(p: Path, rows: list[dict[str, str]]) -> Path:
    fields = ["ts", "uid", "id.orig_h", "id.resp_h", "method", "host", "uri",
              "user_agent", "status_code"]
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["#fields\t" + "\t".join(fields)]
    for r in rows:
        lines.append("\t".join(r.get(f, "-") for f in fields))
    p.write_text("\n".join(lines) + "\n")
    return p


# ─── beacon_score ────────────────────────────────────────────────────────────


def test_beacon_score_detects_periodic_traffic(tmp_path):
    rows = []
    for i in range(50):
        rows.append({
            "ts": str(1700000000 + i * 60),
            "uid": f"C{i}",
            "id.orig_h": "10.0.0.5",
            "id.orig_p": "40000",
            "id.resp_h": "1.2.3.4",
            "id.resp_p": "443",
            "proto": "tcp",
            "duration": "0.5",
            "orig_bytes": "120",
            "resp_bytes": "300",
        })
    for i in range(5):
        rows.append({
            "ts": str(1700001000 + i * 1837),
            "uid": f"R{i}",
            "id.orig_h": "10.0.0.5",
            "id.orig_p": "40001",
            "id.resp_h": f"5.6.7.{i}",
            "id.resp_p": "80",
            "proto": "tcp",
            "duration": "1.0",
            "orig_bytes": "500",
            "resp_bytes": "1000",
        })
    log = _write_conn_log(tmp_path / "input" / "conn.log", rows)
    r = beacon_score(str(log))
    assert r["candidates_examined"] >= 1
    top = r["candidates"][0]
    assert top["dst"] == "1.2.3.4"
    assert top["dst_port"] == "443"
    assert top["connection_count"] == 50
    assert top["coefficient_of_variation"] < 0.1
    assert top["score"] > 0.8


def test_beacon_score_skips_short_streams(tmp_path):
    rows = [
        {"ts": str(1700000000 + i * 60), "uid": f"C{i}",
         "id.orig_h": "10.0.0.5", "id.orig_p": "40000",
         "id.resp_h": "1.2.3.4", "id.resp_p": "443",
         "proto": "tcp", "duration": "0.5", "orig_bytes": "100", "resp_bytes": "100"}
        for i in range(5)
    ]
    log = _write_conn_log(tmp_path / "input" / "conn.log", rows)
    r = beacon_score(str(log), min_connections=8)
    assert r["candidates"] == []


def test_beacon_score_dst_filter_excludes_non_matching(tmp_path):
    rows = []
    for i in range(20):
        rows.append({
            "ts": str(1700000000 + i * 60), "uid": f"C{i}",
            "id.orig_h": "10.0.0.5", "id.orig_p": "40000",
            "id.resp_h": "1.2.3.4", "id.resp_p": "443",
            "proto": "tcp", "duration": "0.5", "orig_bytes": "100", "resp_bytes": "100",
        })
    for i in range(20):
        rows.append({
            "ts": str(1700000000 + i * 60), "uid": f"D{i}",
            "id.orig_h": "10.0.0.5", "id.orig_p": "40001",
            "id.resp_h": "9.9.9.9", "id.resp_p": "443",
            "proto": "tcp", "duration": "0.5", "orig_bytes": "100", "resp_bytes": "100",
        })
    log = _write_conn_log(tmp_path / "input" / "conn.log", rows)
    r = beacon_score(str(log), dst_filter="1.2.3.")
    assert all(c["dst"].startswith("1.2.3.") for c in r["candidates"])
    assert len(r["candidates"]) == 1


def test_beacon_score_returns_empty_for_empty_log(tmp_path):
    log = _write_conn_log(tmp_path / "input" / "conn.log", [])
    r = beacon_score(str(log))
    assert r["candidates"] == []
    assert r["candidates_examined"] == 0


def test_interval_entropy_zero_for_constant_intervals():
    assert _interval_entropy([60.0] * 50) == 0.0


def test_interval_entropy_higher_for_random_intervals():
    constant = _interval_entropy([60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0])
    spread = _interval_entropy([1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0])
    assert spread > constant


# ─── conn_top_talkers ────────────────────────────────────────────────────────


def test_conn_top_talkers_by_bytes(tmp_path):
    rows = [
        {"ts": "1700000000", "uid": "C1", "id.orig_h": "10.0.0.1", "id.orig_p": "1",
         "id.resp_h": "1.1.1.1", "id.resp_p": "443", "proto": "tcp",
         "duration": "1.0", "orig_bytes": "1000", "resp_bytes": "2000"},
        {"ts": "1700000010", "uid": "C2", "id.orig_h": "10.0.0.1", "id.orig_p": "2",
         "id.resp_h": "1.1.1.1", "id.resp_p": "443", "proto": "tcp",
         "duration": "1.0", "orig_bytes": "500", "resp_bytes": "500"},
        {"ts": "1700000020", "uid": "C3", "id.orig_h": "10.0.0.2", "id.orig_p": "1",
         "id.resp_h": "8.8.8.8", "id.resp_p": "53", "proto": "udp",
         "duration": "0.1", "orig_bytes": "100", "resp_bytes": "200"},
    ]
    log = _write_conn_log(tmp_path / "input" / "conn.log", rows)
    r = conn_top_talkers(str(log), k=2, by="bytes")
    assert r["pairs"][0]["src"] == "10.0.0.1"
    assert r["pairs"][0]["dst"] == "1.1.1.1"
    assert r["pairs"][0]["bytes"] == 4000
    assert r["pairs"][0]["connections"] == 2


def test_conn_top_talkers_by_connections(tmp_path):
    rows = [
        {"ts": "0", "uid": "C1", "id.orig_h": "a", "id.orig_p": "1",
         "id.resp_h": "x", "id.resp_p": "1", "proto": "tcp",
         "duration": "1", "orig_bytes": "10", "resp_bytes": "10"},
        {"ts": "0", "uid": "C2", "id.orig_h": "a", "id.orig_p": "2",
         "id.resp_h": "x", "id.resp_p": "1", "proto": "tcp",
         "duration": "1", "orig_bytes": "10", "resp_bytes": "10"},
        {"ts": "0", "uid": "C3", "id.orig_h": "b", "id.orig_p": "1",
         "id.resp_h": "y", "id.resp_p": "1", "proto": "tcp",
         "duration": "100", "orig_bytes": "1", "resp_bytes": "1"},
    ]
    log = _write_conn_log(tmp_path / "input" / "conn.log", rows)
    r = conn_top_talkers(str(log), by="connections")
    assert r["pairs"][0]["src"] == "a"
    assert r["pairs"][0]["connections"] == 2


def test_conn_top_talkers_rejects_bad_by(tmp_path):
    log = _write_conn_log(tmp_path / "input" / "conn.log", [])
    with pytest.raises(ValueError, match="not in"):
        conn_top_talkers(str(log), by="rainbows")


# ─── dns_summarize ───────────────────────────────────────────────────────────


def test_dns_summarize_counts_top_queries(tmp_path):
    rows = (
        [{"ts": "0", "uid": "D", "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
          "query": "good.example.com", "qtype": "1", "qtype_name": "A",
          "rcode": "0", "rcode_name": "NOERROR"}] * 30
        + [{"ts": "0", "uid": "D", "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
            "query": "less.example.com", "qtype": "1", "qtype_name": "A",
            "rcode": "0", "rcode_name": "NOERROR"}] * 5
    )
    log = _write_dns_log(tmp_path / "input" / "dns.log", rows)
    r = dns_summarize(str(log))
    assert r["top_queries"][0]["query"] == "good.example.com"
    assert r["top_queries"][0]["count"] == 30
    assert r["unique_resolvers"] == 1


def test_dns_summarize_counts_nxdomain(tmp_path):
    rows = (
        [{"ts": "0", "uid": "D", "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
          "query": "ok.example.com", "qtype": "1", "qtype_name": "A",
          "rcode": "0", "rcode_name": "NOERROR"}] * 10
        + [{"ts": "0", "uid": "D", "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
            "query": "deadbeef-abc-xyz.com", "qtype": "1", "qtype_name": "A",
            "rcode": "3", "rcode_name": "NXDOMAIN"}] * 7
    )
    log = _write_dns_log(tmp_path / "input" / "dns.log", rows)
    r = dns_summarize(str(log))
    assert r["nxdomain_count"] == 7
    assert r["nxdomain_top"][0]["query"] == "deadbeef-abc-xyz.com"
    assert r["nxdomain_top"][0]["count"] == 7


# ─── http_ua_profile ─────────────────────────────────────────────────────────


def test_http_ua_profile_method_and_status_distribution(tmp_path):
    rows = (
        [{"ts": "0", "uid": "H", "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1",
          "method": "GET", "host": "example.com", "uri": "/", "user_agent": "Mozilla/5.0",
          "status_code": "200"}] * 5
        + [{"ts": "0", "uid": "H", "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1",
            "method": "POST", "host": "example.com", "uri": "/api", "user_agent": "Mozilla/5.0",
            "status_code": "404"}] * 2
    )
    log = _write_http_log(tmp_path / "input" / "http.log", rows)
    r = http_ua_profile(str(log))
    assert r["method_distribution"] == {"GET": 5, "POST": 2}
    assert r["status_code_distribution"] == {"200": 5, "404": 2}
    assert r["top_user_agents"][0]["user_agent"] == "Mozilla/5.0"


def test_http_ua_profile_flags_pe_extensions(tmp_path):
    rows = [
        {"ts": "0", "uid": "H1", "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1",
         "method": "GET", "host": "evil.example", "uri": "/payload.exe",
         "user_agent": "curl/8.0", "status_code": "200"},
        {"ts": "0", "uid": "H2", "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1",
         "method": "GET", "host": "evil.example", "uri": "/Stage2.DLL",
         "user_agent": "curl/8.0", "status_code": "200"},
        {"ts": "0", "uid": "H3", "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1",
         "method": "GET", "host": "cdn.example", "uri": "/assets/main.css?v=1",
         "user_agent": "Mozilla", "status_code": "200"},
    ]
    log = _write_http_log(tmp_path / "input" / "http.log", rows)
    r = http_ua_profile(str(log))
    flagged_uris = [h["uri"] for h in r["external_uris_with_pe_extension"]]
    assert "/payload.exe" in flagged_uris
    assert "/Stage2.DLL" in flagged_uris
    assert "/assets/main.css?v=1" not in flagged_uris


def test_http_ua_profile_empty_log(tmp_path):
    log = _write_http_log(tmp_path / "input" / "http.log", [])
    r = http_ua_profile(str(log))
    assert r["row_count"] == 0
    assert r["top_user_agents"] == []


# ─── error class smoke ──────────────────────────────────────────────────────


def test_network_analytics_error_is_exception():
    assert issubclass(NetworkAnalyticsError, Exception)
