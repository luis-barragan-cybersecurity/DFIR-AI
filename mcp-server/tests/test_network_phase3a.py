"""Tests for Phase 3a network forensics wrappers.

Groups A (pcap distillation), B (pcap manipulation), C (NetFlow query) — all
subprocess wrappers, so tests use `monkeypatch` against `shutil.which` (missing-
binary path) and `subprocess.run` (happy-path with fabricated CompletedProcess).
"""
from __future__ import annotations

import subprocess
import types
from pathlib import Path

import pytest

from protocol_sift_mcp.tools import network as net
from protocol_sift_mcp.tools.network import (
    NetFlowError,
    PcapToolError,
    _parse_nfdump_csv,
    _validate_bpf,
    _validate_editcap_ts,
    nfdump_query,
    pcap_filter_bpf,
    pcap_info,
    pcap_merge,
    pcap_slice_time,
    pcap_to_netflow,
    pcap_to_passivedns,
    pcap_to_zeek,
    tcp_reassemble,
)


def _fake_run(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a stub subprocess.run that returns a fabricated CompletedProcess."""
    def _runner(cmd, **kwargs):  # noqa: ARG001 — matches subprocess.run signature
        return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)
    return _runner


def _touch(p: Path, content: bytes = b"\xd4\xc3\xb2\xa1") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


def _which(mapping: dict[str, str | None]):
    def _w(name):
        return mapping.get(name, "/usr/bin/" + name)
    return _w


# ─── Validators ──────────────────────────────────────────────────────────────


def test_validate_bpf_allows_common_filters():
    _validate_bpf("tcp port 443")
    _validate_bpf("host 10.0.0.1 and not port 22")


def test_validate_bpf_rejects_shell_metacharacters():
    for bad in (";", "|", "&", "$", "`", "\n", "\\", ">", "<"):
        with pytest.raises(PcapToolError, match="forbidden char"):
            _validate_bpf(f"tcp {bad} port 80")


def test_validate_bpf_rejects_overlong():
    with pytest.raises(PcapToolError, match="too long"):
        _validate_bpf("x" * 2000)


def test_validate_bpf_rejects_leading_dash_argument_injection():
    """Per advisor finding: leading-`-` would be parsed as a CLI flag by tcpdump/nfdump
    if it slipped through, defeating argv-list-passing. Reject at the boundary."""
    for hostile in ("-w/etc/passwd", "--config=/dev/null", "-r/dev/tty"):
        with pytest.raises(PcapToolError, match="may not start with"):
            _validate_bpf(hostile)


def test_validate_editcap_ts_accepts_iso_with_t():
    assert _validate_editcap_ts("2024-01-15T12:30:45") == "2024-01-15 12:30:45"


def test_validate_editcap_ts_accepts_space_form():
    assert _validate_editcap_ts("2024-01-15 12:30:45") == "2024-01-15 12:30:45"


def test_validate_editcap_ts_rejects_garbage():
    with pytest.raises(PcapToolError, match="not in ISO format"):
        _validate_editcap_ts("yesterday")


# ─── Group A — Pcap distillation ─────────────────────────────────────────────


def test_pcap_to_zeek_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({"zeek": None}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "zeek"
    with pytest.raises(PcapToolError, match="zeek not found"):
        pcap_to_zeek(str(pcap), str(out))


def test_pcap_to_zeek_happy_path_lists_log_files(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="", stderr="zeek finished"))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "zeek"
    out.mkdir(parents=True, exist_ok=True)
    (out / "conn.log").write_text("#fields\tts\n0\n")
    (out / "dns.log").write_text("#fields\tts\n0\n")
    r = pcap_to_zeek(str(pcap), str(out))
    assert r["tool"] == "pcap_to_zeek"
    assert sorted(Path(p).name for p in r["log_files"]) == ["conn.log", "dns.log"]
    assert r["logs_dir"] == str(out.resolve())


def test_pcap_to_netflow_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({"nfpcapd": None}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "nf"
    with pytest.raises(PcapToolError, match="nfpcapd not found"):
        pcap_to_netflow(str(pcap), str(out))


def test_pcap_to_netflow_happy_path_collects_nfcapd_files(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="", stderr=""))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "nf"
    out.mkdir(parents=True, exist_ok=True)
    (out / "nfcapd.202401151200").write_bytes(b"\x00")
    (out / "nfcapd.202401151205").write_bytes(b"\x00")
    (out / "ignore.txt").write_bytes(b"x")
    r = pcap_to_netflow(str(pcap), str(out))
    assert r["tool"] == "pcap_to_netflow"
    assert len(r["netflow_files"]) == 2
    assert all("nfcapd." in p for p in r["netflow_files"])


def test_pcap_to_passivedns_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({"passivedns": None}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "pdns"
    with pytest.raises(PcapToolError, match="passivedns not found"):
        pcap_to_passivedns(str(pcap), str(out))


def test_pcap_to_passivedns_happy_path_returns_log_path(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="", stderr="ok"))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "pdns"
    out.mkdir(parents=True, exist_ok=True)
    (out / "passivedns.log").write_text("1700000000\t10.0.0.1\texample.com\tA\t1.2.3.4\n")
    r = pcap_to_passivedns(str(pcap), str(out))
    assert r["passivedns_log"].endswith("passivedns.log")
    assert r["exists"] is True
    assert r["size_bytes"] > 0


# ─── Group B — Pcap manipulation ─────────────────────────────────────────────


def test_pcap_info_parses_key_value_lines(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    fake = (
        "File name:           x.pcap\n"
        "File type:           Wireshark/tcpdump/... - pcap\n"
        "Number of packets:   12345\n"
        "Data byte rate:      1.2 Mbps\n"
    )
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=fake, stderr=""))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    r = pcap_info(str(pcap))
    assert r["tool"] == "pcap_info"
    assert r["summary"]["File name"] == "x.pcap"
    assert r["summary"]["Number of packets"] == "12345"
    assert len(r["summary"]) >= 3


def test_pcap_info_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({"capinfos": None}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    with pytest.raises(PcapToolError, match="capinfos not found"):
        pcap_info(str(pcap))


def test_pcap_slice_time_rejects_bad_timestamp(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "sliced.pcap"
    with pytest.raises(PcapToolError, match="not in ISO format"):
        pcap_slice_time(str(pcap), "noon", "midnight", str(out))


def test_pcap_slice_time_happy_path(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="", stderr=""))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "sliced.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\xd4\xc3\xb2\xa1xxxxxx")
    r = pcap_slice_time(str(pcap), "2024-01-15T00:00:00", "2024-01-15T01:00:00", str(out))
    assert r["start"] == "2024-01-15 00:00:00"
    assert r["end"] == "2024-01-15 01:00:00"
    assert r["exists"] is True


def test_pcap_merge_rejects_empty_list(tmp_path):
    out = tmp_path / "output" / "merged.pcap"
    with pytest.raises(ValueError, match="empty"):
        pcap_merge([], str(out))


def test_pcap_merge_happy_path_resolves_each_input(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    captured_cmd: list[list[str]] = []

    def cap_run(cmd, **kwargs):  # noqa: ARG001
        captured_cmd.append(list(cmd))
        return types.SimpleNamespace(stdout="", stderr="", returncode=0)
    monkeypatch.setattr(subprocess, "run", cap_run)
    p1 = _touch(tmp_path / "input" / "a.pcap")
    p2 = _touch(tmp_path / "input" / "b.pcap")
    out = tmp_path / "output" / "merged.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\xd4\xc3\xb2\xa1")
    r = pcap_merge([str(p1), str(p2)], str(out))
    assert r["tool"] == "pcap_merge"
    assert len(r["inputs"]) == 2
    assert "-w" in captured_cmd[0]
    assert str(out.resolve()) in captured_cmd[0]


def test_pcap_filter_bpf_rejects_metacharacters(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "f.pcap"
    with pytest.raises(PcapToolError, match="forbidden char"):
        pcap_filter_bpf(str(pcap), "tcp; rm -rf /", str(out))


def test_pcap_filter_bpf_happy_path(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="", stderr=""))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "f.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\xd4\xc3\xb2\xa1")
    r = pcap_filter_bpf(str(pcap), "tcp port 443", str(out))
    assert r["bpf"] == "tcp port 443"
    assert r["exists"] is True


def test_tcp_reassemble_happy_path(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="", stderr=""))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "flows"
    out.mkdir(parents=True, exist_ok=True)
    (out / "010.000.000.001.12345-008.008.008.008.00080").write_bytes(b"GET /")
    r = tcp_reassemble(str(pcap), str(out))
    assert r["flow_count"] == 1


def test_tcp_reassemble_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({"tcpflow": None}))
    pcap = _touch(tmp_path / "input" / "x.pcap")
    out = tmp_path / "output" / "flows"
    with pytest.raises(PcapToolError, match="tcpflow not found"):
        tcp_reassemble(str(pcap), str(out))


# ─── Group C — NetFlow query ─────────────────────────────────────────────────


def test_nfdump_query_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({"nfdump": None}))
    nf = _touch(tmp_path / "input" / "nfcapd.202401151200", content=b"\x00")
    with pytest.raises(NetFlowError, match="nfdump not found"):
        nfdump_query(str(nf))


def test_nfdump_query_rejects_bad_format(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    nf = _touch(tmp_path / "input" / "nfcapd.202401151200", content=b"\x00")
    with pytest.raises(NetFlowError, match="not in allowlist"):
        nfdump_query(str(nf), output_format="evil")


def test_nfdump_query_parses_csv_output(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    fake_csv = (
        "ts,te,sa,da,sp,dp,pr,pkt,byt\n"
        "1700000000,1700000010,10.0.0.1,8.8.8.8,40000,443,TCP,12,1500\n"
        "1700000010,1700000020,10.0.0.2,1.1.1.1,40001,53,UDP,2,200\n"
        "Summary: 2 flows\n"
    )
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=fake_csv, stderr=""))
    nf = _touch(tmp_path / "input" / "nfcapd.202401151200", content=b"\x00")
    r = nfdump_query(str(nf), output_format="csv")
    assert r["tool"] == "nfdump_query"
    assert r["rows"] is not None
    assert len(r["rows"]) == 2
    assert r["rows"][0]["sa"] == "10.0.0.1"
    assert r["rows"][1]["dp"] == "53"


def test_nfdump_query_passes_aggregation_and_filter(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", _which({}))
    captured: list[list[str]] = []

    def cap_run(cmd, **kwargs):  # noqa: ARG001
        captured.append(list(cmd))
        return types.SimpleNamespace(stdout="ts,te,sa,da\n", stderr="", returncode=0)
    monkeypatch.setattr(subprocess, "run", cap_run)
    nf = _touch(tmp_path / "input" / "nfcapd.202401151200", content=b"\x00")
    nfdump_query(str(nf), aggregation="srcip,dstip", bpf_filter="proto tcp", top_n=10)
    cmd = captured[0]
    assert "-A" in cmd
    assert "srcip,dstip" in cmd
    assert "-c" in cmd
    assert "10" in cmd
    assert "proto tcp" in cmd


def test_parse_nfdump_csv_skips_summary_block():
    out = (
        "ts,te,sa,da\n"
        "1700000000,1700000010,10.0.0.1,8.8.8.8\n"
        "Summary: 1 flow\n"
        "Total bytes: 1500\n"
    )
    rows = _parse_nfdump_csv(out)
    assert len(rows) == 1
    assert rows[0]["sa"] == "10.0.0.1"


# ─── Smoke: error classes are properly exported ──────────────────────────────


def test_error_classes_are_exported():
    assert issubclass(net.PcapToolError, Exception)
    assert issubclass(net.NetFlowError, Exception)
    assert net.PcapToolError is not net.NetFlowError
