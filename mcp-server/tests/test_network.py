"""Tests for tshark + zeek log wrappers."""
from __future__ import annotations

import pytest

from protocol_sift_mcp.tools.network import (
    TsharkError,
    ZeekLogError,
    _validate_filter,
    tshark_extract,
    zeek_log_read,
)


# ─── Display-filter validation ───────────────────────────────────────────────


def test_validate_filter_allows_simple():
    _validate_filter("http.host == \"example.com\"")  # should not raise


def test_validate_filter_rejects_shell_metacharacters():
    for bad in (";", "|", "&", "$", "`", "\n", "\\"):
        with pytest.raises(TsharkError, match="forbidden char"):
            _validate_filter(f"http {bad} evil")


def test_validate_filter_rejects_overlong():
    with pytest.raises(TsharkError, match="too long"):
        _validate_filter("x" * 2000)


# ─── Sandbox + missing-binary plumbing ───────────────────────────────────────


def test_tshark_missing_binary_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    pcap = tmp_path / "input" / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    with pytest.raises(TsharkError, match="not found on PATH"):
        tshark_extract(str(pcap))


# ─── Zeek TSV reader ─────────────────────────────────────────────────────────


def test_zeek_log_read_parses_fields_header(tmp_path):
    log = tmp_path / "input" / "conn.log"
    log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\n"
        "#types\ttime\tstring\taddr\taddr\n"
        "1600000000.0\tCabc\t10.0.0.1\t8.8.8.8\n"
        "1600000010.0\tCdef\t10.0.0.2\t1.1.1.1\n"
    )
    r = zeek_log_read(str(log))
    assert r["fields"] == ["ts", "uid", "id.orig_h", "id.resp_h"]
    assert r["row_count"] == 2
    assert r["rows"][0]["id.orig_h"] == "10.0.0.1"


def test_zeek_log_read_rejects_data_before_fields(tmp_path):
    log = tmp_path / "input" / "broken.log"
    log.write_text("1600000000\tCabc\n")
    with pytest.raises(ZeekLogError, match="before #fields"):
        zeek_log_read(str(log))


def test_zeek_log_read_caps_at_max_rows(tmp_path):
    log = tmp_path / "input" / "big.log"
    lines = ["#fields\ta\tb"]
    for i in range(100):
        lines.append(f"{i}\tx")
    log.write_text("\n".join(lines) + "\n")
    r = zeek_log_read(str(log), max_rows=10)
    assert r["row_count"] == 10
