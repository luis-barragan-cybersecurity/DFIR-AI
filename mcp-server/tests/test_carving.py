"""Tests for carving + strings wrappers.

bulk_extractor and binwalk require the binaries; strings_extract is pure-
Python and gets exercised end-to-end.
"""
from __future__ import annotations

import pytest

from protocol_sift_mcp.tools.carving import (
    CarvingError,
    binwalk,
    bulk_extractor,
    strings_extract,
)


# ─── strings_extract (no external binary) ────────────────────────────────────


def test_strings_extract_pulls_ascii(tmp_path):
    target = tmp_path / "input" / "blob.bin"
    target.write_bytes(b"\x00\x01hello world\x00\xff\xfeanother string here\x00")
    r = strings_extract(str(target), min_length=5)
    strings = [s["ascii"] for s in r["strings"]]
    assert "hello world" in strings
    assert "another string here" in strings


def test_strings_extract_respects_min_length(tmp_path):
    target = tmp_path / "input" / "x.bin"
    target.write_bytes(b"\x00hi\x00toolong-enough\x00")
    r = strings_extract(str(target), min_length=8)
    assert all(s["length"] >= 8 for s in r["strings"])
    assert "hi" not in [s["ascii"] for s in r["strings"]]


def test_strings_extract_caps_max(tmp_path):
    target = tmp_path / "input" / "x.bin"
    payload = b"\x00".join([f"chunk{i:04d}".encode() for i in range(200)])
    target.write_bytes(payload)
    r = strings_extract(str(target), min_length=4, max_strings=20)
    assert r["string_count"] == 20
    assert r["truncated"] is True


def test_strings_extract_records_offsets_in_order(tmp_path):
    target = tmp_path / "input" / "x.bin"
    target.write_bytes(b"first_string\x00\x00second_string\x00")
    r = strings_extract(str(target), min_length=5)
    offsets = [s["offset"] for s in r["strings"]]
    assert offsets == sorted(offsets)


# ─── bulk_extractor / binwalk — binary missing path ──────────────────────────


def test_bulk_extractor_missing_binary(tmp_path, monkeypatch):
    img = tmp_path / "input" / "img.bin"
    img.write_bytes(b"\x00")
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(CarvingError, match="bulk_extractor"):
        bulk_extractor(str(img), str(tmp_path / "output" / "be"))


def test_binwalk_missing_binary(tmp_path, monkeypatch):
    target = tmp_path / "input" / "blob.bin"
    target.write_bytes(b"\x00")
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(CarvingError, match="binwalk"):
        binwalk(str(target))
