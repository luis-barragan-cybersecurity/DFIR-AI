"""Tests for Sleuth Kit subprocess wrappers.

Skips when the binary isn't installed — Sleuth Kit is a SIFT/Linux baseline,
not guaranteed on the test host.
"""
from __future__ import annotations

import shutil

import pytest

from protocol_sift_mcp.tools.filesystem import (
    SleuthKitError,
    _parse_fls,
    _parse_mactime,
    _parse_mmls,
    tsk_run,
)

_HAVE_FLS = shutil.which("fls") is not None


# ─── Pure-function parser tests (always run) ────────────────────────────────


def test_parse_fls_basic_rows():
    text = "d/d 256:   home\nr/r 257:   passwd\n"
    rows = _parse_fls(text)
    assert rows[0]["type"] == "d/d"
    assert rows[0]["inode"] == "256"
    assert rows[0]["name"] == "home"
    assert rows[1]["name"] == "passwd"


def test_parse_fls_empty():
    assert _parse_fls("") == []


def test_parse_mmls_picks_numbered_partition_rows():
    text = (
        "GUID Partition Table (EFI)\n"
        "Offset Sector: 0\n"
        "Units are in 512-byte sectors\n"
        "\n"
        "      Slot      Start        End          Length       Description\n"
        "001:  -------   0000000000   0000000000   0000000001   Primary Table\n"
        "002:  00:00     0000000001   0000204799   0000204799   Linux (0x83)\n"
    )
    rows = _parse_mmls(text)
    descs = " ".join(r.get("description", "") for r in rows)
    assert "Linux" in descs


def test_parse_mactime_csv():
    text = (
        "Date,Size,Type,Mode,UID,GID,Meta,File Name\n"
        "2020-11-14T03:42:50Z,4096,m...,d/drwxr-xr-x,0,0,2,/var/log\n"
    )
    rows = _parse_mactime(text)
    assert rows[0]["ts"] == "2020-11-14T03:42:50Z"
    assert rows[0]["path"] == "/var/log"


# ─── Boundary tests for allowlist (no binary required) ───────────────────────


def test_tsk_run_rejects_unknown_tool(tmp_path):
    img = tmp_path / "input" / "img.dd"
    img.write_bytes(b"\x00")
    with pytest.raises(ValueError, match="not in allowlist"):
        tsk_run("rm", str(img))


def test_tsk_run_sandbox_violation(tmp_path):
    # Drop a file OUTSIDE EVIDENCE_PATH (which is tmp_path/input).
    img = tmp_path / "elsewhere.dd"
    img.write_bytes(b"\x00")
    from protocol_sift_mcp.sandbox import SandboxViolation
    with pytest.raises(SandboxViolation):
        tsk_run("fls", str(img))


@pytest.mark.skipif(not _HAVE_FLS, reason="fls (sleuthkit) not installed on test host")
def test_tsk_fls_against_tiny_blob(tmp_path):
    img = tmp_path / "input" / "tiny.dd"
    img.write_bytes(b"\x00" * 16)
    with pytest.raises(SleuthKitError):
        tsk_run("fls", str(img))


def test_sleuthkit_error_message_includes_install_hint(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    img = tmp_path / "input" / "img.dd"
    img.write_bytes(b"\x00")
    with pytest.raises(SleuthKitError, match="apt install sleuthkit"):
        tsk_run("fls", str(img))
