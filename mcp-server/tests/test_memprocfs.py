"""Boundary tests for the MemProcFS FindEvil wrapper."""
from __future__ import annotations

import pytest

from protocol_sift_mcp.tools.memory import MemProcFSError, memprocfs_findevil


def test_missing_binary_yields_install_hint(tmp_path, monkeypatch):
    img = tmp_path / "input" / "mem.raw"
    img.write_bytes(b"\x00" * 1024)
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(MemProcFSError, match="memprocfs binary not on PATH"):
        memprocfs_findevil(str(img))


def test_path_must_be_under_evidence_root(tmp_path):
    """An out-of-sandbox path is refused regardless of memprocfs presence."""
    other = tmp_path / "elsewhere.raw"
    other.write_bytes(b"\x00")
    from protocol_sift_mcp.sandbox import SandboxViolation
    with pytest.raises(SandboxViolation):
        memprocfs_findevil(str(other))
