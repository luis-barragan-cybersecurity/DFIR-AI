"""Boundary tests for the EZ Tools wrappers.

Real execution requires dotnet runtime + EZ Tools DLLs, neither guaranteed
in CI. We test the availability probe + missing-runtime path.
"""
from __future__ import annotations

import pytest

from protocol_sift_mcp.tools.win_artifacts import (
    EzToolsError,
    EzToolsUnavailable,
    ez_tools_available,
    evtxecmd,
)


def test_availability_probe_returns_structured_result():
    r = ez_tools_available()
    assert "available" in r
    assert isinstance(r["available"], bool)


def test_evtxecmd_reports_unavailable_without_dotnet(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: None)
    (tmp_path / "input" / "test.evtx").write_bytes(b"\x00")
    with pytest.raises(EzToolsUnavailable, match="dotnet runtime not on PATH"):
        evtxecmd(str(tmp_path / "input" / "test.evtx"), str(tmp_path / "output"))


def test_ez_tools_error_hierarchy():
    assert issubclass(EzToolsUnavailable, EzToolsError)
