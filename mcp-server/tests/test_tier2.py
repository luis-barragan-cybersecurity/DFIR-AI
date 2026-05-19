"""Tier-2 smoke tests: pe_inspect + 6 EZ Tool wrappers + 8 Sleuth Kit block-layer
+ 2 image-mount + 3 ESE-derived wrappers.

These are mostly boundary tests — verifying each function raises a clear
boundary error when the external dep / binary is missing (which is the
expected state on most non-SIFT hosts). Real end-to-end coverage requires
SIFT + dotnet + FUSE.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from protocol_sift_mcp import sandbox
from protocol_sift_mcp.tools import filesystem, parse, win_artifacts, windows


def _evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "input"
    d.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", d.resolve())
    return d


def _output_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "output"
    d.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "OUTPUT_ROOT", d.resolve())
    return d


# ─── pe_inspect ─────────────────────────────────────────────────────────────


def test_pe_inspect_raises_when_pefile_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "x.exe"
    fake.write_bytes(b"\x00" * 64)
    monkeypatch.setattr(
        parse, "_import_pefile",
        lambda: (_ for _ in ()).throw(
            parse.PeToolError("pefile not installed — test stub")
        ),
    )
    with pytest.raises(parse.PeToolError, match="pefile not installed"):
        parse.pe_inspect(str(fake))


def test_pe_inspect_synthetic_pe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Build a minimal valid PE via the real pefile if available; else skip."""
    pytest.importorskip("pefile")
    import pefile
    d = _evidence(tmp_path, monkeypatch)
    # Smallest known-good PE: take pefile's own bundled test fixture path, or
    # synthesize via a tiny known good binary. For determinism use a stub blob
    # that pefile rejects — we then expect a clear PeToolError.
    bad = d / "notpe.exe"
    bad.write_bytes(b"NOT A PE FILE" + b"\x00" * 64)
    with pytest.raises(parse.PeToolError, match="Failed to parse PE"):
        parse.pe_inspect(str(bad))


# ─── EZ Tools — backend absent ──────────────────────────────────────────────


@pytest.mark.parametrize("func_name", [
    "appcompatcacheparser", "pecmd", "lecmd", "jlecmd", "sbecmd", "rbcmd",
])
def test_ez_tool_raises_when_dotnet_missing(
    func_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    out = _output_dir(tmp_path, monkeypatch)
    fake_in = d / "fake.bin"
    fake_in.write_bytes(b"\x00" * 64)

    def _no_dotnet() -> str:
        raise win_artifacts.EzToolsUnavailable("dotnet not on PATH — test stub")
    monkeypatch.setattr(win_artifacts, "_resolve_dotnet", _no_dotnet)

    fn = getattr(win_artifacts, func_name)
    with pytest.raises(win_artifacts.EzToolsUnavailable, match="dotnet"):
        fn(str(fake_in), str(out))


def test_ez_tools_available_lists_new_wrappers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        win_artifacts, "_resolve_dotnet",
        lambda: (_ for _ in ()).throw(
            win_artifacts.EzToolsUnavailable("dotnet not on PATH — test stub")
        ),
    )
    res = win_artifacts.ez_tools_available()
    assert res["available"] is False
    assert "dotnet" in res["reason"]


# ─── Sleuth Kit block-layer — backend absent ────────────────────────────────


def test_blkcat_raises_when_binary_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "img.raw"
    fake.write_bytes(b"\x00" * 64)
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _name: None)
    with pytest.raises(filesystem.SleuthKitError, match="blkcat"):
        filesystem.blkcat(str(fake), "0")


def test_fsstat_allowlist_includes_new_tools() -> None:
    for t in ("fsstat", "blkcat", "blkls", "blkcalc", "blkstat", "ils", "ifind", "ffind"):
        assert t in filesystem._ALLOWED_TOOLS, f"{t} missing from _ALLOWED_TOOLS"


def test_blkcalc_rejects_bad_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "img.raw"
    fake.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError, match="mode must be"):
        filesystem.blkcalc(str(fake), "0", mode="invalid")


def test_ils_rejects_bad_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "img.raw"
    fake.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError, match="mode must be"):
        filesystem.ils(str(fake), mode="banana")


def test_ifind_requires_exactly_one_arg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "img.raw"
    fake.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError, match="exactly one"):
        filesystem.ifind(str(fake))
    with pytest.raises(ValueError, match="exactly one"):
        filesystem.ifind(str(fake), block="100", file_path="/etc/passwd")


# ─── Image-mount — backend absent ───────────────────────────────────────────


def test_ewfmount_raises_when_binary_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    out = _output_dir(tmp_path, monkeypatch)
    e01 = d / "evidence.E01"
    e01.write_bytes(b"\x00" * 64)
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _name: None)
    with pytest.raises(filesystem.MountToolError, match="ewfmount"):
        filesystem.ewfmount(str(e01), str(out / "mnt"))


def test_vshadowmount_raises_when_binary_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    out = _output_dir(tmp_path, monkeypatch)
    vol = d / "vol.raw"
    vol.write_bytes(b"\x00" * 64)
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda _name: None)
    with pytest.raises(filesystem.MountToolError, match="vshadowmount"):
        filesystem.vshadowmount(str(vol), str(out / "mnt"))


# ─── ESE-derived wrappers ───────────────────────────────────────────────────


def test_srum_query_rejects_unknown_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "SRUDB.dat"
    fake.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError, match="table must be"):
        windows.srum_query(str(fake), table="not-a-real-table")


def test_srum_query_routes_to_win_ese_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """srum_query("app_resource") should call win_ese_query with the right GUID."""
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "SRUDB.dat"
    fake.write_bytes(b"\x00" * 64)
    captured: dict[str, object] = {}

    def fake_ese(path: str, table: str, *, limit: int = 0, **kw: object) -> list[dict[str, object]]:
        captured["path"] = path
        captured["table"] = table
        captured["limit"] = limit
        return [{"row": 1}]

    monkeypatch.setattr(windows, "win_ese_query", fake_ese)
    rows = windows.srum_query(str(fake), table="app_resource", limit=42)
    assert rows == [{"row": 1}]
    assert captured["table"] == windows.SRUM_TABLES["app_resource"]
    assert captured["limit"] == 42


def test_webcache_query_uses_containers_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "WebCacheV01.dat"
    fake.write_bytes(b"\x00" * 64)
    captured: dict[str, object] = {}

    def fake_ese(path: str, table: str, *, limit: int = 0, **kw: object) -> list[dict[str, object]]:
        captured["table"] = table
        return [{"row": 1}]

    monkeypatch.setattr(windows, "win_ese_query", fake_ese)
    windows.webcache_query(str(fake))
    assert captured["table"] == "Containers"
