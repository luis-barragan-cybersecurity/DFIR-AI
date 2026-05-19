"""Smoke tests for the 7 W2/W3 stubs that were promoted to real implementations.

Covers: sqlite_query, win_recyclebin_parse, win_shellbag_parse, win_ese_query,
mac_apfs_inspect, mac_spotlight_query, mac_tracev3_query.

Tests that can run without external binaries / hives use synthetic evidence
in tmp_path. Tests that require external tooling (fsstat, mdfind, log,
dissect.esedb) assert the boundary error fires with the install hint —
that's the contract we promise callers when the backend isn't present.
"""

from __future__ import annotations

import sqlite3
import struct
from pathlib import Path

import pytest

from protocol_sift_mcp import sandbox
from protocol_sift_mcp.tools import macos, parse, windows


def _evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "input"
    d.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", d.resolve())
    return d


# ─── sqlite_query ───────────────────────────────────────────────────────────


def test_sqlite_query_returns_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _evidence(tmp_path, monkeypatch)
    db = d / "history.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE urls (id INTEGER, url TEXT, visit_count INTEGER)")
    conn.execute("INSERT INTO urls VALUES (1, 'https://example.com', 7)")
    conn.execute("INSERT INTO urls VALUES (2, 'https://memoryhound.dev', 42)")
    conn.commit()
    conn.close()

    rows = parse.sqlite_query(str(db), "SELECT url, visit_count FROM urls ORDER BY id")
    assert rows == [
        {"url": "https://example.com", "visit_count": 7},
        {"url": "https://memoryhound.dev", "visit_count": 42},
    ]


def test_sqlite_query_rejects_non_select(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _evidence(tmp_path, monkeypatch)
    db = d / "x.sqlite"
    sqlite3.connect(str(db)).close()
    with pytest.raises(ValueError, match="SELECT"):
        parse.sqlite_query(str(db), "DELETE FROM foo")


def test_sqlite_query_with_cte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _evidence(tmp_path, monkeypatch)
    db = d / "cte.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE t (n INTEGER)")
    for n in range(1, 4):
        conn.execute("INSERT INTO t VALUES (?)", (n,))
    conn.commit()
    conn.close()

    rows = parse.sqlite_query(str(db), "WITH x AS (SELECT n FROM t) SELECT SUM(n) AS s FROM x")
    assert rows == [{"s": 6}]


def test_sqlite_query_coerces_blob_to_hex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _evidence(tmp_path, monkeypatch)
    db = d / "blob.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE b (data BLOB)")
    conn.execute("INSERT INTO b VALUES (?)", (b"\x00\xff\xab",))
    conn.commit()
    conn.close()

    rows = parse.sqlite_query(str(db), "SELECT data FROM b")
    assert rows == [{"data": "00ffab"}]


# ─── win_recyclebin_parse ──────────────────────────────────────────────────


def _make_i_file_v2(path: Path, *, name: str, size: int, ft: int) -> None:
    """Synthesize a Vista+ v2 $I header file."""
    name_utf16 = (name + "\x00").encode("utf-16-le")
    blob = (
        struct.pack("<Q", 2)                                  # version
        + struct.pack("<Q", size)                             # deleted file size
        + struct.pack("<Q", ft)                               # FILETIME
        + struct.pack("<I", len(name) + 1)                    # name length (chars, incl. null)
        + name_utf16
    )
    path.write_bytes(blob)


def test_recyclebin_parse_v2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _evidence(tmp_path, monkeypatch)
    rb = d / "$Recycle.Bin" / "S-1-5-21-FAKE"
    rb.mkdir(parents=True)
    # 2024-01-01 00:00:00 UTC in Windows FILETIME 100-ns ticks since 1601
    ft = (1704067200 + 11644473600) * 10_000_000
    _make_i_file_v2(rb / "$IABCDEF", name="C:\\Users\\hacker\\evidence.docx", size=4096, ft=ft)
    (rb / "$RABCDEF").write_bytes(b"recovered-bytes")  # paired data file

    rows = windows.win_recyclebin_parse(str(rb))
    assert len(rows) == 1
    row = rows[0]
    assert row["version"] == 2
    assert row["deleted_size"] == 4096
    assert row["original_name"] == "C:\\Users\\hacker\\evidence.docx"
    assert row["r_file_present"] is True
    assert row["deleted_at"] and row["deleted_at"].startswith("2024-01-01")


# ─── win_ese_query — backend absent ────────────────────────────────────────


def test_ese_query_raises_when_dissect_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If dissect.esedb is not installed we surface a clear EseToolError."""
    d = _evidence(tmp_path, monkeypatch)
    fake = d / "WebCacheV01.dat"
    fake.write_bytes(b"\x00" * 64)

    # Force the import helper to fail regardless of env.
    monkeypatch.setattr(
        windows, "_import_dissect_esedb",
        lambda: (_ for _ in ()).throw(
            windows.EseToolError("dissect.esedb not installed — test stub")
        ),
    )
    with pytest.raises(windows.EseToolError, match="dissect.esedb"):
        windows.win_ese_query(str(fake), "Containers")


# ─── win_shellbag_parse — minimal smoke (no real hive) ─────────────────────


def test_shellbag_parse_handles_missing_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hive without any BagMRU root returns an empty list, not an exception."""
    d = _evidence(tmp_path, monkeypatch)
    fake_hive = d / "fake.dat"
    fake_hive.write_bytes(b"\x00" * 1024)

    class _FakeRegistry:
        class Registry:
            def __init__(self, path: str) -> None:
                self.path = path

            def open(self, p: str) -> None:
                raise RuntimeError(f"no key {p}")

    monkeypatch.setattr(windows, "_import_registry", lambda: _FakeRegistry)
    rows = windows.win_shellbag_parse(str(fake_hive))
    assert rows == []


# ─── mac_apfs_inspect — backend absent ─────────────────────────────────────


def test_apfs_inspect_raises_when_fsstat_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    fake_image = d / "img.raw"
    fake_image.write_bytes(b"\x00" * 1024)
    monkeypatch.setattr(macos, "_resolve_binary", lambda name: None)
    with pytest.raises(macos.ApfsToolError, match="fsstat"):
        macos.mac_apfs_inspect(str(fake_image))


# ─── mac_spotlight_query — backend absent ──────────────────────────────────


def test_spotlight_query_raises_when_mdfind_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    vol = d / "Volume"
    vol.mkdir()
    monkeypatch.setattr(macos, "_resolve_binary", lambda name: None)
    with pytest.raises(macos.SpotlightToolError, match="mdfind"):
        macos.mac_spotlight_query(str(vol), 'kMDItemContentType == "public.png"')


# ─── mac_tracev3_query — backend absent ────────────────────────────────────


def test_tracev3_query_raises_when_backends_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _evidence(tmp_path, monkeypatch)
    archive = d / "system_logs.logarchive"
    archive.mkdir()
    monkeypatch.setattr(macos, "_resolve_binary", lambda name: None)
    with pytest.raises(macos.TracevToolError, match="No Unified Logs backend"):
        macos.mac_tracev3_query(str(archive), predicate=None)
