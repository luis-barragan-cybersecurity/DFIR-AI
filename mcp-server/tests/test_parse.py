"""os_detect + parse-primitive tests.

os_detect routes the orchestrator to the correct OS specialist. Wrong routing
sends a Linux journal at WindowsAgent — wasted time, lower IR Accuracy. So
detection must be high-confidence on canonical artifacts and honest about
ambiguity (return ``unknown`` rather than guessing) on borderline cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol_sift_mcp import sandbox
from protocol_sift_mcp.tools import parse


def _evidence_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sandbox, "INPUT_ROOT", input_dir.resolve())
    return input_dir


def test_os_detect_registry_hive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "NTUSER.DAT"
    f.write_bytes(b"regf" + b"\x00" * 60 + b"\x00" * 4096)
    result = parse.os_detect(str(f))
    assert result["os"] == "windows"
    assert result["confidence"] >= 0.6
    assert result["evidence_class"] == "registry"


def test_os_detect_evtx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "Security.evtx"
    f.write_bytes(b"ElfFile\x00" + b"\x00" * 56 + b"\x00" * 4096)
    result = parse.os_detect(str(f))
    assert result["os"] == "windows"
    assert result["evidence_class"] == "evtx"


def test_os_detect_prefetch_compressed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "CMD.EXE-AAAA.pf"
    f.write_bytes(b"MAM\x04" + b"\x00" * 60 + b"\x00" * 4096)
    result = parse.os_detect(str(f))
    assert result["os"] == "windows"
    assert result["evidence_class"] == "prefetch"


def test_os_detect_macos_plist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "preferences.plist"
    f.write_bytes(b"bplist00" + b"\x00" * 56)
    result = parse.os_detect(str(f))
    assert result["os"] == "macos"
    assert result["evidence_class"] == "plist"


def test_os_detect_macho(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "binary"
    f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
    result = parse.os_detect(str(f))
    assert result["os"] == "macos"


def test_os_detect_apfs_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "disk.dmg"
    payload = b"\x00" * 32 + b"NXSB" + b"\x00" * 4060
    f.write_bytes(payload)
    result = parse.os_detect(str(f))
    assert result["os"] == "macos"
    assert result["evidence_class"] == "filesystem_image"


def test_os_detect_elf_linux(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "rootkit.ko"
    f.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56)
    result = parse.os_detect(str(f))
    assert result["os"] == "linux"


def test_os_detect_ext4_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "rootfs.img"
    blob = bytearray(b"\x00" * 0x500)
    blob[0x438:0x43A] = b"\x53\xef"
    f.write_bytes(bytes(blob))
    result = parse.os_detect(str(f))
    assert result["os"] == "linux"
    assert result["evidence_class"] == "filesystem_image"


def test_os_detect_lime_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "memory.lime"
    f.write_bytes(b"EMiL" + b"\x00" * 60)
    result = parse.os_detect(str(f))
    assert result["os"] == "linux"
    assert result["confidence"] <= 0.8


def test_os_detect_directory_windows_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    win_root = indir / "C_drive_mount"
    (win_root / "Windows" / "System32").mkdir(parents=True)
    (win_root / "Windows" / "Prefetch").mkdir(parents=True)
    result = parse.os_detect(str(win_root))
    assert result["os"] == "windows"
    assert result["is_directory"] is True
    assert result["evidence_class"] == "directory"
    assert any(s["match"].startswith("presence of Windows") for s in result["signals"])


def test_os_detect_directory_linux_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    lin_root = indir / "rootfs"
    (lin_root / "etc").mkdir(parents=True)
    (lin_root / "etc" / "passwd").touch()
    (lin_root / "var" / "log").mkdir(parents=True)
    (lin_root / "var" / "log" / "auth.log").touch()
    result = parse.os_detect(str(lin_root))
    assert result["os"] == "linux"
    assert result["is_directory"] is True


def test_os_detect_extension_only_low_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "mystery.dmp"
    f.write_bytes(b"\x00" * 4096)
    result = parse.os_detect(str(f))
    assert result["confidence"] <= 0.6
    assert any(s["source"] == "extension" for s in result["signals"])


def test_os_detect_raw_memory_extension_classified_as_memory_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: rocba-memory case shipped a Rocba-Memory.raw image and the
    pipeline produced zero findings because .raw was missing from ext_map →
    os_detect returned 'unknown' → triage routed to WindowsAgent → evtx/registry
    tools failed against raw bytes."""
    indir = _evidence_dir(tmp_path, monkeypatch)
    for name in ("Rocba-Memory.raw", "image.mem"):
        f = indir / name
        f.write_bytes(b"\x00" * 4096)
        result = parse.os_detect(str(f))
        assert result["os"] == "memory_dump", (
            f"{name} should classify as memory_dump, got {result['os']!r}"
        )
        assert result["evidence_class"] == "memory_dump"
        assert any(s["source"] == "extension" for s in result["signals"])


def test_os_detect_unknown_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "random.bin"
    f.write_bytes(b"\xaa\xbb\xcc\xdd" * 16)
    result = parse.os_detect(str(f))
    assert result["os"] == "unknown"
    assert result["confidence"] == 0.0


def test_os_detect_rejects_path_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    _ = indir
    elsewhere = tmp_path / "outside.dat"
    elsewhere.write_bytes(b"\x00")
    with pytest.raises(sandbox.SandboxViolation):
        parse.os_detect(str(elsewhere))


def test_magic_check_returns_head_and_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    indir = _evidence_dir(tmp_path, monkeypatch)
    f = indir / "file.bin"
    f.write_bytes(b"hello-world-and-some-more-data")
    result = parse.magic_check(str(f))
    assert result["head_hex"] == b"hello-world-and-".hex()
    assert result["size"] == 30
