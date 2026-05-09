"""memory_volatility real-impl tests (Sub-Plan 04 / T6).

Replaces the NotImplementedError stub in tools/memory.py with a real
subprocess wrapper around the Volatility 3 CLI. All subprocess calls
are mocked here so these tests run unconditionally without requiring
a Volatility install. The live-image happy-path (against the DFRWS
2008 dump) is gated separately and lives in T11/T12.

Conventions follow tests/test_linux_history.py: evidence files are
written under EVIDENCE_PATH (seeded by the autouse _sandbox_env
fixture), and assert_input_path enforces the sandbox.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from protocol_sift_mcp import sandbox as _sandbox
from protocol_sift_mcp.tools.memory import (
    ALLOWED_PLUGINS,
    MemoryToolError,
    memory_volatility,
)


def _make_image(name: str = "memory.raw") -> Path:
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    img = input_dir / name
    img.write_bytes(b"\x00" * 16)
    return img


def test_plugin_allowlist_rejects_unlisted() -> None:
    """Plugins outside the documented allowlist are rejected before any I/O."""
    img = _make_image()
    with pytest.raises(ValueError, match="not in allowlist"):
        memory_volatility(str(img), "windows.evilplugin")


def test_sandbox_rejects_out_of_bounds_path() -> None:
    """Paths outside EVIDENCE_PATH must be blocked by assert_input_path.

    We reference the *current* SandboxViolation class via the live module
    because the conftest autouse fixture reloads sandbox per test, so a
    top-of-module `from sandbox import SandboxViolation` would bind to a
    stale class. See tests/conftest.py::_sandbox_env.
    """
    with pytest.raises(_sandbox.SandboxViolation):
        memory_volatility("/tmp/escape.raw", "windows.pslist")  # noqa: S108 — intentional out-of-sandbox path under test


def test_subprocess_invoked_with_correct_args() -> None:
    """vol is invoked with -f <image> --renderer json <plugin>."""
    img = _make_image()
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "[]"
    fake.stderr = ""
    with (
        patch("protocol_sift_mcp.tools.memory.shutil.which", return_value="/usr/bin/vol"),
        patch("protocol_sift_mcp.tools.memory.subprocess.run", return_value=fake) as mock_run,
    ):
        memory_volatility(str(img), "windows.pslist")

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "/usr/bin/vol"
    assert "-f" in cmd
    assert str(img) in cmd
    assert "--renderer" in cmd
    assert "json" in cmd
    assert "windows.pslist" in cmd


def test_nonzero_exit_raises_memory_tool_error() -> None:
    """A non-zero vol exit surfaces stderr through MemoryToolError."""
    img = _make_image()
    fake = MagicMock()
    fake.returncode = 1
    fake.stdout = ""
    fake.stderr = "Volatility framework error: invalid image"
    with (
        patch("protocol_sift_mcp.tools.memory.shutil.which", return_value="/usr/bin/vol"),
        patch("protocol_sift_mcp.tools.memory.subprocess.run", return_value=fake),
    ):
        with pytest.raises(MemoryToolError, match="invalid image"):
            memory_volatility(str(img), "windows.pslist")


def test_happy_path_parses_json() -> None:
    """JSON stdout is parsed into a list[dict] preserving plugin shape."""
    img = _make_image()
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps(
        [
            {"PID": 4, "PPID": 0, "ImageFileName": "System"},
            {"PID": 600, "PPID": 4, "ImageFileName": "smss.exe"},
        ]
    )
    fake.stderr = ""
    with (
        patch("protocol_sift_mcp.tools.memory.shutil.which", return_value="/usr/bin/vol"),
        patch("protocol_sift_mcp.tools.memory.subprocess.run", return_value=fake),
    ):
        result = memory_volatility(str(img), "windows.pslist")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["ImageFileName"] == "System"
    assert result[1]["PID"] == 600


def test_vol_missing_raises_with_install_hint() -> None:
    """When vol is not on PATH, MemoryToolError mentions the forensics extras."""
    img = _make_image()
    with patch("protocol_sift_mcp.tools.memory.shutil.which", return_value=None):
        with pytest.raises(MemoryToolError, match="vol.*not found|forensics"):
            memory_volatility(str(img), "windows.pslist")


def test_allowlist_constants_complete() -> None:
    """ALLOWED_PLUGINS includes the documented 11 plugins across Win/Linux/macOS."""
    assert "windows.pslist" in ALLOWED_PLUGINS
    assert "windows.psscan" in ALLOWED_PLUGINS
    assert "windows.malfind" in ALLOWED_PLUGINS
    assert "windows.netscan" in ALLOWED_PLUGINS
    assert "linux.pslist" in ALLOWED_PLUGINS
    assert "linux.bash" in ALLOWED_PLUGINS
    assert "linux.malfind" in ALLOWED_PLUGINS
    assert "linux.sockstat" in ALLOWED_PLUGINS
    assert "mac.pslist" in ALLOWED_PLUGINS
    assert "mac.malfind" in ALLOWED_PLUGINS
    assert "mac.netstat" in ALLOWED_PLUGINS
    assert len(ALLOWED_PLUGINS) >= 11
