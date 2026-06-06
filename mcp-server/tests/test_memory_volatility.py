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
    DEFAULT_TIMEOUT_SEC,
    MemoryToolError,
    memory_volatility,
)


def test_default_timeout_accommodates_large_image_scan_plugins():
    """Regression: rocba case (19GB image) timed out 4 full-scan plugins at
    the prior 300s default, blocking live network enumeration. The new
    default must be high enough for windows.netscan / psscan / malfind /
    filescan to complete on a 19GB+ image. Empirically these take 10-30 min
    per plugin; 1800s is the floor."""
    assert DEFAULT_TIMEOUT_SEC >= 1800, (
        f"DEFAULT_TIMEOUT_SEC={DEFAULT_TIMEOUT_SEC} is too low for full-image scan plugins. "
        "Bump to >= 1800 to avoid GAP-01-style accuracy losses on big-image cases."
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
        patch("protocol_sift_mcp.tools.memory._resolve_volatility_invocation", return_value=["/usr/bin/vol"]),
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
        patch("protocol_sift_mcp.tools.memory._resolve_volatility_invocation", return_value=["/usr/bin/vol"]),
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
        patch("protocol_sift_mcp.tools.memory._resolve_volatility_invocation", return_value=["/usr/bin/vol"]),
        patch("protocol_sift_mcp.tools.memory.subprocess.run", return_value=fake),
    ):
        result = memory_volatility(str(img), "windows.pslist")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["ImageFileName"] == "System"
    assert result[1]["PID"] == 600


def test_vol_missing_raises_with_install_hint() -> None:
    """When the resolver finds no vol invocation, MemoryToolError mentions
    the forensics extras + lists what was tried."""
    img = _make_image()
    with patch("protocol_sift_mcp.tools.memory._resolve_volatility_invocation",
               return_value=[]):
        with pytest.raises(MemoryToolError, match="not resolvable|forensics"):
            memory_volatility(str(img), "windows.pslist")


# ──────────────────────────────────────────────────────────────────────────
# _resolve_volatility_invocation — interpreter-resolution discipline
# ──────────────────────────────────────────────────────────────────────────
#
# Pre-fix this was a bare `shutil.which("vol")` which on a real system
# could resolve to a binary whose shebang Python lacked volatility3 (e.g.
# Homebrew python3.14 installed after a venv built against python3.12).
# Every plugin call then returned empty CSV + a 74-byte "No module named
# volatility3" error and the LLM subagent retried indefinitely. These
# tests pin the deterministic-resolution contract.


def test_resolver_honors_mh_vol_bin_env_override(monkeypatch) -> None:
    from protocol_sift_mcp.tools.memory import _resolve_volatility_invocation
    monkeypatch.setenv("MH_VOL_BIN", "/custom/vol")
    monkeypatch.delenv("MH_VOLATILITY_PYTHON", raising=False)
    assert _resolve_volatility_invocation() == ["/custom/vol"]


def test_resolver_honors_mh_volatility_python_env_override(monkeypatch, tmp_path) -> None:
    """When MH_VOLATILITY_PYTHON is set, the resolver invokes the vol
    script alongside that interpreter."""
    from protocol_sift_mcp.tools.memory import _resolve_volatility_invocation
    fake_py = tmp_path / "bin" / "python"
    fake_vol = tmp_path / "bin" / "vol"
    fake_py.parent.mkdir(parents=True)
    fake_py.touch()
    fake_vol.touch()
    monkeypatch.delenv("MH_VOL_BIN", raising=False)
    monkeypatch.setenv("MH_VOLATILITY_PYTHON", str(fake_py))
    invocation = _resolve_volatility_invocation()
    assert invocation == [str(fake_py), str(fake_vol)]


def test_resolver_prefers_venv_vol_script_when_volatility3_importable(monkeypatch) -> None:
    """Default path on a properly-installed system: resolver invokes the
    `vol` console-script alongside sys.executable. This is the path that
    fixes the rocba-memory regression."""
    import sys
    from pathlib import Path
    from protocol_sift_mcp.tools.memory import _resolve_volatility_invocation
    monkeypatch.delenv("MH_VOL_BIN", raising=False)
    monkeypatch.delenv("MH_VOLATILITY_PYTHON", raising=False)
    expected_vol = Path(sys.executable).parent / "vol"
    if not expected_vol.exists():
        pytest.skip(
            "venv has no vol script — skipping (this test asserts the "
            "happy path on a fully-installed dev env)"
        )
    invocation = _resolve_volatility_invocation()
    assert invocation == [sys.executable, str(expected_vol)], (
        f"resolver did not pick venv vol; got {invocation}"
    )


def test_resolver_falls_back_to_path_when_venv_vol_missing(monkeypatch) -> None:
    """If the venv has no vol script (e.g. forensics extras not installed),
    fall back to PATH probe — but the docstring warns this is risky."""
    from protocol_sift_mcp.tools.memory import _resolve_volatility_invocation
    monkeypatch.delenv("MH_VOL_BIN", raising=False)
    monkeypatch.delenv("MH_VOLATILITY_PYTHON", raising=False)
    # Force the venv-side branch to fail by claiming volatility3 isn't
    # importable.
    with patch("importlib.util.find_spec", return_value=None), \
         patch("protocol_sift_mcp.tools.memory.shutil.which",
               side_effect=lambda name: "/usr/bin/vol" if name == "vol" else None):
        invocation = _resolve_volatility_invocation()
    assert invocation == ["/usr/bin/vol"]


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
