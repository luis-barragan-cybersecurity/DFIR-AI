"""VOLATILITY_SYMBOL_PATH env propagation tests (Sub-Plan 05 / T2).

The launcher (`bin/mh-mcp-server`) exports `VOLATILITY_SYMBOL_PATH` when
the vendored ISF symbols dir exists at `corpus/dfrws-2008-memory/symbols/`.
For that export to actually reach the `vol` subprocess, `memory_volatility`
must pass `env=` explicitly to `subprocess.run` — relying on Python's
implicit env inheritance is correct today but makes the contract
untestable and means a future caller mutation (SP06 may want to inject
`--symbol-dirs` shimmed via env) has nowhere clean to hook in.

These tests pin the contract: subprocess.run is called with `env=`, and
`VOLATILITY_SYMBOL_PATH` is propagated when (and only when) it is set in
the parent process env.

Patches use the fully-qualified module attr (`protocol_sift_mcp.tools.
memory.subprocess.run`) to match the T6 pattern in
test_memory_volatility.py — patching bare `subprocess.run` would miss
the import the SUT actually resolves.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from protocol_sift_mcp.tools.memory import memory_volatility


def _make_image(name: str = "memory.raw") -> Path:
    input_dir = Path(os.environ["EVIDENCE_PATH"])
    img = input_dir / name
    img.write_bytes(b"\x00" * 16)
    return img


def test_subprocess_receives_volatility_symbol_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When VOLATILITY_SYMBOL_PATH is set in the parent env, the
    subprocess invocation propagates it via env=."""
    img = _make_image()
    monkeypatch.setenv("VOLATILITY_SYMBOL_PATH", "/test/symbols")

    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "[]"
    fake.stderr = ""
    with (
        patch("protocol_sift_mcp.tools.memory.shutil.which", return_value="/usr/bin/vol"),
        patch("protocol_sift_mcp.tools.memory.subprocess.run", return_value=fake) as mock_run,
    ):
        memory_volatility(str(img), "windows.pslist")

    kwargs = mock_run.call_args.kwargs
    assert "env" in kwargs, "subprocess.run called without env=; T2 contract broken"
    assert kwargs["env"].get("VOLATILITY_SYMBOL_PATH") == "/test/symbols"


def test_subprocess_env_unset_when_volatility_symbol_path_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the parent env has no VOLATILITY_SYMBOL_PATH, the subprocess
    env also lacks it (no synthetic injection)."""
    img = _make_image()
    monkeypatch.delenv("VOLATILITY_SYMBOL_PATH", raising=False)

    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "[]"
    fake.stderr = ""
    with (
        patch("protocol_sift_mcp.tools.memory.shutil.which", return_value="/usr/bin/vol"),
        patch("protocol_sift_mcp.tools.memory.subprocess.run", return_value=fake) as mock_run,
    ):
        memory_volatility(str(img), "windows.pslist")

    kwargs = mock_run.call_args.kwargs
    assert "env" in kwargs, "subprocess.run called without env=; T2 contract broken"
    assert "VOLATILITY_SYMBOL_PATH" not in kwargs["env"]
