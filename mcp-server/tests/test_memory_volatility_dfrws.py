"""DFRWS 2008 happy-path test for memory_volatility (Sub-Plan 05 Task 3).

Double-gated:
- MH_RUN_VOLATILITY_TESTS=1 env var
- DFRWS image (memory.raw) on disk
- vendored ISF on disk
- volatility3 importable
- `vol` binary on PATH

Skip-by-default keeps default `pytest mcp-server/tests` light. Opt-in
via:
    MH_RUN_VOLATILITY_TESTS=1 PYTHONPATH=mcp-server/src \
        .venv/bin/python -m pytest mcp-server/tests/test_memory_volatility_dfrws.py -v --no-cov

When green, this proves the SP05 vendored ISF + VOLATILITY_SYMBOL_PATH
plumbing actually produces structured output against the real Linux
CentOS 5 memory image.
"""
from __future__ import annotations

import importlib
import os
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DFRWS_IMAGE = REPO_ROOT / "corpus" / "dfrws-2008-memory" / "input" / "memory.raw"
DFRWS_ISF = (
    REPO_ROOT
    / "corpus"
    / "dfrws-2008-memory"
    / "symbols"
    / "linux"
    / "2.6.18-8.1.15.el5_64.json.xz"
)
SYMBOLS_DIR = REPO_ROOT / "corpus" / "dfrws-2008-memory" / "symbols"


def _opt_in_reason() -> str | None:
    """Return None if all preconditions met, else a skip reason."""
    if os.environ.get("MH_RUN_VOLATILITY_TESTS") != "1":
        return "set MH_RUN_VOLATILITY_TESTS=1 to run real-image Volatility tests"
    if not DFRWS_IMAGE.exists():
        return f"DFRWS memory image missing at {DFRWS_IMAGE}"
    if not DFRWS_ISF.exists():
        return f"vendored ISF missing at {DFRWS_ISF}"
    if (
        shutil.which("vol") is None
        and shutil.which("vol3") is None
        and shutil.which("volatility3") is None
    ):
        return "vol binary not on PATH (install with: pip install '.[forensics]')"
    return None


pytestmark = pytest.mark.skipif(
    _opt_in_reason() is not None,
    reason=_opt_in_reason() or "real-image gated",
)


# Late import — module-level skipif handles the volatility3 importability
# gate without us needing to do `pytest.importorskip("volatility3")` here,
# but include it as a safety net for the case where MH_RUN_VOLATILITY_TESTS
# is set but volatility3 still isn't importable.
volatility3 = pytest.importorskip("volatility3")  # noqa: F401


def test_linux_pslist_returns_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    """linux.pslist against DFRWS 2008 produces a populated process list.

    Validates: vendored ISF + VOLATILITY_SYMBOL_PATH wiring + sandbox path
    + Volatility CLI subprocess all work end-to-end against a real Linux
    CentOS 5 memory image.

    Note: conftest.py's autouse `_sandbox_env` fixture already reloaded
    `protocol_sift_mcp.sandbox` against a tmp EVIDENCE_PATH. We re-point
    EVIDENCE_PATH at the real DFRWS input dir and reload again so
    `assert_input_path` accepts the vendored memory.raw without raising
    SandboxViolation.
    """
    # Wire env so memory.py picks up the symbol path and sandbox accepts the image.
    monkeypatch.setenv("VOLATILITY_SYMBOL_PATH", str(SYMBOLS_DIR))
    monkeypatch.setenv("EVIDENCE_PATH", str(DFRWS_IMAGE.parent))

    # Reload sandbox so its module-level INPUT_ROOT picks up the new
    # EVIDENCE_PATH. Without this reload, assert_input_path would still
    # be pinned to the conftest tmp dir.
    from protocol_sift_mcp import sandbox

    importlib.reload(sandbox)

    from protocol_sift_mcp.tools.memory import memory_volatility

    rows = memory_volatility(str(DFRWS_IMAGE), "linux.pslist")

    assert isinstance(rows, list), f"expected list, got {type(rows).__name__}"
    assert len(rows) > 0, (
        "linux.pslist returned 0 rows — ISF symbol path likely broken. "
        f"Image: {DFRWS_IMAGE}\n"
        f"Symbols: {SYMBOLS_DIR}"
    )
    # Volatility 3 linux.pslist columns: PID, TID, PPID, COMM, ...
    sample = rows[0]
    assert isinstance(sample, dict)
    has_pid = any(k.upper() == "PID" for k in sample.keys())
    has_comm = any(k.upper() in ("COMM", "NAME") for k in sample.keys())
    assert has_pid or has_comm, f"sample row missing PID/COMM: {sample}"
    # Sanity: linux.pslist on a real Linux dump should have init/swapper or systemd.
    comms = [str(row.get("COMM", row.get("Name", ""))) for row in rows]
    print(f"\n[INFO] linux.pslist returned {len(rows)} processes")
    print(f"[INFO] Sample: {sample}")
    print(f"[INFO] First 5 COMMs: {comms[:5]}")
