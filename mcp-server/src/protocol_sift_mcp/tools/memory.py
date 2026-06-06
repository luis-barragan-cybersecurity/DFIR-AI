"""Cross-OS memory analysis via Volatility 3.

`memory_volatility` is a thin, sandboxed subprocess wrapper around the
Volatility 3 CLI. We deliberately shell out to `vol` (rather than embed
the Python framework) because:

  * Volatility 3 ships its own renderer + symbol-loading machinery that
    we'd otherwise have to reimplement.
  * The CLI's `--renderer json` output is the contract we want to pin
    against — it's stable across plugin namespaces (windows.*, linux.*,
    mac.*) and avoids us shimming each plugin's row schema.
  * Subprocess isolation gives us a hard timeout, easy stderr capture,
    and a clean blast radius if a plugin hangs on a corrupt image.

Plugins are enforced against `ALLOWED_PLUGINS` (the 11 documented across
Sub-Plan 04). Image paths are sandbox-asserted under `EVIDENCE_PATH`.
Every failure mode raises `MemoryToolError` so callers get a single
exception type to handle.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..sandbox import assert_input_path


def _resolve_volatility_invocation() -> list[str]:
    """Return the argv prefix to invoke Volatility 3.

    Resolution order (first wins):

    1. ``MH_VOL_BIN`` — explicit path to a ``vol``/``vol3`` binary.
       Operator escape hatch.
    2. ``MH_VOLATILITY_PYTHON`` — explicit interpreter; the corresponding
       ``vol`` script next to it is invoked.
    3. The ``vol`` console-script alongside the running MCP-server Python.
       This is always the project venv's vol script — its shebang is
       irrelevant because we invoke ``sys.executable <vol_script>``
       explicitly. **Deterministic** — no PATH lookup, no shebang surprise.
    4. ``shutil.which("vol" | "vol3" | "volatility3")`` — last resort.
       Subject to the bug this function exists to avoid: PATH can
       resolve to a ``vol`` whose shebang interpreter lacks volatility3
       (e.g. Homebrew ``python3.14`` installed after a venv built against
       ``python3.12``), in which case every plugin call returned an empty
       CSV with a 74-byte "No module named volatility3" error.
    """
    override_bin = os.environ.get("MH_VOL_BIN")
    if override_bin:
        return [override_bin]
    override_py = os.environ.get("MH_VOLATILITY_PYTHON")
    if override_py:
        candidate = Path(override_py).parent / "vol"
        if candidate.exists():
            return [override_py, str(candidate)]
    # Primary path — the ``vol`` console-script in the same venv as
    # sys.executable (the venv Python that bin/mh-mcp-server exec'd).
    # `volatility3.cli` is a package, not a module with __main__, so
    # `python -m volatility3` and `python -m volatility3.cli` both fail;
    # the console-script does `from volatility3.cli import main; main()`
    # which is the supported entrypoint. Invoking it via sys.executable
    # bypasses the binary's shebang line entirely — that shebang is
    # exactly what got us into this mess when an OS Python upgrade
    # repointed it at a Python without volatility3 installed.
    here = Path(sys.executable).parent / "vol"
    if here.exists():
        try:
            import importlib.util
            if importlib.util.find_spec("volatility3") is not None:
                return [sys.executable, str(here)]
        except (ImportError, ValueError):
            pass
    # Last resort — PATH probe. Subject to the bug this function exists
    # to avoid; kept for distro installs that don't ship a co-located
    # python (rare).
    vol_bin = shutil.which("vol") or shutil.which("vol3") or shutil.which("volatility3")
    if vol_bin:
        return [vol_bin]
    return []

# Plugin allowlist. Anything outside this set is rejected before we ever
# touch disk. Coverage targets the SIFT-Workstation Volatility 3 surface
# across Windows, Linux, macOS — process / hiding / credential / registry
# / kernel / file / VAD / network plugins. Add to this set only after the
# plugin is known-good against the standard SIFT corpus.
ALLOWED_PLUGINS: frozenset[str] = frozenset(
    {
        # ── Windows core process / network (4) ────────────────────────────
        "windows.pslist",
        "windows.psscan",
        "windows.malfind",
        "windows.netscan",
        # ── Windows process introspection / hiding (5) ────────────────────
        "windows.psxview",
        "windows.pstree",
        "windows.envars",
        "windows.privileges",
        "windows.mutantscan",
        # ── Windows credential / Mimikatz detection (6) ───────────────────
        "windows.lsadump",
        "windows.hashdump",
        "windows.cmdline",
        "windows.dlllist",
        "windows.svcscan",
        "windows.handles",
        # ── Windows registry / persistence (3) ────────────────────────────
        "windows.registry.printkey",
        "windows.registry.userassist",
        "windows.registry.shimcachemem",
        # ── Windows kernel / driver / module (3) ──────────────────────────
        "windows.modules",
        "windows.driverirp",
        "windows.driverscan",
        # ── Windows file system / VAD / YARA (3) ──────────────────────────
        "windows.filescan",
        "windows.vadinfo",
        "windows.vadyarascan",
        # Cached-file extraction — gates the "memory cap" doctrine: any
        # process holding a handle to a high-value log/state file
        # (OneDrive AODL, downloads3.txt, browser caches, Slack logs,
        # etc.) MUST have its working set dumped before a finding can
        # claim "memory cannot tell us X about that file." See
        # docs/handle-dump-discipline + handle_dump_registry.
        "windows.dumpfiles",
        "windows.yarascan",
        # ── Linux core + network (8) ───────────────────────────────────────
        "linux.pslist",
        "linux.psaux",
        "linux.bash",
        "linux.malfind",
        "linux.sockstat",
        "linux.lsof",
        "linux.mount",
        "linux.proc.Maps",
        # ── Linux discovery (3) ────────────────────────────────────────────
        "linux.envars",
        "linux.elfs",
        "linux.tty_check",
        # ── macOS core + network (6) ───────────────────────────────────────
        "mac.pslist",
        "mac.psaux",
        "mac.malfind",
        "mac.netstat",
        "mac.lsof",
        "mac.mount",
        # ── macOS discovery (3) ────────────────────────────────────────────
        "mac.bash",
        "mac.ifconfig",
        "mac.kauth_listeners",
    }
)

# Volatility full-image scan plugins (windows.netscan, windows.psscan,
# windows.malfind, windows.filescan) legitimately take 10-30 min per plugin
# on a 19GB+ memory image. The previous 300s default caused the Rocba case
# (2026-05) to time out four of the highest-signal plugins, blocking live
# network endpoint enumeration and hidden-process discovery and forcing a
# GAP-01 entry in accuracy-report.md. 1800s (30 min) covers the slowest
# plugin we've measured against the SANS test corpus; callers running on
# images >25GB should pass timeout_sec=3600 explicitly.
DEFAULT_TIMEOUT_SEC = 1800


class MemoryToolError(Exception):
    """Volatility subprocess failure or environment misconfiguration."""


def memory_volatility(
    image_path: str,
    plugin: str,
    *,
    args: list[str] | None = None,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> list[dict[str, Any]]:
    """Run a Volatility 3 plugin against a memory image, parse JSON output.

    Image path is sandbox-asserted under EVIDENCE_PATH. Plugin must be in
    ALLOWED_PLUGINS. Subprocess is capped at `timeout_sec` (default 300).
    Stdout is parsed via `json.loads`; stderr is surfaced when the
    subprocess exits non-zero.

    Args:
        image_path: Path to the memory image, must resolve under EVIDENCE_PATH.
        plugin: Volatility 3 plugin name (e.g. "windows.pslist").
        args: Optional extra CLI args appended after the plugin name.
        timeout_sec: Subprocess wall-clock cap.

    Returns:
        Parsed JSON output as a list of row dicts.

    Raises:
        ValueError: plugin not in ALLOWED_PLUGINS.
        SandboxViolation: image_path escapes EVIDENCE_PATH or doesn't exist.
        MemoryToolError: vol binary missing, timeout, non-zero exit, or
            stdout that isn't valid JSON list output.
    """
    if plugin not in ALLOWED_PLUGINS:
        raise ValueError(
            f"plugin {plugin!r} not in allowlist "
            f"({len(ALLOWED_PLUGINS)} allowed: see ALLOWED_PLUGINS)"
        )

    img = assert_input_path(image_path)

    # Deterministic interpreter resolution — see _resolve_volatility_invocation
    # for the precedence order. Pre-fix this was a bare `shutil.which("vol")`
    # which could resolve to a binary whose shebang-bound Python lacked
    # volatility3 (e.g. when Homebrew installed python3.14 after our venv
    # was built against python3.12). Every plugin call then returned empty
    # CSV + a 74-byte "No module named volatility3" error, and the LLM
    # subagent would spin retrying. See cases/rocba-memory regression.
    invocation = _resolve_volatility_invocation()
    if not invocation:
        raise MemoryToolError(
            "Volatility 3 not resolvable. Tried (in order): "
            "MH_VOLATILITY_PYTHON, MH_VOL_BIN, sys.executable -m volatility3, "
            "shutil.which('vol'/'vol3'/'volatility3'). "
            "Install with: pip install '.[forensics]' "
            "(brings volatility3>=2.7.0)."
        )

    cmd: list[str] = [*invocation, "-f", str(img), "--renderer", "json", plugin]
    if args:
        cmd.extend(args)

    # Pass env explicitly (rather than relying on subprocess.run's implicit
    # inherit) so the contract is testable and so VOLATILITY_SYMBOL_PATH —
    # exported by bin/mh-mcp-server when the vendored ISF symbol dir
    # exists — actually reaches the vol child. SP05/T2.
    try:
        proc = subprocess.run(  # noqa: S603 — cmd[0] is shutil.which result, args are allowlisted plugin + sandbox-asserted path
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        raise MemoryToolError(
            f"vol {plugin} timed out after {timeout_sec}s on {img}"
        ) from exc
    except FileNotFoundError as exc:
        # Race: shutil.which found it, but exec failed (e.g. binary unlinked).
        raise MemoryToolError(f"vol exec failed: {exc}") from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise MemoryToolError(
            f"vol {plugin} exited {proc.returncode}: {stderr}"
        )

    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise MemoryToolError(
            f"vol {plugin} produced non-JSON stdout: {exc}"
        ) from exc

    if not isinstance(parsed, list):
        raise MemoryToolError(
            f"vol {plugin} JSON output is not a list (got {type(parsed).__name__})"
        )

    return parsed


# ─── MemProcFS findevil wrapper ────────────────────────────────────────────


class MemProcFSError(Exception):
    """MemProcFS binary missing or non-zero exit."""


_MEMPROCFS_TIMEOUT = 1200  # 20 min cap on FindEvil scans


def memprocfs_findevil(
    memory_path: str,
    *,
    mount_point: str = "/tmp/memprocfs-mh",  # noqa: S108 — intentional fixed mount path; caller can override
    timeout_sec: int = _MEMPROCFS_TIMEOUT,
) -> dict[str, Any]:
    """Run MemProcFS FindEvil over a memory image and return structured hits.

    Requires the `memprocfs` binary (Linux/SIFT). Mounts the image read-only
    at `mount_point` via FUSE, reads the findevil/findevil.txt summary, then
    unmounts. If the binary isn't installed, raises a clear MemProcFSError.

    Returns:
        {tool, image, mount_point, findevil_lines: list[str], raw: str}
    """
    img = assert_input_path(memory_path)
    bin_path = shutil.which("memprocfs")
    if not bin_path:
        raise MemProcFSError(
            "memprocfs binary not on PATH. Install: https://github.com/ufrisk/MemProcFS/releases"
        )

    mp = Path(mount_point)
    mp.mkdir(parents=True, exist_ok=True)

    cmd = [bin_path, "-device", str(img), "-mount", str(mp), "-norefresh", "-disablesymbolserver"]
    try:
        # MemProcFS daemonizes by default — give it a short window then look
        # for the findevil output file. We don't keep the mount alive past
        # this call (we explicitly unmount below).
        proc = subprocess.Popen(  # noqa: S603
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except FileNotFoundError as exc:
        raise MemProcFSError(f"memprocfs exec failed: {exc}") from exc

    findevil_path = mp / "findevil" / "findevil.txt"
    findevil_lines: list[str] = []
    elapsed = 0
    poll_interval = 5
    while elapsed < timeout_sec:
        if findevil_path.exists():
            findevil_lines = findevil_path.read_text(errors="replace").splitlines()
            break
        if proc.poll() is not None and proc.returncode != 0:
            break
        try:
            proc.wait(timeout=poll_interval)
            break
        except subprocess.TimeoutExpired:
            elapsed += poll_interval

    # Best-effort unmount + terminate.
    try:
        subprocess.run(  # noqa: S603
            ["fusermount", "-u", str(mp)],  # noqa: S607
            capture_output=True, check=False, timeout=30,
        )
    except Exception:  # noqa: BLE001, S110 — unmount is best-effort; logging the error adds no value
        pass
    try:
        proc.terminate()
    except Exception:  # noqa: BLE001, S110 — terminate is best-effort
        pass

    return {
        "tool": "memprocfs_findevil",
        "image": str(img),
        "mount_point": str(mp),
        "findevil_lines": findevil_lines,
        "hit_count": len(findevil_lines),
    }
