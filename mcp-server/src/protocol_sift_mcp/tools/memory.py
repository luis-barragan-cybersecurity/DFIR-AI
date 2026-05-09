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
from typing import Any

from ..sandbox import assert_input_path

# 11 plugins documented in Sub-Plan 04 (T6). Anything outside this set
# is rejected before we ever touch disk.
ALLOWED_PLUGINS: frozenset[str] = frozenset(
    {
        # Windows (4)
        "windows.pslist",
        "windows.psscan",
        "windows.malfind",
        "windows.netscan",
        # Linux (4)
        "linux.pslist",
        "linux.bash",
        "linux.malfind",
        "linux.sockstat",
        # macOS (3)
        "mac.pslist",
        "mac.malfind",
        "mac.netstat",
    }
)

DEFAULT_TIMEOUT_SEC = 300


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

    # Volatility 3 is packaged under several CLI names depending on
    # install method (pip, distro, source). Probe in order of preference.
    vol_bin = shutil.which("vol") or shutil.which("vol3") or shutil.which("volatility3")
    if not vol_bin:
        raise MemoryToolError(
            "vol binary not found on PATH. "
            "Install with: pip install '.[forensics]' "
            "(brings volatility3>=2.7.0)."
        )

    cmd: list[str] = [vol_bin, "-f", str(img), "--renderer", "json", plugin]
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
