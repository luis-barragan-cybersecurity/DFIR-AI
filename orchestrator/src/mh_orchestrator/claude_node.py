"""Thin compatibility shim — delegates to the provider registry.

Pre-refactor this module held the full subprocess wrapper for ``claude -p``.
That logic now lives in ``providers/anthropic_cli.py`` and the registry in
``providers/registry.py`` picks the right provider per ``MH_PROVIDER`` env or
auto-detect.

Every prior import surface is preserved so existing nodes
(``triage``, ``analyze``, ``verifier_pass``, ``scope``, ``detect``,
``correlate``, ``manifest_ingest``, …) keep working untouched:

- ``invoke_subagent(...)`` — calls into the resolved provider.
- ``SubagentResult``       — re-exported from ``providers.base``.
- ``HeadlessBillingError`` — re-exported from ``providers.base``.
- ``should_stub(node_name)`` — unchanged stub-mode policy used by node code.
- ``DEFAULT_ALLOWED_TOOLS`` — re-exported from ``providers.anthropic_cli``.
- ``_resolve_project_dir()`` — re-exported (used by ``cli.py`` directly).

This module intentionally has no behaviour of its own beyond delegation. Add
new functionality in the provider files, not here.
"""
from __future__ import annotations

import os

from .providers import HeadlessBillingError, SubagentResult, get_provider
from .providers.anthropic_cli import (
    DEFAULT_ALLOWED_TOOLS,
    _kill_group,
    _parse_stream_json,
    _read_stream,
    _resolve_project_dir,
    _run_with_liveness_monitor,
    _write_mcp_config,
    _write_stdin,
    _write_subagent_trace,
)


def should_stub(node_name: str) -> bool:
    """Decide whether an LLM-invoking node should use its stub branch.

    Rules (in precedence order):
    1. If ``MH_NO_CLAUDE`` is not set or != "1" → return False (always real).
    2. If ``MH_REAL_CLAUDE_NODES`` is set and ``node_name`` is in the
       comma-separated list → return False (override: real LLM even though
       MH_NO_CLAUDE=1).
    3. Otherwise → return True (stub).

    Args:
        node_name: One of ``"triage"``, ``"analyze"``, ``"verifier_pass"``.

    Returns:
        True if the node should take its stub branch.
    """
    if os.environ.get("MH_NO_CLAUDE") != "1":
        return False
    real_nodes = os.environ.get("MH_REAL_CLAUDE_NODES", "")
    requested = {n.strip() for n in real_nodes.split(",") if n.strip()}
    return node_name not in requested


def invoke_subagent(
    *,
    subagent_name: str,
    prompt: str,
    allowed_tools: list[str] | None = None,
    headless: bool = True,
) -> SubagentResult:
    """Invoke a named subagent via the resolved provider.

    Provider selection:
      1. ``MH_PROVIDER`` env (explicit override).
      2. Auto-detect in order: anthropic-cli → anthropic-api → openai → ollama.

    The returned ``SubagentResult`` shape is identical regardless of provider;
    nodes that destructure ``parsed_messages`` / ``final_text`` / ``timed_out``
    / ``timeout_reason`` work without changes.

    Raises:
        HeadlessBillingError: Anthropic CLI hit the billing gate.
        ProviderToolError: A provider's tool-call loop failed.
        RuntimeError: Selected provider's SDK / endpoint not available.
    """
    provider = get_provider()
    return provider.invoke(
        subagent_name=subagent_name,
        prompt=prompt,
        allowed_tools=allowed_tools,
        headless=headless,
    )


__all__ = [
    "DEFAULT_ALLOWED_TOOLS",
    "HeadlessBillingError",
    "SubagentResult",
    "_kill_group",
    "_parse_stream_json",
    "_read_stream",
    "_resolve_project_dir",
    "_run_with_liveness_monitor",
    "_write_mcp_config",
    "_write_stdin",
    "_write_subagent_trace",
    "invoke_subagent",
    "should_stub",
]
