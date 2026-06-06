"""Node registry + shared helpers."""
from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from protocol_sift_mcp.tools.audit import agent_message_append, audit_append

from ..state import IncidentState
from . import (
    analyze,
    attack_tag,
    contain,
    correlate,
    d3fend_recommend,
    declare_incident,
    detect,
    eradicate,
    human_in_loop,
    kill_chain,
    lessons_learned,
    manifest_ingest,
    recover,
    remediation,
    scope,
    session_finalize,
    session_init,
    suppress,
    triage,
    verifier_pass,
)


def emit_message(
    state: IncidentState, *, from_agent: str, to_agent: str, role: str,
    content: str, metadata: dict[str, Any] | None = None,
) -> None:
    out = Path(state["_output_dir"])
    agent_message_append(
        out / "agent_messages.jsonl",
        from_agent=from_agent, to_agent=to_agent, role=role,
        content=content, metadata=metadata or {},
    )


def record_audit(state: IncidentState, *, event: str, data: dict[str, Any]) -> None:
    out = Path(state["_output_dir"])
    audit_append(out / "audit.jsonl", event=event, data=data)


# ─── Live progress printer ──────────────────────────────────────────────────
#
# `mh run` in default (LangGraph) mode used to print only the launch banner
# and then go silent for the full triage (1-3+ hours on big-image cases).
# Users couldn't tell whether the pipeline was working, hung, or finished
# without `tail -f cases/<id>/output/audit.jsonl` in a second terminal.
#
# This wraps every node in NODES with a stderr printer that emits one line
# on entry and one on exit (with elapsed time). stderr keeps stdout free
# for any structured output the orchestrator emits.
#
# Opt-out: `MH_QUIET=1` suppresses progress lines (used by CI + tests).
# Color: respects the standard `NO_COLOR` env var.

_QUIET = os.environ.get("MH_QUIET", "0") == "1"
_USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
_DIM = "\033[2m" if _USE_COLOR else ""
_CYAN = "\033[36m" if _USE_COLOR else ""
_GREEN = "\033[32m" if _USE_COLOR else ""
_RED = "\033[31m" if _USE_COLOR else ""
_RESET = "\033[0m" if _USE_COLOR else ""

# Heartbeat: while a node runs, emit a "still running" line every N seconds so
# users see progress on long claude-backed nodes (triage/analyze/verifier_pass
# can take 30-600s). MH_HEARTBEAT_SEC=0 disables; MH_QUIET=1 silences via the
# existing _print_status gate. Default 30s.
try:
    _HEARTBEAT_SEC = int(os.environ.get("MH_HEARTBEAT_SEC", "30"))
except ValueError:
    _HEARTBEAT_SEC = 30
if _HEARTBEAT_SEC < 0:
    _HEARTBEAT_SEC = 0


def _fmt_duration(seconds: float) -> str:
    if seconds < 1.0:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m{secs:02d}s"


def _print_status(symbol: str, color: str, node_name: str, suffix: str = "") -> None:
    if _QUIET:
        return
    ts = time.strftime("%H:%M:%S")
    msg = f"{_DIM}{ts}{_RESET} {color}{symbol}{_RESET} {node_name}"
    if suffix:
        msg += f" {_DIM}{suffix}{_RESET}"
    print(msg, file=sys.stderr, flush=True)


def _wrap_with_progress(node_name: str, fn: Callable[[IncidentState], IncidentState]) -> Callable[[IncidentState], IncidentState]:
    """Wrap a node callable so it emits per-node start/end signals to
    both the legacy line printer (for log scrapers) and the live TUI
    dashboard (for human eyeballs / demo recording)."""
    from .. import tui as _tui

    def wrapped(state: IncidentState) -> IncidentState:
        _print_status("▶", _CYAN, node_name, "(starting)")
        _tui.node_start(node_name)
        start = time.monotonic()
        stop_heartbeat = threading.Event()
        heartbeat_thread: threading.Thread | None = None
        if _HEARTBEAT_SEC > 0:
            def _heartbeat() -> None:
                # Event.wait returns True if stop was signaled, False on timeout.
                # First tick fires no earlier than _HEARTBEAT_SEC after start.
                while not stop_heartbeat.wait(_HEARTBEAT_SEC):
                    elapsed = _fmt_duration(time.monotonic() - start)
                    _print_status("⋯", _DIM, node_name, f"still running ({elapsed} elapsed)")
                    # Also nudge the TUI so the elapsed counter in the
                    # pipeline pane refreshes without an explicit event.
                    _tui.now(f"{node_name} · still running",
                             f"elapsed {elapsed}")
            heartbeat_thread = threading.Thread(
                target=_heartbeat, name=f"mh-heartbeat-{node_name}", daemon=True,
            )
            heartbeat_thread.start()
        try:
            result = fn(state)
        except Exception as exc:  # noqa: BLE001 — re-raised after logging
            stop_heartbeat.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=1.0)
            elapsed = _fmt_duration(time.monotonic() - start)
            _print_status("✗", _RED, node_name, f"FAILED after {elapsed}: {type(exc).__name__}: {exc}")
            _tui.node_end(node_name, ok=False, elapsed_s=time.monotonic() - start)
            raise
        stop_heartbeat.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1.0)
        elapsed = _fmt_duration(time.monotonic() - start)
        _print_status("✓", _GREEN, node_name, f"done in {elapsed}")
        _tui.node_end(node_name, ok=True, elapsed_s=time.monotonic() - start)
        # Refresh the right-pane state summary from whatever the node
        # just mutated. Cheap — pure pluck, no IO.
        try:
            _tui.update_state(**_tui.derive_state_summary(result))
        except Exception:  # noqa: BLE001 — TUI must never break the pipeline
            pass
        return result
    return wrapped


# §11.2 registry — 20 nodes total: 14 core IR nodes (detect, triage,
# declare_incident, analyze, attack_tag, kill_chain, d3fend_recommend, contain,
# human_in_loop, eradicate, recover, lessons_learned, remediation, verifier_pass)
# plus 6 framing/structural nodes (manifest_ingest, session_init, scope,
# suppress, correlate, session_finalize).
# Note: kill_chain_classify is registered as "kill_chain" and remediation_plan
# is registered as "remediation" (graph-key names match the LangGraph nodes;
# §11.4 phase mapping in picerl.NODE_TO_PICERL uses the longer descriptive
# names — see picerl.picerl_phase_for callers in each node body).
_RAW_NODES: dict[str, Callable[[IncidentState], IncidentState]] = {
    "manifest_ingest": manifest_ingest.run,
    "session_init": session_init.run,
    "detect": detect.run,
    "triage": triage.run,
    "scope": scope.run,
    "declare_incident": declare_incident.run,
    "suppress": suppress.run,
    "analyze": analyze.run,
    "attack_tag": attack_tag.run,
    "kill_chain": kill_chain.run,
    "d3fend_recommend": d3fend_recommend.run,
    "contain": contain.run,
    "human_in_loop": human_in_loop.run,
    "eradicate": eradicate.run,
    "recover": recover.run,
    "lessons_learned": lessons_learned.run,
    "remediation": remediation.run,
    "verifier_pass": verifier_pass.run,
    "correlate": correlate.run,
    "session_finalize": session_finalize.run,
}

NODES: dict[str, Callable[[IncidentState], IncidentState]] = {
    name: _wrap_with_progress(name, fn) for name, fn in _RAW_NODES.items()
}
