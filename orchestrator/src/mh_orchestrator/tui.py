"""Terminal UI dashboard for mh-orchestrate.

Two-pane fixed dashboard (pipeline tree | live state panel) with a
dedicated 2-line NOW area below it and a progress bar at the bottom.
Pure ANSI — no third-party deps. Designed to make a live orchestrator
run visually legible to judges in the SANS FindEvil demo video.

Two render modes:

    TUI (default)         — in-place refresh via ANSI cursor moves.
                            Looks clean on a live terminal but can
                            artifact on screen recordings if the
                            recorder samples below ~30 fps.
    append-only fallback  — every refresh re-prints the whole frame
                            on a new line. Recording-safe; verbose.

Choose via ``MH_NO_TUI=1`` (or ``MH_QUIET=1`` to disable both and fall
back to the original per-line printer in ``nodes/__init__.py``).

The public API is small on purpose:

    tui = Tui(case_id=..., evidence_summary=...)
    tui.start()                              # paint initial frame
    tui.node_start("triage")
    tui.now("WindowsAgent · cold start",
            "spawning claude -p subprocess")
    ...
    tui.now("WindowsAgent · calling memory_volatility",
            "windows.psscan against 19.0GB image · 00:42")
    tui.node_end("triage", ok=True, elapsed_s=42.1)
    tui.update_state(state)                  # refresh side panel
    tui.stop(final_state)                    # final frame + cursor reset
"""
from __future__ import annotations

import io
import os
import shutil
import sys
import threading
import time
from collections.abc import Iterable

# Canonical node order — must mirror ``_RAW_NODES`` in ``nodes/__init__.py``.
# The TUI uses this to render the static pipeline tree on the left pane.
# `suppress` and `human_in_loop` are conditional and only show when fired.
PIPELINE_NODES: tuple[str, ...] = (
    "manifest_ingest", "session_init", "detect", "triage", "scope",
    "declare_incident", "analyze", "attack_tag", "kill_chain",
    "d3fend_recommend", "contain", "eradicate", "recover",
    "lessons_learned", "remediation", "verifier_pass", "correlate",
    "session_finalize",
)

# Symbol set for node status.
_SYM_PENDING = "○"
_SYM_RUNNING = "▶"
_SYM_DONE = "✓"
_SYM_FAIL = "✗"

# Colors — opt-out via NO_COLOR per the de facto standard.
_USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
_C = {
    "dim":    "\033[2m" if _USE_COLOR else "",
    "bold":   "\033[1m" if _USE_COLOR else "",
    "cyan":   "\033[36m" if _USE_COLOR else "",
    "green":  "\033[32m" if _USE_COLOR else "",
    "yellow": "\033[33m" if _USE_COLOR else "",
    "red":    "\033[31m" if _USE_COLOR else "",
    "blue":   "\033[34m" if _USE_COLOR else "",
    "reset":  "\033[0m" if _USE_COLOR else "",
}


def _strip_ansi_len(s: str) -> int:
    """Visible length, stripping ANSI escape sequences for width math."""
    out, i, n = 0, 0, len(s)
    while i < n:
        if s[i] == "\033":
            j = s.find("m", i)
            i = (j + 1) if j != -1 else n
            continue
        out += 1
        i += 1
    return out


def _pad_visible(s: str, width: int) -> str:
    """Right-pad with spaces to a visible width (ignoring ANSI codes)."""
    deficit = width - _strip_ansi_len(s)
    if deficit > 0:
        return s + (" " * deficit)
    return s


def _fmt_duration(seconds: float) -> str:
    if seconds < 1.0:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, rem_min = divmod(minutes, 60)
    return f"{hours}h{rem_min:02d}m"


def _human_size(n_bytes: int) -> str:
    if n_bytes < 1024:
        return f"{n_bytes}B"
    for unit in ("KB", "MB", "GB", "TB"):
        n_bytes /= 1024
        if n_bytes < 1024:
            return f"{n_bytes:.1f}{unit}"
    return f"{n_bytes:.1f}PB"


class Tui:
    """Live two-pane dashboard."""

    LEFT_WIDTH = 26
    RIGHT_WIDTH = 46
    TOTAL_INNER = LEFT_WIDTH + 3 + RIGHT_WIDTH  # "│  " separator
    OUTER_WIDTH = TOTAL_INNER + 4               # "│ " padding both sides

    def __init__(
        self,
        *,
        case_id: str,
        evidence_summary: str = "",
        stream: io.TextIOBase | None = None,
        in_place: bool | None = None,
    ) -> None:
        self.case_id = case_id
        self.evidence_summary = evidence_summary
        self.stream = stream or sys.stderr
        # Default mode: in-place if TTY, append-only otherwise.
        # MH_NO_TUI=1 forces append-only even on TTY.
        if in_place is None:
            tty = getattr(self.stream, "isatty", lambda: False)()
            in_place = tty and os.environ.get("MH_NO_TUI", "0") != "1"
        self.in_place = in_place

        # Mutable state shown in the right pane / progress bar.
        self.node_status: dict[str, str] = {n: "pending" for n in PIPELINE_NODES}
        self.node_elapsed: dict[str, float] = {}
        self.current_node: str | None = None
        self.current_node_start: float | None = None
        # NOW area: two lines.
        self.now_line1 = "idle · waiting for first node"
        self.now_line2 = ""
        self.now_started: float | None = None
        # Right-pane live state.
        self.state_summary: dict[str, str] = {
            "phase": "—", "picerl": "—", "iso27035": "—",
            "severity": "pending", "findings": "0", "attck": "0",
            "csf": "0", "subagent": "—", "dissent": "—",
        }
        self._run_start = time.monotonic()
        self._frames_drawn = 0
        self._lock = threading.Lock()

    # ─── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        self._render()

    def stop(self, *, success: bool = True) -> None:
        # Final frame + a trailing newline so subsequent output doesn't
        # clobber the dashboard.
        if self.current_node and self.node_status.get(self.current_node) == "running":
            # Edge case: stopped mid-node.
            self.node_status[self.current_node] = "done" if success else "failed"
        self._render(final=True)
        print(file=self.stream, flush=True)

    # ─── per-node hooks ───────────────────────────────────────────────────

    def node_start(self, node_name: str) -> None:
        with self._lock:
            if node_name in self.node_status:
                self.node_status[node_name] = "running"
            self.current_node = node_name
            self.current_node_start = time.monotonic()
            self.now_line1 = f"{node_name} · entered"
            self.now_line2 = "waiting for first sub-action"
            self.now_started = self.current_node_start
        # Lifecycle events bypass the append-only throttle — they're rare
        # and structurally significant; missing one breaks the trace.
        self._render(force=True)

    def node_end(self, node_name: str, *, ok: bool, elapsed_s: float) -> None:
        with self._lock:
            if node_name in self.node_status:
                self.node_status[node_name] = "done" if ok else "failed"
            self.node_elapsed[node_name] = elapsed_s
            if self.current_node == node_name:
                self.now_line1 = f"{node_name} · {'completed' if ok else 'FAILED'} in {_fmt_duration(elapsed_s)}"
                self.now_line2 = ""
        self._render(force=True)

    # ─── live-action signal ──────────────────────────────────────────────

    def now(self, line1: str, line2: str = "") -> None:
        """Update the 2-line NOW area. Called by subagent / MCP / verifier
        hooks each time the current action changes."""
        with self._lock:
            self.now_line1 = line1
            self.now_line2 = line2
            if self.now_started is None:
                self.now_started = time.monotonic()
        self._render()

    # ─── state panel ─────────────────────────────────────────────────────

    def update_state(self, **kwargs: str) -> None:
        """Merge into the right-pane summary. Caller chooses keys."""
        with self._lock:
            for k, v in kwargs.items():
                self.state_summary[k] = str(v)
        self._render()

    # ─── render ──────────────────────────────────────────────────────────

    def _render(self, *, final: bool = False, force: bool = False) -> None:
        if os.environ.get("MH_QUIET", "0") == "1":
            return
        frame = self._build_frame()
        if self.in_place:
            # Move cursor back to start of dashboard area, then redraw.
            # Frame is fixed height — count lines once.
            n_lines = frame.count("\n") + 1
            if self._frames_drawn > 0:
                # Cursor up N lines, then carriage return.
                self.stream.write(f"\033[{n_lines}A\r")
            self.stream.write(frame)
            self.stream.write("\n")
            self.stream.flush()
        else:
            # Append-only: throttle the high-frequency now() updates to one
            # frame every 2s so the log stays readable. node_start/node_end
            # set force=True to bypass — those are structurally significant
            # and rare.
            now = time.monotonic()
            if not (final or force) and self._frames_drawn > 0:
                last = getattr(self, "_last_append", 0.0)
                if now - last < 2.0:
                    return
            self.stream.write(frame)
            self.stream.write("\n\n")
            self.stream.flush()
            self._last_append = now
        self._frames_drawn += 1

    def _build_frame(self) -> str:
        cols = shutil.get_terminal_size((100, 24)).columns
        # The dashboard is fixed-width (OUTER_WIDTH). If the terminal is
        # narrower, the box will wrap — that's the caller's problem; we
        # don't try to reflow into an arbitrary width.
        rows: list[str] = []
        rows.extend(self._render_header())
        rows.extend(self._render_panes())
        rows.extend(self._render_now_area())
        rows.extend(self._render_progress_bar())
        return "\n".join(rows)

    # ── header ──────────────────────────────────────────────────────────

    def _render_header(self) -> list[str]:
        title = f"MemoryHound · {self.case_id}"
        subtitle = self.evidence_summary or "(no evidence summary)"
        bold = _C["bold"]; cyan = _C["cyan"]; reset = _C["reset"]
        return [
            "┌─ " + bold + cyan + title + reset + " " + "─" * max(0, self.OUTER_WIDTH - 5 - _strip_ansi_len(title) - 1) + "┐",
            "│ " + _C["dim"] + _pad_visible(subtitle, self.OUTER_WIDTH - 4) + reset + " │",
            "├" + "─" * self.LEFT_WIDTH + "─┬─" + "─" * self.RIGHT_WIDTH + "┤",
        ]

    # ── two-pane body ────────────────────────────────────────────────────

    def _render_panes(self) -> list[str]:
        left = self._render_pipeline_pane()
        right = self._render_state_pane()
        # Equal-height; right-pad shorter pane with blank lines.
        height = max(len(left), len(right))
        left += [""] * (height - len(left))
        right += [""] * (height - len(right))
        out: list[str] = []
        for L, R in zip(left, right):
            out.append(
                "│ " + _pad_visible(L, self.LEFT_WIDTH) + " │ "
                + _pad_visible(R, self.RIGHT_WIDTH) + " │"
            )
        return out

    def _render_pipeline_pane(self) -> list[str]:
        bold = _C["bold"]; reset = _C["reset"]; dim = _C["dim"]
        lines = [bold + "PIPELINE" + reset, dim + "─" * (self.LEFT_WIDTH - 2) + reset]
        for name in PIPELINE_NODES:
            status = self.node_status.get(name, "pending")
            if status == "running":
                elapsed = time.monotonic() - (self.current_node_start or time.monotonic())
                suffix = f" {_C['yellow']}({_fmt_duration(elapsed)}){reset}"
                line = f"{_C['cyan']}{_SYM_RUNNING}{reset} {bold}{name}{reset}{suffix}"
            elif status == "done":
                el = self.node_elapsed.get(name, 0.0)
                line = f"{_C['green']}{_SYM_DONE}{reset} {name} {dim}{_fmt_duration(el)}{reset}"
            elif status == "failed":
                line = f"{_C['red']}{_SYM_FAIL}{reset} {bold}{_C['red']}{name}{reset}"
            else:
                line = f"{dim}{_SYM_PENDING} {name}{reset}"
            lines.append(line)
        return lines

    def _render_state_pane(self) -> list[str]:
        bold = _C["bold"]; reset = _C["reset"]; dim = _C["dim"]; green = _C["green"]
        s = self.state_summary
        lines = [bold + "LIVE STATE" + reset, dim + "─" * (self.RIGHT_WIDTH - 2) + reset]
        # Layout: label : value pairs, fixed-label-width 12 chars.
        def kv(label: str, value: str, color: str = "") -> str:
            return f"{dim}{label:<10}{reset}{color}{value}{reset}"
        lines += [
            kv("Phase",    s["phase"]),
            kv("PICERL",   s["picerl"]),
            kv("ISO 27035", s["iso27035"]),
            kv("Severity", s["severity"], _C["yellow"] if s["severity"] not in {"pending", "—"} else ""),
            kv("Findings", s["findings"], green if s["findings"] not in {"0", "—"} else ""),
            kv("ATT&CK",   s["attck"]),
            kv("CSF",      s["csf"] + " satisfied"),
            "",
            kv("Subagent", s["subagent"], _C["cyan"]),
            kv("Dissent",  s["dissent"], _C["red"] if s["dissent"] not in {"—", "0", "0 of 0"} else ""),
        ]
        return lines

    # ── NOW area ────────────────────────────────────────────────────────

    def _render_now_area(self) -> list[str]:
        bold = _C["bold"]; reset = _C["reset"]; dim = _C["dim"]
        elapsed = ""
        if self.now_started is not None:
            elapsed = f"  {dim}({_fmt_duration(time.monotonic() - self.now_started)}){reset}"
        l1 = f"{bold}NOW ›{reset} {self.now_line1}{elapsed}"
        l2 = f"      {dim}└ {self.now_line2}{reset}" if self.now_line2 else f"      {dim}└ —{reset}"
        return [
            "├" + "─" * (self.OUTER_WIDTH - 2) + "┤",
            "│ " + _pad_visible(l1, self.OUTER_WIDTH - 4) + " │",
            "│ " + _pad_visible(l2, self.OUTER_WIDTH - 4) + " │",
        ]

    # ── progress bar ────────────────────────────────────────────────────

    def _render_progress_bar(self) -> list[str]:
        reset = _C["reset"]; green = _C["green"]; dim = _C["dim"]
        done = sum(1 for s in self.node_status.values() if s in {"done", "failed"})
        total = len(PIPELINE_NODES)
        bar_inner = self.OUTER_WIDTH - 18  # frame for "[bar] N/M · elapsed"
        filled = int(bar_inner * done / total) if total else 0
        bar = green + ("█" * filled) + reset + dim + ("░" * (bar_inner - filled)) + reset
        elapsed = _fmt_duration(time.monotonic() - self._run_start)
        center = f"{done}/{total} · {elapsed}"
        line = f"[{bar}] {center}"
        return [
            "├" + "─" * (self.OUTER_WIDTH - 2) + "┤",
            "│ " + _pad_visible(line, self.OUTER_WIDTH - 4) + " │",
            "└" + "─" * (self.OUTER_WIDTH - 2) + "┘",
        ]


# ─── module-level singleton + facade ──────────────────────────────────────
#
# The orchestrator wraps nodes via NODES = {name: wrap(fn) for ...} in
# nodes/__init__.py. Each wrapped node fires tui.node_start / node_end via
# this singleton. claude_node.invoke_subagent fires tui.now() to update
# the live-action area. The singleton avoids threading a Tui handle
# through every callsite.

_TUI: Tui | None = None


def get() -> Tui | None:
    """Return the active Tui, or None if not started."""
    return _TUI


def start(*, case_id: str, evidence_summary: str = "") -> Tui:
    """Initialize the singleton and paint the first frame."""
    global _TUI
    if os.environ.get("MH_QUIET", "0") == "1":
        # Tests / CI — no TUI at all.
        return _NullTui()  # type: ignore[return-value]
    _TUI = Tui(case_id=case_id, evidence_summary=evidence_summary)
    _TUI.start()
    return _TUI


def stop(*, success: bool = True) -> None:
    global _TUI
    if _TUI is not None and not isinstance(_TUI, _NullTui):
        _TUI.stop(success=success)
    _TUI = None


def node_start(name: str) -> None:
    if _TUI is not None:
        _TUI.node_start(name)


def node_end(name: str, *, ok: bool, elapsed_s: float) -> None:
    if _TUI is not None:
        _TUI.node_end(name, ok=ok, elapsed_s=elapsed_s)


def now(line1: str, line2: str = "") -> None:
    if _TUI is not None:
        _TUI.now(line1, line2)


def update_state(**kwargs: str) -> None:
    if _TUI is not None:
        _TUI.update_state(**kwargs)


class _NullTui:
    """No-op stand-in used when MH_QUIET=1 — silences everything."""
    def start(self) -> None: ...
    def stop(self, **_: object) -> None: ...
    def node_start(self, _: str) -> None: ...
    def node_end(self, *_: object, **__: object) -> None: ...
    def now(self, *_: object) -> None: ...
    def update_state(self, **_: object) -> None: ...


# ─── helpers callers may want ─────────────────────────────────────────────


def derive_state_summary(state: dict) -> dict[str, str]:
    """Pluck human-facing fields from an IncidentState for the right pane."""
    findings = list(state.get("_findings") or [])
    by_conf: dict[str, int] = {}
    for f in findings:
        c = (f.get("confidence") or "?").lower()
        by_conf[c] = by_conf.get(c, 0) + 1
    findings_summary = (
        f"{len(findings)}  "
        + f"({by_conf.get('high', 0)} high · {by_conf.get('medium', 0)} med · "
        + f"{by_conf.get('low', 0)} low)"
    ) if findings else "0"
    attck = sorted({t for f in findings for t in (f.get("mitre_attck") or [])})
    decisions = state.get("_verifier_decisions") or []
    dissent_count = sum(1 for d in decisions if (d.get("decision") or "").lower() == "dissent")
    return {
        "phase":    state.get("phase") or "—",
        "iso27035": state.get("iso27035_phase") or "—",
        "severity": state.get("severity") or "pending",
        "findings": findings_summary,
        "attck":    str(len(attck)),
        "csf":      str(len(state.get("csf_subcategories_satisfied") or [])),
        "subagent": state.get("_active_subagent") or "—",
        "dissent":  f"{dissent_count} of {len(decisions)}" if decisions else "—",
    }
