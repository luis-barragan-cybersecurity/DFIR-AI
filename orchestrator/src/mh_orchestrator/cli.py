"""mh-orchestrate CLI — entrypoint registered in pyproject.toml."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .graph import DEFAULT_RECURSION_LIMIT, build_graph
from .state import new_state


def _cmd_run(args: argparse.Namespace) -> int:
    cases_dir = Path(args.cases_dir).expanduser().resolve()
    case_dir = cases_dir / args.case_id
    input_dir = case_dir / "input"
    output_dir = case_dir / "output"
    if not input_dir.exists():
        print(f"error: no evidence at {input_dir}", file=sys.stderr)
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)

    state = new_state(args.case_id)
    state["_output_dir"] = str(output_dir)
    state["_input_dir"] = str(input_dir)

    # ─── start the live TUI dashboard ──────────────────────────────────
    # Reads the case input dir to build the evidence summary line.
    from . import tui
    try:
        evidence_files = sorted(input_dir.iterdir())
        total_bytes = sum(f.stat().st_size for f in evidence_files if f.is_file())
        evidence_summary = (
            f"{len(evidence_files)} artifact(s) · "
            f"{tui._human_size(total_bytes)} · "
            f"{evidence_files[0].name if evidence_files else '—'}"
        )
    except OSError:
        evidence_summary = "(evidence summary unavailable)"
    tui.start(case_id=args.case_id, evidence_summary=evidence_summary)

    # If --recursion-limit not passed, build_graph will honor
    # MH_LG_RECURSION_LIMIT env var, then DEFAULT_RECURSION_LIMIT.
    graph = build_graph(recursion_limit=args.recursion_limit)
    try:
        final = graph.invoke(state)
    except Exception:
        tui.stop(success=False)
        raise
    tui.stop(success=True)

    print(json.dumps({"incident_id": final["incident_id"],
                      "phase": final["phase"],
                      "nodes": final["_node_history"]}))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mh-orchestrate")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Run the orchestrator on a case directory.")
    r.add_argument("case_id")
    r.add_argument("--cases-dir", default=str(Path.cwd() / "cases"))
    r.add_argument(
        "--recursion-limit", type=int, default=None,
        help=(
            f"LangGraph recursion limit (default: ${{MH_LG_RECURSION_LIMIT}} "
            f"or {DEFAULT_RECURSION_LIMIT})"
        ),
    )
    args = p.parse_args(argv)
    if args.cmd == "run":
        return _cmd_run(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
