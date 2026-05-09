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

    # If --recursion-limit not passed, build_graph will honor
    # MH_LG_RECURSION_LIMIT env var, then DEFAULT_RECURSION_LIMIT.
    graph = build_graph(recursion_limit=args.recursion_limit)
    final = graph.invoke(state)
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
