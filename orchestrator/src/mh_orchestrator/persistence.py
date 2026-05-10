"""State checkpoint + history writers."""
from __future__ import annotations

import json
from pathlib import Path

from .state import IncidentState, serialize_state


def write_checkpoint(state: IncidentState, output_dir: Path | str) -> Path:
    """Overwrite output_dir/state.json with the current state snapshot."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "state.json"
    path.write_text(json.dumps(serialize_state(state), indent=2, sort_keys=True))
    return path


def append_history(state: IncidentState, output_dir: Path | str, *, node: str) -> Path:
    """Append one snapshot of state (with extra `node` key) to state.history.jsonl."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "state.history.jsonl"
    snapshot = serialize_state(state)
    snapshot["node"] = node
    with path.open("a") as f:
        f.write(json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n")
    return path
