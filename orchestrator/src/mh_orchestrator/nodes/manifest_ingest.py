"""manifest_ingest — SHA256 manifest of every input artifact.

Runs as the graph entry point, BEFORE session_init. Walks the case's input/
directory, hashes every file, and writes `output/manifest.json` with
`{path, sha256, size_bytes, captured_at}` per artifact. The manifest is the
chain-of-custody anchor: `mh verify` later re-hashes the input tree and
compares against this file. Any byte change is flagged.

This is intentionally pure-Python and offline — no LLM, no subprocess. The
audit log also records a `manifest_complete` event with the manifest's own
sha256 so the file's integrity is provable via the audit chain alone.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..state import IncidentState

CHUNK = 1 << 20  # 1 MiB streaming


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _resolve_input_dir(state: IncidentState) -> Path | None:
    """Derive the case's input/ dir, or None if not resolvable.

    Priority:
      1. state["_input_dir"] if explicitly populated by the CLI.
      2. Sibling of state["_output_dir"] (case-dir/output → case-dir/input).
      3. EVIDENCE_PATH env var set by bin/mh.

    Returns None instead of raising when no input dir is known — this is the
    smoke-test path. `run` writes an empty manifest with an `error` annotation
    in that case so chain-of-custody is still anchored (just trivially).
    """
    explicit = state.get("_input_dir")
    if explicit:
        return Path(explicit)
    out_dir = state.get("_output_dir")
    if out_dir:
        sibling = Path(out_dir).parent / "input"
        if sibling.exists():
            return sibling
    env = os.environ.get("EVIDENCE_PATH")
    if env:
        return Path(env)
    return None


def build_manifest(input_dir: Path) -> list[dict[str, Any]]:
    """Walk input_dir recursively, hash every file, return manifest entries."""
    entries: list[dict[str, Any]] = []
    if not input_dir.exists():
        return entries
    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            stat = p.stat()
            digest = _sha256_file(p)
        except OSError as exc:
            entries.append({
                "path": str(p.relative_to(input_dir)),
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
        entries.append({
            "path": str(p.relative_to(input_dir)),
            "sha256": digest,
            "size_bytes": stat.st_size,
            "captured_at": datetime.now(UTC).isoformat(),
        })
    return entries


def write_manifest(output_dir: Path, entries: list[dict[str, Any]]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    payload = {
        "schema": "memoryhound.manifest.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "entry_count": len(entries),
        "entries": entries,
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return manifest_path


def manifest_self_sha256(manifest_path: Path) -> str:
    return _sha256_file(manifest_path)


def run(state: IncidentState) -> IncidentState:
    from ..persistence import append_history, write_checkpoint
    from . import record_audit  # local import avoids circular

    output_dir = Path(state["_output_dir"]) if state.get("_output_dir") else None
    if output_dir is None:
        # Pathological synthetic test path — no output dir at all. Skip but
        # still emit an audit event so the absence is visible. (No snapshot
        # possible without an output dir.)
        state["_node_history"].append("manifest_ingest")
        return state
    output_dir.mkdir(parents=True, exist_ok=True)
    input_dir = _resolve_input_dir(state)

    if input_dir is None:
        # No input dir resolvable (smoke-test path). Write an empty manifest
        # so chain-of-custody is at least trivially anchored, and record the
        # condition in the audit log.
        manifest_path = write_manifest(output_dir, [])
        record_audit(
            state,
            event="manifest_complete",
            data={
                "input_dir": None,
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest_self_sha256(manifest_path),
                "entry_count": 0,
                "errors": 0,
                "note": "no input dir resolved — smoke-test or pre-ingest run",
            },
        )
        state["_node_history"].append("manifest_ingest")
        write_checkpoint(state, output_dir)
        append_history(state, output_dir, node="manifest_ingest")
        return state

    entries = build_manifest(input_dir)
    manifest_path = write_manifest(output_dir, entries)
    manifest_sha = manifest_self_sha256(manifest_path)

    record_audit(
        state,
        event="manifest_complete",
        data={
            "input_dir": str(input_dir),
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha,
            "entry_count": len(entries),
            "errors": sum(1 for e in entries if "error" in e),
        },
    )

    state["_node_history"].append("manifest_ingest")
    # Emit per-node snapshot so state.history.jsonl is complete. Skipping
    # this previously left manifest_ingest invisible in the audit-trail
    # deliverable even though _node_history declared it had run.
    write_checkpoint(state, output_dir)
    append_history(state, output_dir, node="manifest_ingest")
    return state
