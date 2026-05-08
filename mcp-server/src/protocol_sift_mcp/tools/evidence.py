"""Evidence hashing primitives.

Reduced from the prior trust-stack module — chain-of-custody, signing, and
attestation were removed. Plain audit-log behavior lives in `audit.py`.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from ..sandbox import assert_input_path
from . import audit

HASH_ALGO = "sha256"


def hash_file(path: Path, *, chunk_size: int = 1 << 20) -> dict[str, str | int]:
    """Compute sha256 + sha1 of a file in one pass."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # noqa: S324 - dual-hash for collision resistance
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
            sha1.update(chunk)
            size += len(chunk)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "size": size}


def ingest_artifact(audit_path: Path, artifact: Path) -> dict:
    """Hash an evidence file and append an `evidence_ingest` entry to the audit log."""
    artifact = assert_input_path(artifact)
    digest = hash_file(artifact)
    return audit.audit_append(
        audit_path,
        event="evidence_ingest",
        data={"artifact": str(artifact), **digest},
    )


def main(argv: list[str] | None = None) -> int:
    """CLI: hooks call `python -m protocol_sift_mcp.tools.evidence ingest --audit <log> --artifact <path>`."""
    parser = argparse.ArgumentParser(prog="protocol_sift_mcp.tools.evidence")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest")
    p_ingest.add_argument("--audit", required=True, type=Path)
    p_ingest.add_argument("--artifact", required=True, type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "ingest":
        ingest_artifact(args.audit, args.artifact)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
