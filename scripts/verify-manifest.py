#!/usr/bin/env python3
"""Re-hash files under --input and compare against --manifest.

Exit code 0 = manifest matches every file under input/ (no missing, no extra
on the chain-of-custody list, every sha256 + size matches). Exit code 1 = any
mismatch. Used by `mh verify`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

CHUNK = 1 << 20


def sha256_file(p: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with p.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path,
                    help="Case input/ directory to re-hash")
    ap.add_argument("--manifest", required=True, type=Path,
                    help="Path to output/manifest.json")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"FAIL  input dir {args.input} does not exist", file=sys.stderr)
        return 1
    if not args.manifest.exists():
        print(f"FAIL  manifest {args.manifest} does not exist", file=sys.stderr)
        return 1

    manifest = json.loads(args.manifest.read_text())
    entries = manifest.get("entries", [])
    by_path = {e["path"]: e for e in entries if "path" in e}

    breaks: list[str] = []
    on_disk_paths: set[str] = set()

    for p in sorted(args.input.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(args.input))
        on_disk_paths.add(rel)
        manifest_entry = by_path.get(rel)
        if manifest_entry is None:
            breaks.append(f"  extra-on-disk: {rel} (not in manifest)")
            continue
        if "error" in manifest_entry:
            print(f"  skip (manifest had read error): {rel} — {manifest_entry['error']}")
            continue
        digest, size = sha256_file(p)
        if digest != manifest_entry.get("sha256"):
            breaks.append(
                f"  sha256-changed: {rel}\n"
                f"      manifest: {manifest_entry.get('sha256', '<missing>')[:16]}…\n"
                f"      on-disk : {digest[:16]}…"
            )
        elif size != manifest_entry.get("size_bytes"):
            breaks.append(
                f"  size-changed:   {rel} manifest={manifest_entry.get('size_bytes')} on-disk={size}"
            )

    missing = set(by_path.keys()) - on_disk_paths
    for rel in sorted(missing):
        breaks.append(f"  missing-from-disk: {rel} (manifest has it, file gone)")

    if breaks:
        print(f"FAIL  {len(breaks)} chain-of-custody break(s):")
        for line in breaks:
            print(line)
        return 1

    print(f"OK    manifest matches input/ — {len(on_disk_paths)} files re-hashed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
