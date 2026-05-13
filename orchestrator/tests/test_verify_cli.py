"""Integration smoke for the `scripts/verify-manifest.py` helper.

Validates the spoliation-test pathway end to end against a freshly-built
manifest, plus the tamper-detection negative case.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "verify-manifest.py"


def _build_manifest(input_dir: Path, manifest_path: Path) -> None:
    from mh_orchestrator.nodes.manifest_ingest import build_manifest, write_manifest

    entries = build_manifest(input_dir)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    out_dir = manifest_path.parent
    written = write_manifest(out_dir, entries)
    # write_manifest always names the file 'manifest.json' under out_dir.
    if written != manifest_path:
        # Move/rename — for compatibility with this test's API.
        written.rename(manifest_path)


def test_verify_manifest_clean(tmp_path):
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "a.txt").write_text("alpha")
    (inp / "b.bin").write_bytes(b"\x01\x02\x03")
    manifest = tmp_path / "output" / "manifest.json"
    _build_manifest(inp, manifest)

    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(inp), "--manifest", str(manifest)],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK" in r.stdout


def test_verify_manifest_detects_tamper(tmp_path):
    inp = tmp_path / "input"
    inp.mkdir()
    target = inp / "a.txt"
    target.write_text("original")
    manifest = tmp_path / "output" / "manifest.json"
    _build_manifest(inp, manifest)

    # Tamper.
    target.write_text("tampered")

    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(inp), "--manifest", str(manifest)],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 1
    assert "sha256-changed" in r.stdout or "size-changed" in r.stdout


def test_verify_manifest_detects_extra_file(tmp_path):
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "a.txt").write_text("one")
    manifest = tmp_path / "output" / "manifest.json"
    _build_manifest(inp, manifest)

    # Add a new file post-manifest.
    (inp / "b.txt").write_text("snuck in")

    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(inp), "--manifest", str(manifest)],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 1
    assert "extra-on-disk" in r.stdout


def test_verify_manifest_detects_missing_file(tmp_path):
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "a.txt").write_text("one")
    (inp / "b.txt").write_text("two")
    manifest = tmp_path / "output" / "manifest.json"
    _build_manifest(inp, manifest)

    # Remove one.
    (inp / "b.txt").unlink()

    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(inp), "--manifest", str(manifest)],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 1
    assert "missing-from-disk" in r.stdout


def test_verify_manifest_missing_paths_fail_fast(tmp_path):
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--input", str(tmp_path / "nope"),
         "--manifest", str(tmp_path / "nope.json")],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 1


def test_manifest_round_trips_through_verify(tmp_path):
    """A manifest written by build_manifest must always verify clean against
    its source — the script is the inverse of the manifest builder."""
    inp = tmp_path / "input"
    inp.mkdir()
    for i in range(5):
        (inp / f"f{i}.bin").write_bytes(bytes([i]) * 100)
    manifest = tmp_path / "out" / "manifest.json"
    _build_manifest(inp, manifest)
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(inp), "--manifest", str(manifest)],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0
    # And manifest content is sane.
    manifest_payload = json.loads(manifest.read_text())
    assert manifest_payload["entry_count"] == 5
