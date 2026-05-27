"""detect node — fingerprints artifacts and sets _detected_os."""
from __future__ import annotations

import os
from pathlib import Path

from .. import csf_tags, picerl
from ..persistence import append_history, write_checkpoint
from ..state import IncidentState


# Trust-contract fix (#6): when a case is memory-only, peek at the first
# 64 KiB of each memory image for kernel banner signatures and route to
# the correct OS specialist. Previously every memory_dump fell to
# WindowsAgent — fine for Rocba-Memory (Windows), wrong for a Linux or
# macOS dump. The signatures below are the kernel banner strings that
# appear verbatim near the start of an x86_64 memory image:
#   - Windows: NT/PROCESSR/KdVersionBlock pointers + "Microsoft Corporation"
#   - Linux:   the literal "Linux version " banner
#   - macOS:   the literal "Darwin Kernel Version "
# Falling through to "memory_dump" (unchanged) when discrimination fails
# preserves the existing WindowsAgent-fallback path.
_MEM_PROBE_BYTES = 64 * 1024
_MEM_SIGNATURES = (
    (b"Linux version ", "linux"),
    (b"Darwin Kernel Version ", "macos"),
    (b"Microsoft Windows", "windows"),
    (b"\\SystemRoot\\system32\\ntoskrnl.exe", "windows"),
)


def _classify_memory_image(path: Path) -> str | None:
    """Return 'windows' | 'linux' | 'macos' | None for a memory image file.

    None means "I couldn't tell" — caller should keep the file labeled as
    memory_dump and route through the WindowsAgent fallback.
    """
    # LiME header byte-magic is a Linux memory acquisition tool — strong
    # signal even if no banner is present.
    suf = path.suffix.lower()
    if suf == ".lime":
        return "linux"
    try:
        with path.open("rb") as fp:
            head = fp.read(_MEM_PROBE_BYTES)
    except OSError:
        return None
    for needle, os_name in _MEM_SIGNATURES:
        if needle in head:
            return os_name
    return None


def _detect_os_from_evidence(evidence_path: str) -> str:
    """Quick heuristic: scan filenames in evidence dir for OS markers.
    Real os_detect MCP tool is invoked by the LLM nodes; this is the
    deterministic stub used inline by the detect node and short-circuited
    cleanly under MH_NO_CLAUDE=1.

    Memory-dump branch is intentionally LAST so a case dir that contains
    BOTH a memory image AND OS-specific artifacts (e.g. .raw + .evtx hives)
    classifies as the OS — the OS-side artifacts are the higher-signal
    triage target. A memory-only case (just .raw) used to fall through to
    memory_dump → routed to WindowsAgent regardless of the dump's actual
    underlying OS. Now we peek at the file's kernel banner bytes to pick
    the right specialist; if discrimination fails we still return
    "memory_dump" (unchanged behavior, falls to WindowsAgent fallback).

    Rocba case (2026-05) regressed because .raw was missing from this
    heuristic: a 19GB Rocba-Memory.raw with no sibling OS artifacts
    classified as 'unknown' → triage routed to WindowsAgent via the
    fallback default → WindowsAgent tried win_evtx_query / win_registry_get
    on raw bytes → 0 findings shipped to findings.json. The .raw / .mem /
    .dmp / .vmem / .lime / .aff branch closes that gap."""
    p = Path(evidence_path)
    if not p.exists():
        return "unknown"
    files = [f for f in p.rglob("*") if f.is_file()]
    names = " ".join(f.name.lower() for f in files)
    if any(m in names for m in ("ntuser.dat", ".evtx", "prefetch", ".pf")):
        return "windows"
    # Raw NTFS metadata files (disk-image triage, e.g. a $MFT-only collection).
    # NTFS is Windows-only, so these are an unambiguous Windows signal. Without
    # them a $MFT-only case returned 'unknown' → wrong-agent fallback.
    if any(m in names for m in ("$mft", "$logfile", "$usnjrnl", "$boot", "$secure", "$extend")):
        return "windows"
    if any(m in names for m in (".plist", "knowledgec.db", "tracev3")):
        return "macos"
    if any(m in names for m in ("auth.log", "syslog", ".bash_history")):
        return "linux"
    if any(m in names for m in (".raw", ".mem", ".dmp", ".vmem", ".lime", ".aff")):
        # Byte-level discrimination — pick the OS specialist matching the
        # dump's kernel banner. First match wins; if none, stay generic.
        for f in files:
            if f.suffix.lower() in (".raw", ".mem", ".dmp", ".vmem", ".lime", ".aff"):
                classified = _classify_memory_image(f)
                if classified is not None:
                    return classified
        return "memory_dump"
    return "unknown"


def run(state: IncidentState) -> IncidentState:
    from . import emit_message, record_audit  # lazy to avoid circular

    out = Path(state["_output_dir"])
    evidence = os.environ.get("EVIDENCE_PATH", "")
    detected = _detect_os_from_evidence(evidence) if evidence else "unknown"
    state["_detected_os"] = detected
    state["phase"] = "triage"
    state["_node_history"].append("detect")
    csf_tags.mark_satisfied(state, csf_tags.DE_AE_02)
    picerl.advance_iso27035(state, picerl.picerl_phase_for("detect"))

    record_audit(state, event="detect_complete", data={"detected_os": detected})
    emit_message(state, from_agent="orchestrator", to_agent="orchestrator",
                 role="lifecycle", content=f"detect: os={detected}")
    write_checkpoint(state, out)
    append_history(state, out, node="detect")
    return state
