"""Process-group CPU-activity sampler for the subagent liveness monitor.

Linux /proc-native (the SIFT target), stdlib only. Lets claude_node's monitor
tell a busy subagent (a forensic tool burning CPU) apart from a hung one (idle,
blocked on stdin). On non-Linux (/proc absent) the caller degrades to
stdout-activity-only liveness.
"""
from __future__ import annotations

import os
from pathlib import Path


def proc_available() -> bool:
    """True when /proc is present as a directory (Linux). A mounted-but-unreadable /proc still degrades safely: read_pgroup_cpu returns {} on listdir failure."""
    return Path("/proc").is_dir()


def read_pgroup_cpu(pgid: int) -> dict[int, int]:
    """Map pid -> cumulative CPU jiffies (utime+stime) for every process whose
    process-group id == pgid. Per-pid races (a process exits mid-scan) are
    swallowed so the sampler never raises.
    """
    cpu: dict[int, int] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return cpu
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", encoding="utf-8") as fh:
                line = fh.read()
            # Field 2 (comm) is parenthesized and may contain spaces/parens,
            # so parse the fixed fields from after the last ") ". In that tail:
            #   index 2 = pgrp (field 5), index 11 = utime (14), index 12 = stime (15).
            tail = line.rsplit(") ", 1)[1].split()
            if int(tail[2]) != pgid:
                continue
            cpu[int(name)] = int(tail[11]) + int(tail[12])
        except (OSError, ValueError, IndexError):
            continue
    return cpu


def cpu_advanced(prev: dict[int, int], curr: dict[int, int]) -> bool:
    """True if any process in the group burned CPU between the two samples.
    Uses positive per-pid deltas (new pids count their first reading; exited
    pids are ignored) so child churn never masks real activity."""
    for pid, now in curr.items():
        if now > prev.get(pid, 0):
            return True
    return False
