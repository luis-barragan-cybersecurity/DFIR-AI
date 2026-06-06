"""proc_activity sampler tests — uses real short-lived subprocesses, no mocks."""
from __future__ import annotations

import os
import subprocess
import time

from mh_orchestrator import proc_activity


def test_proc_available_is_true_on_linux():
    # SIFT/CI is Linux; /proc exists.
    assert proc_activity.proc_available() is True


def test_busy_process_registers_cpu_activity():
    # A tight busy-loop in its own session/group burns CPU between samples.
    proc = subprocess.Popen(
        ["python3", "-c", "x=0\nwhile True:\n x+=1"],
        start_new_session=True,
    )
    try:
        pgid = os.getpgid(proc.pid)
        first = proc_activity.read_pgroup_cpu(pgid)
        time.sleep(0.5)
        second = proc_activity.read_pgroup_cpu(pgid)
        assert proc_activity.cpu_advanced(first, second) is True
    finally:
        os.killpg(os.getpgid(proc.pid), 9)
        proc.wait()


def test_idle_process_registers_no_cpu_activity():
    # Mildly timing-sensitive: under heavy host load an idle sleep could
    # accrue a stray jiffy, but in practice it stays flat across 0.5s.
    proc = subprocess.Popen(["sleep", "5"], start_new_session=True)
    try:
        pgid = os.getpgid(proc.pid)
        first = proc_activity.read_pgroup_cpu(pgid)
        time.sleep(0.5)
        second = proc_activity.read_pgroup_cpu(pgid)
        assert proc_activity.cpu_advanced(first, second) is False
    finally:
        os.killpg(os.getpgid(proc.pid), 9)
        proc.wait()


def test_read_pgroup_cpu_never_raises_on_bad_pgid():
    # A pgid with no live members returns an empty mapping, no exception.
    assert proc_activity.read_pgroup_cpu(999999) == {}


def test_cpu_advanced_pure_logic():
    assert proc_activity.cpu_advanced({}, {}) is False
    assert proc_activity.cpu_advanced({}, {1: 100}) is True          # new pid counts first reading
    assert proc_activity.cpu_advanced({1: 100}, {1: 101}) is True    # burned CPU
    assert proc_activity.cpu_advanced({1: 100}, {1: 100}) is False   # idle (no delta)
    assert proc_activity.cpu_advanced({1: 100}, {}) is False         # exited pid ignored
