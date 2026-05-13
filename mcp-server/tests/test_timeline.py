"""Smoke tests for the Plaso wrappers.

Plaso is heavy + slow; we test the boundary conditions (path validation,
output_format allowlist, missing binary) rather than running real
log2timeline against a fixture.
"""
from __future__ import annotations

import pytest

from protocol_sift_mcp.tools.timeline import (
    PlasoError,
    log2timeline,
    psort,
)


def test_psort_rejects_unknown_output_format(tmp_path):
    store = tmp_path / "output" / "fake.plaso"
    store.write_bytes(b"PLSO")
    with pytest.raises(ValueError, match="output_format"):
        psort(str(store), output_format="not-real")


def test_psort_rejects_missing_storage(tmp_path):
    with pytest.raises(PlasoError, match="plaso storage not found"):
        psort(str(tmp_path / "output" / "nope.plaso"))


def test_log2timeline_requires_existing_source(tmp_path):
    from protocol_sift_mcp.sandbox import SandboxViolation
    with pytest.raises(SandboxViolation):
        log2timeline(
            str(tmp_path / "input" / "no-such"),
            str(tmp_path / "output" / "out.plaso"),
        )


def test_log2timeline_storage_must_be_under_output(tmp_path):
    src = tmp_path / "input" / "src"
    src.mkdir()
    from protocol_sift_mcp.sandbox import SandboxViolation
    with pytest.raises(SandboxViolation):
        log2timeline(str(src), str(tmp_path / "elsewhere.plaso"))  # outside OUTPUT_PATH
