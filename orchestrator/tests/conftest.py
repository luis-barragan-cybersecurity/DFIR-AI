"""Shared orchestrator test fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_case(tmp_path: Path) -> Path:
    case = tmp_path / "cases" / "case-001"
    (case / "input").mkdir(parents=True)
    (case / "input" / "sample.bin").write_bytes(b"hello")
    (case / "output").mkdir()
    return case


@pytest.fixture(autouse=True)
def _no_claude(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MH_NO_CLAUDE", "1")
