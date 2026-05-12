"""Tests for the YARA scanner wrapper.

Skips gracefully when yara-python isn't installed in the test env.
The autouse `_sandbox_env` fixture in conftest.py pins EVIDENCE_PATH to
`tmp_path/input` — all fixtures live under that root.
"""
from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from protocol_sift_mcp.tools.parse import YaraToolError, yara_scan  # noqa: E402


def _write_rules(tmp_path, body: str):
    # Rules can live anywhere — they're not sandbox-asserted (analyst library).
    p = tmp_path / "rules.yar"
    p.write_text(body)
    return p


def test_yara_scan_single_file_match(tmp_path):
    inp = tmp_path / "input"
    target = inp / "evidence.bin"
    target.write_text("the canary string lives here")
    rules = _write_rules(tmp_path, """
rule canary {
  strings:
    $a = "canary string"
  condition:
    $a
}
""")
    hits = yara_scan(str(target), str(rules))
    assert len(hits) == 1
    assert hits[0]["rule"] == "canary"
    assert hits[0]["strings"]


def test_yara_scan_no_match_returns_empty(tmp_path):
    inp = tmp_path / "input"
    target = inp / "evidence.bin"
    target.write_text("nothing interesting here")
    rules = _write_rules(tmp_path, """
rule canary { strings: $a = "missing" condition: $a }
""")
    hits = yara_scan(str(target), str(rules))
    assert hits == []


def test_yara_scan_directory_recursive(tmp_path):
    inp = tmp_path / "input"
    (inp / "a.bin").write_text("canary")
    (inp / "sub").mkdir()
    (inp / "sub" / "b.bin").write_text("canary too")
    rules = _write_rules(tmp_path, """
rule c { strings: $a = "canary" condition: $a }
""")
    hits = yara_scan(str(inp), str(rules), recursive=True)
    assert len(hits) == 2


def test_yara_scan_missing_rule_file_raises(tmp_path):
    inp = tmp_path / "input"
    (inp / "x").write_text("ok")
    with pytest.raises(YaraToolError):
        yara_scan(str(inp / "x"), str(tmp_path / "no-such-rule.yar"))


def test_yara_scan_malformed_rule_raises(tmp_path):
    inp = tmp_path / "input"
    (inp / "x").write_text("ok")
    bad = _write_rules(tmp_path, "this is not yara syntax")
    with pytest.raises(YaraToolError):
        yara_scan(str(inp / "x"), str(bad))


def test_yara_scan_max_hits_bounds_output(tmp_path):
    inp = tmp_path / "input"
    for i in range(20):
        (inp / f"f{i:02d}.bin").write_text("canary")
    rules = _write_rules(tmp_path, """
rule c { strings: $a = "canary" condition: $a }
""")
    hits = yara_scan(str(inp), str(rules), recursive=True, max_hits=5)
    assert len(hits) == 5
