"""Filter tests for the scope node — these are the guardrails added after
the dfrws-2008-memory exec-report was found to fabricate "192.168.151.1"
into affected_hosts and inflate affected_data by ~12× via greedy path
regex against free-text. Each test pins one specific failure mode.
"""
from __future__ import annotations

from pathlib import Path

from mh_orchestrator.nodes import scope
from mh_orchestrator.state import new_state


def _state(findings: list[dict], tmp_path: Path):
    s = new_state("scope-filter-test")
    s["_findings"] = findings
    s["_output_dir"] = str(tmp_path / "output")
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    return s


# ──────────────────────────────────────────────────────────────────────────
# Egress destinations vs victim hosts
# ──────────────────────────────────────────────────────────────────────────


def test_ioc_with_egress_context_goes_to_destinations_not_hosts(tmp_path: Path) -> None:
    """Reproduces the dfrws-2008-memory bug: 219.93.175.67 is the exfil
    proxy. Pre-fix it landed in affected_hosts (leadership read it as
    'we own this'). After fix it must land in egress_destinations only.
    """
    s = _state([{
        "claim": "Outbound HTTP proxy configured to a public IP.",
        "pins": [{
            "artifact": "input/memory.raw",
            "tool": "memory_hunt",
            "locator": {"type": "string", "value": "http_proxy"},
            "raw_excerpt": "http_proxy=http://219.93.175.67:80",
        }],
        "ioc": [{"type": "ip", "value": "219.93.175.67",
                 "context": "egress / outbound"}],
    }], tmp_path)
    out = scope.compute_scope(s)
    assert "219.93.175.67" in out["egress_destinations"]
    assert "219.93.175.67" not in out["affected_hosts"]


def test_destination_label_wins_when_same_ip_seen_both_ways(tmp_path: Path) -> None:
    """If the same IP is regex-scraped from raw_excerpt AND labeled an
    egress destination by another finding, the destination label wins —
    a destination cannot also be a victim host.
    """
    s = _state([
        {
            "claim": "first finding mentions 1.2.3.4",
            "pins": [{
                "artifact": "x", "tool": "y",
                "locator": {"type": "log", "value": "..."},
                "raw_excerpt": "talked to 1.2.3.4",
            }],
        },
        {
            "claim": "second finding flags 1.2.3.4 as outbound proxy",
            "pins": [{"artifact": "x", "tool": "y",
                      "locator": {"type": "log", "value": "..."},
                      "raw_excerpt": "proxy=1.2.3.4"}],
            "ioc": [{"type": "ip", "value": "1.2.3.4",
                     "context": "outbound proxy"}],
        },
    ], tmp_path)
    out = scope.compute_scope(s)
    assert "1.2.3.4" in out["egress_destinations"]
    assert "1.2.3.4" not in out["affected_hosts"]


def test_ip_with_no_ioc_context_still_becomes_a_host(tmp_path: Path) -> None:
    """Backward compat: pre-existing test_compute_scope_extracts_hosts_from_pins
    asserts that IPs in raw_excerpt with no ioc[] still flow to
    affected_hosts. Re-verify here so the change doesn't silently regress
    the fallback path.
    """
    s = _state([{
        "claim": "outbound C2",
        "pins": [{
            "artifact": "memory.raw", "tool": "windows.netscan",
            "locator": {"type": "memory_vad", "value": "tcp 10.0.2.15:443"},
            "raw_excerpt": "ForeignAddr 142.250.182.3 ESTABLISHED",
        }],
    }], tmp_path)
    out = scope.compute_scope(s)
    assert "10.0.2.15" in out["affected_hosts"]
    assert "142.250.182.3" in out["affected_hosts"]
    assert out["egress_destinations"] == []


def test_non_ip_ioc_does_not_pollute_destinations(tmp_path: Path) -> None:
    """An ioc[] entry of type=domain should not affect IP destination
    classification. Only type=ip should be considered."""
    s = _state([{
        "claim": "malware contacted evil.example.com",
        "pins": [{"artifact": "x", "tool": "y",
                  "locator": {"type": "log", "value": "..."},
                  "raw_excerpt": "GET evil.example.com"}],
        "ioc": [{"type": "domain", "value": "evil.example.com",
                 "context": "command-and-control"}],
    }], tmp_path)
    out = scope.compute_scope(s)
    assert out["egress_destinations"] == []


# ──────────────────────────────────────────────────────────────────────────
# OS-noise paths filtered from affected_data
# ──────────────────────────────────────────────────────────────────────────


def test_os_default_paths_are_filtered_from_affected_data(tmp_path: Path) -> None:
    """/usr/lib/, /etc/, /Library/ etc. are OS defaults — they appear
    constantly in finding text but don't represent exposed data. Pre-fix
    the dfrws exec-report claimed 13 'data locations' built largely from
    these.
    """
    s = _state([{
        "claim": "process loaded /usr/lib/libc.so.6 and read /etc/passwd",
        "pins": [{
            "artifact": "/Library/Frameworks/foo", "tool": "y",
            "locator": {"type": "path", "value": "/System/Library/CoreServices"},
            "raw_excerpt": "ld /opt/homebrew/lib/libx",
        }],
    }], tmp_path)
    out = scope.compute_scope(s)
    for noise in ("/usr/lib/libc.so.6", "/etc/passwd",
                  "/Library/Frameworks/foo",
                  "/System/Library/CoreServices",
                  "/opt/homebrew/lib/libx"):
        assert noise not in out["affected_data"], (
            f"OS-noise path leaked into affected_data: {noise!r}")


def test_user_data_paths_still_pass_filter(tmp_path: Path) -> None:
    """Filter must not over-fire — real user/exfil paths must still flow
    to affected_data. Asserts the existing test_compute_scope_extracts_data_paths
    contract still holds for non-OS paths.
    """
    s = _state([{
        "claim": "files staged at /tmp/exfil/data.tar; /home/alice/secret.docx copied",
        "pins": [{
            "artifact": "C:\\Users\\bob\\Documents\\plan.pptx", "tool": "y",
            "locator": {"type": "path", "value": "/srv/payroll/q4.xlsx"},
            "raw_excerpt": "...",
        }],
    }], tmp_path)
    out = scope.compute_scope(s)
    assert any("/tmp/exfil/data.tar" in d for d in out["affected_data"])
    assert any("/home/alice/secret.docx" in d for d in out["affected_data"])
    assert any("plan.pptx" in d for d in out["affected_data"])
    assert any("/srv/payroll/q4.xlsx" in d for d in out["affected_data"])


def test_forensic_artifact_paths_bypass_noise_filter(tmp_path: Path) -> None:
    """Artifacts listed on state.forensic_artifacts are operator-supplied
    evidence inputs, not regex hits — they must always appear in
    affected_data regardless of where they live on disk."""
    from mh_orchestrator.state import Artifact
    s = new_state("scope-art-noise")
    s["forensic_artifacts"] = [
        Artifact(path="/Library/Logs/case-evidence/dump.raw"),
    ]
    out = scope.compute_scope(s)
    assert "/Library/Logs/case-evidence/dump.raw" in out["affected_data"]


# ──────────────────────────────────────────────────────────────────────────
# scope.run wires the new bucket into state
# ──────────────────────────────────────────────────────────────────────────


def test_user_pattern_denylist_filters_english_nouns(tmp_path: Path) -> None:
    """'User directories are direct indicators of attack' should NOT
    promote 'directories' to a username. Real-world false positive
    found in the dfrws-2008-memory case."""
    s = _state([{
        "claim": "User directories are direct indicators of attack patterns",
        "pins": [],
    }], tmp_path)
    out = scope.compute_scope(s)
    assert "directories" not in out["affected_users"]


def test_user_pattern_still_extracts_real_usernames(tmp_path: Path) -> None:
    """Denylist must not over-fire — real-looking usernames after
    'user '/'user:'/'user=' must still flow through."""
    s = _state([
        {"claim": "User alice ran cmd.exe", "pins": []},
        {"claim": "user=bob02 launched powershell", "pins": []},
        {"claim": "user: carol-svc accessed lsass", "pins": []},
    ], tmp_path)
    out = scope.compute_scope(s)
    assert "alice" in out["affected_users"]
    assert "bob02" in out["affected_users"]
    assert "carol-svc" in out["affected_users"]


def test_run_persists_egress_destinations_to_state(tmp_path: Path) -> None:
    s = _state([{
        "claim": "exfil proxy",
        "pins": [{"artifact": "x", "tool": "y",
                  "locator": {"type": "log", "value": "..."},
                  "raw_excerpt": "proxy=5.6.7.8"}],
        "ioc": [{"type": "ip", "value": "5.6.7.8", "context": "exfil"}],
    }], tmp_path)
    out = scope.run(s)
    assert "egress_destinations" in out
    assert "5.6.7.8" in out["egress_destinations"]
    assert "5.6.7.8" not in out["affected_hosts"]
