"""Provider registry auto-detect + explicit override matrix.

Pins ISC-20..26 from the multi-provider abstraction ISA. Tests assert that:

- ``MH_PROVIDER`` env wins when set to any valid name.
- Auto-detect order is anthropic-cli > anthropic-api > openai > ollama.
- Each detect step fires only when its precondition is met.
- ``get_provider`` returns the correct concrete subclass and never crashes
  when an optional SDK is absent (registry only imports it on demand).
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from mh_orchestrator.providers import (
    Provider,
    get_provider,
    list_providers,
    resolve_provider_name,
)
from mh_orchestrator.providers.anthropic_cli import AnthropicCliProvider


_VALID = ("anthropic-cli", "anthropic-api", "openai", "ollama")


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    """Strip every provider-affecting env var before each test."""
    for var in (
        "MH_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
        "OLLAMA_HOST", "CLAUDECODE",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


def test_list_providers_returns_valid_set():
    assert set(list_providers()) == set(_VALID)


def test_mh_provider_env_explicit_anthropic_cli(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "anthropic-cli")
    assert resolve_provider_name() == "anthropic-cli"


def test_mh_provider_env_explicit_anthropic_api(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "anthropic-api")
    assert resolve_provider_name() == "anthropic-api"


def test_mh_provider_env_explicit_openai(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "openai")
    assert resolve_provider_name() == "openai"


def test_mh_provider_env_explicit_ollama(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "ollama")
    assert resolve_provider_name() == "ollama"


def test_mh_provider_env_case_insensitive_and_trimmed(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "  OLLAMA  ")
    assert resolve_provider_name() == "ollama"


def test_unknown_mh_provider_falls_through_to_auto_detect(monkeypatch, tmp_path):
    """An unrecognised MH_PROVIDER must not be silently honored; the resolver
    falls back to auto-detect. Preflight then surfaces the misspelling."""
    monkeypatch.setenv("MH_PROVIDER", "not-a-real-provider")
    # Force auto-detect to anthropic-api by setting just that key.
    monkeypatch.setenv("PATH", "/dev/null")  # no claude binary
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert resolve_provider_name() == "anthropic-api"


def test_autodetect_claude_cli_when_on_path_and_not_nested(monkeypatch, tmp_path):
    """ISC-23: anthropic-cli wins when `claude` is on PATH and CLAUDECODE unset."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "claude").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "claude").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}/usr/bin")
    monkeypatch.delenv("CLAUDECODE", raising=False)
    assert resolve_provider_name() == "anthropic-cli"


def test_autodetect_skips_anthropic_cli_when_nested(monkeypatch, tmp_path):
    """When CLAUDECODE=1, the anthropic-cli rule does not fire — nested
    `claude -p` calls hang per PAI constitutional rules."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "claude").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "claude").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}/usr/bin")
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert resolve_provider_name() == "anthropic-api"


def test_autodetect_anthropic_api_when_only_key_set(monkeypatch):
    """ISC-24."""
    monkeypatch.setenv("PATH", "/dev/null")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert resolve_provider_name() == "anthropic-api"


def test_autodetect_openai_when_only_openai_key_set(monkeypatch):
    """ISC-25."""
    monkeypatch.setenv("PATH", "/dev/null")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-test")
    assert resolve_provider_name() == "openai"


def test_autodetect_ollama_when_daemon_responds(monkeypatch):
    """ISC-26: stub the registry's daemon probe to True, no other signals."""
    monkeypatch.setenv("PATH", "/dev/null")
    from mh_orchestrator.providers import registry as reg
    monkeypatch.setattr(reg, "_ollama_responding", lambda host, timeout=2.0: True)
    assert resolve_provider_name() == "ollama"


def test_autodetect_falls_back_to_anthropic_cli_when_nothing_set(monkeypatch):
    """No env vars, no daemon — fallback is anthropic-cli (preflight will
    catch the missing binary)."""
    monkeypatch.setenv("PATH", "/dev/null")
    from mh_orchestrator.providers import registry as reg
    monkeypatch.setattr(reg, "_ollama_responding", lambda host, timeout=2.0: False)
    assert resolve_provider_name() == "anthropic-cli"


def test_get_provider_anthropic_cli_returns_concrete_subclass(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "anthropic-cli")
    p = get_provider()
    assert isinstance(p, AnthropicCliProvider)
    assert isinstance(p, Provider)
    assert p.name == "anthropic-cli"


def test_get_provider_with_explicit_name_bypasses_env(monkeypatch):
    monkeypatch.setenv("MH_PROVIDER", "ollama")
    p = get_provider(name="anthropic-cli")
    assert isinstance(p, AnthropicCliProvider)


def test_get_provider_rejects_unknown_name_with_clear_error():
    with pytest.raises(RuntimeError, match="Unknown provider"):
        get_provider(name="not-real")
