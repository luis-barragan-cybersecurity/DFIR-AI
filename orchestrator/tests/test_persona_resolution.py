"""Subagent-persona resolution across the non-CLI providers.

Regression guard: nodes pass PascalCase identifiers ("WindowsAgent",
"MacOSAgent", "LinuxAgent", "Verifier") while the persona files are kebab-case
("windows-agent.md") with PascalCase `name:` frontmatter. The pre-fix non-CLI
loaders did a naive `<subagent_name>.md` lookup, missed, and silently fell back
to a generic stub — discarding the FOR500/FOR518/FOR577 playbooks on the
anthropic-api / openai / ollama paths. providers.persona.resolve_persona_path
performs the same name→file resolution `claude --agent` does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mh_orchestrator.providers import persona
from mh_orchestrator.providers.anthropic_api import _load_persona as api_persona
from mh_orchestrator.providers.ollama import _persona as ollama_persona
from mh_orchestrator.providers.openai_provider import _load_persona as openai_persona


def _make_agents(project_dir: Path) -> None:
    agents = project_dir / ".claude" / "agents"
    agents.mkdir(parents=True)
    # kebab filename + PascalCase frontmatter name — mirrors the real repo.
    (agents / "windows-agent.md").write_text(
        "---\nname: WindowsAgent\nmodel: sonnet\n---\n"
        "You are the Windows forensic specialist. FOR500 playbook follows.\n"
    )
    (agents / "macos-agent.md").write_text(
        "---\nname: MacOSAgent\n---\nFOR518 macOS specialist persona.\n"
    )
    (agents / "linux-agent.md").write_text(
        "---\nname: LinuxAgent\n---\nFOR577 Linux specialist persona.\n"
    )
    (agents / "verifier.md").write_text(
        "---\nname: Verifier\n---\nIndependent re-verification persona.\n"
    )


@pytest.mark.parametrize("name,expected_file", [
    ("WindowsAgent", "windows-agent.md"),
    ("MacOSAgent", "macos-agent.md"),
    ("LinuxAgent", "linux-agent.md"),
    ("Verifier", "verifier.md"),
])
def test_resolve_pascalcase_to_kebab_file(tmp_path, name, expected_file) -> None:
    _make_agents(tmp_path)
    resolved = persona.resolve_persona_path(tmp_path, name)
    assert resolved is not None, f"{name} should resolve via frontmatter name"
    assert resolved.name == expected_file


def test_resolve_exact_filename_still_works(tmp_path) -> None:
    """Backward-compat: a caller passing the slug directly resolves too."""
    _make_agents(tmp_path)
    resolved = persona.resolve_persona_path(tmp_path, "windows-agent")
    assert resolved is not None and resolved.name == "windows-agent.md"


def test_resolve_unknown_returns_none(tmp_path) -> None:
    _make_agents(tmp_path)
    assert persona.resolve_persona_path(tmp_path, "GhostAgent") is None


def test_resolve_missing_agents_dir_returns_none(tmp_path) -> None:
    assert persona.resolve_persona_path(tmp_path, "WindowsAgent") is None


@pytest.mark.parametrize("loader", [api_persona, openai_persona, ollama_persona])
def test_providers_load_real_persona_not_stub(tmp_path, loader) -> None:
    """Each non-CLI loader, given the PascalCase name the nodes actually pass,
    must return the real persona body — not the generic fallback stub."""
    _make_agents(tmp_path)
    body = loader(tmp_path, "WindowsAgent")
    assert "FOR500 playbook" in body
    assert "forensic specialist. Use the provided" not in body  # stub text


@pytest.mark.parametrize("loader", [api_persona, openai_persona, ollama_persona])
def test_providers_fall_back_when_truly_missing(tmp_path, loader) -> None:
    """When the agent genuinely does not exist, loaders still degrade to a
    non-empty default rather than raising."""
    _make_agents(tmp_path)
    body = loader(tmp_path, "GhostAgent")
    assert isinstance(body, str) and body.strip()
