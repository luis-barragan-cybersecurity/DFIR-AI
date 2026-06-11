"""Shared subagent-persona resolution for the non-CLI providers.

Nodes pass PascalCase subagent identifiers — ``"WindowsAgent"``,
``"MacOSAgent"``, ``"LinuxAgent"``, ``"Verifier"`` (see
``nodes/triage.OS_TO_SUBAGENT`` and ``nodes/verifier_pass.SUBAGENT``). The
``anthropic-cli`` provider hands those straight to ``claude --agent <name>``,
which resolves them against each agent file's ``name:`` frontmatter, so the CLI
path loads the right persona.

The non-CLI providers (``anthropic-api`` / ``openai`` / ``ollama``) load the
persona markdown directly off disk. The agent files are kebab-case
(``.claude/agents/windows-agent.md``) carrying PascalCase ``name:`` frontmatter
(``name: WindowsAgent``). A naive ``<subagent_name>.md`` lookup therefore MISSES
(``WindowsAgent.md`` does not exist) and the providers silently fall back to a
3-line generic stub — discarding the FOR500/FOR518/FOR577 playbooks, the
attribution discipline, and the pin guidance on three of the four engines.

This module performs the same name→file resolution the CLI does, in three
steps: ``name:`` frontmatter match (the authoritative path, mirrors
``--agent``, and returns the true on-disk file even on a case-insensitive
filesystem), exact filename (backward-compatible with callers that already pass
a slug), then a kebab-case derivation as a last-resort fallback.
"""
from __future__ import annotations

import re
from pathlib import Path

# Match the first `name: <value>` line inside (or before) the frontmatter.
_FRONTMATTER_NAME_RE = re.compile(r"^name:\s*(.+?)\s*$", re.MULTILINE)


def _pascal_to_kebab(name: str) -> str:
    """Best-effort PascalCase → kebab-case (``WindowsAgent`` → ``windows-agent``).

    Imperfect for acronym runs (``MacOSAgent`` → ``mac-os-agent``, while the
    file is ``macos-agent``); that case is already covered by the authoritative
    frontmatter-name match, so this remains only a last-resort fallback.
    """
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "-", s)
    return s.lower()


def resolve_persona_path(project_dir: Path, subagent_name: str) -> Path | None:
    """Resolve a subagent identifier to its ``.claude/agents/*.md`` file.

    Args:
        project_dir: Repo/project root containing ``.claude/agents/``.
        subagent_name: Identifier passed by the node (e.g. ``"WindowsAgent"``).

    Returns:
        The resolved persona file ``Path``, or ``None`` if no agent file
        matches by filename, frontmatter name, or kebab derivation.
    """
    agents_dir = Path(project_dir) / ".claude" / "agents"
    if not agents_dir.is_dir():
        return None

    # 1) Authoritative: match the `name:` frontmatter (case-insensitive),
    #    exactly how `claude --agent <name>` resolves the same identifier.
    #    Run FIRST so we return the true on-disk file — on a case-insensitive
    #    filesystem a naive `<name>.md` existence check can succeed for a
    #    mis-cased name (e.g. "Verifier.md" hitting "verifier.md") and yield a
    #    Path whose `.name` carries the wrong casing.
    want = subagent_name.strip().lower()
    for md in sorted(agents_dir.glob("*.md")):
        try:
            head = md.read_text(encoding="utf-8", errors="replace")[:512]
        except OSError:
            continue
        match = _FRONTMATTER_NAME_RE.search(head)
        if match and match.group(1).strip().lower() == want:
            return md

    # 2) Exact filename — backward compatible with any caller already passing
    #    a slug like "windows-agent".
    exact = agents_dir / f"{subagent_name}.md"
    if exact.is_file():
        return exact

    # 3) Last-resort: derive a kebab filename (covers simple PascalCase names).
    kebab = agents_dir / f"{_pascal_to_kebab(subagent_name)}.md"
    if kebab.is_file():
        return kebab

    return None
