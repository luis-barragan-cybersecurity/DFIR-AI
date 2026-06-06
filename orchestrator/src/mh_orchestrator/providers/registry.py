"""Provider factory — picks the right AI engine at runtime.

Resolution rules (in order):
  1. ``MH_PROVIDER`` env var explicit override. Accepted values:
     ``anthropic-cli``, ``anthropic-api``, ``openai``, ``ollama``.
  2. Auto-detect, in this priority order:
       a. ``anthropic-cli`` — ``claude`` on PATH AND ``CLAUDECODE`` env unset.
       b. ``anthropic-api`` — ``ANTHROPIC_API_KEY`` set.
       c. ``openai``        — ``OPENAI_API_KEY`` set.
       d. ``ollama``        — ``GET {OLLAMA_HOST}/api/tags`` returns 200 in 2s.
  3. Fallback: ``anthropic-cli`` regardless of detect outcome — preserves
     pre-refactor behaviour. The orchestrator's preflight will catch a missing
     ``claude`` binary before the run starts.

The factory is intentionally idempotent + cheap to call from every node; cache
the resolved name in process via the module-level ``_RESOLVED`` so subsequent
calls don't re-run detection. ``MH_PROVIDER`` env changes between calls force
re-resolution.
"""
from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

from .base import Provider

if TYPE_CHECKING:
    pass


_VALID_NAMES = ("anthropic-cli", "anthropic-api", "openai", "ollama")
_RESOLVED: tuple[str, str] | None = None  # (cached_name, cached_mh_provider_env)


def list_providers() -> tuple[str, ...]:
    """Return the tuple of provider names recognised by the registry."""
    return _VALID_NAMES


def _ollama_responding(host: str, timeout: float = 2.0) -> bool:
    """Probe ``{host}/api/tags`` — quick HEAD-style check for a local daemon.

    Uses stdlib urllib to avoid forcing an HTTP-client dep on users who never
    touch Ollama.
    """
    try:
        import urllib.error
        import urllib.request
        url = host.rstrip("/") + "/api/tags"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except Exception:  # noqa: BLE001 — anything = "not responding"
        return False


def resolve_provider_name() -> str:
    """Decide which provider to use, honoring ``MH_PROVIDER`` then auto-detect.

    Returns one of :data:`_VALID_NAMES`. Always returns a string; never raises.
    """
    explicit = os.environ.get("MH_PROVIDER", "").strip().lower()
    if explicit:
        if explicit in _VALID_NAMES:
            return explicit
        # Unknown explicit name → log + fall through to auto-detect.
        # The orchestrator will surface this in preflight.

    # (a) anthropic-cli: claude binary present, not running inside Claude Code.
    if shutil.which("claude") and os.environ.get("CLAUDECODE", "0") != "1":
        return "anthropic-cli"

    # (b) anthropic-api: SDK key set.
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic-api"

    # (c) openai: SDK key set.
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"

    # (d) ollama: local daemon responding.
    ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    if _ollama_responding(ollama_host):
        return "ollama"

    # Fallback — preserve pre-refactor behaviour. The CLI preflight will
    # error out cleanly if ``claude`` isn't installed.
    return "anthropic-cli"


def get_provider(name: str | None = None) -> Provider:
    """Return a concrete :class:`Provider` instance.

    Args:
        name: Optional explicit provider name. ``None`` triggers
            ``resolve_provider_name``. Useful for tests that want to instantiate
            a specific provider without touching env vars.

    Raises:
        RuntimeError: A provider was requested whose module fails to import
            (e.g., ``anthropic`` SDK not installed when ``anthropic-api``
            was selected). The error message names the missing dep.
    """
    chosen = (name or resolve_provider_name()).strip().lower()

    if chosen == "anthropic-cli":
        from .anthropic_cli import AnthropicCliProvider
        return AnthropicCliProvider()

    if chosen == "anthropic-api":
        try:
            from .anthropic_api import AnthropicApiProvider
        except ImportError as exc:
            raise RuntimeError(
                "MH_PROVIDER=anthropic-api requires the `anthropic` SDK. "
                "Install with: pip install anthropic"
            ) from exc
        return AnthropicApiProvider()

    if chosen == "openai":
        try:
            from .openai_provider import OpenAiProvider
        except ImportError as exc:
            raise RuntimeError(
                "MH_PROVIDER=openai requires the `openai` SDK. "
                "Install with: pip install openai"
            ) from exc
        return OpenAiProvider()

    if chosen == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider()

    raise RuntimeError(
        f"Unknown provider {chosen!r}. Valid: {', '.join(_VALID_NAMES)}"
    )
