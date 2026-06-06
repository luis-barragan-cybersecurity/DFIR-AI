"""Provider ABC + shared types.

``Provider`` is the single contract every orchestrator node sees. It has one
method, ``invoke(subagent_name, prompt, allowed_tools, headless)`` returning a
``SubagentResult`` whose shape is intentionally identical to the pre-refactor
``claude_node.SubagentResult`` so existing callers (triage, analyze,
verifier_pass, …) are not touched.

Errors that a caller may distinguish from generic ``RuntimeError``:
- ``HeadlessBillingError`` — Anthropic CLI in ``-p`` mode hit a billing gate.
  Surfaced so the orchestrator can fall back to ``--interactive``.
- ``ProviderToolError``    — a provider's tool-call loop hit an unknown tool
  name, a malformed argument set, or a tool function raised.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class HeadlessBillingError(RuntimeError):
    """Anthropic CLI ``-p`` mode is billing-gated for this account.

    Detection is heuristic — the wrapper greps stdout+stderr for billing-shaped
    substrings (``credit balance``, ``402 Payment Required``, ``out of credits``,
    etc.). False positives are fine; they only redirect the user to
    ``--interactive`` (subscription path), which is the same advice every other
    -p failure mode gets.
    """


class ProviderToolError(RuntimeError):
    """A provider's tool-call loop failed.

    Common causes:
    - Model requested a tool name not in :func:`tool_dispatch.dispatch_tool`'s map.
    - Tool arguments missing a required field or wrong shape.
    - The underlying ``protocol_sift_mcp.tools.*`` function raised.

    The message preserves the model's emitted tool-name + arguments so the
    failure can be diagnosed from audit.jsonl.
    """


@dataclass
class SubagentResult:
    """Result envelope returned by every ``Provider.invoke`` call.

    Field-compatible with the pre-refactor ``claude_node.SubagentResult`` so
    nodes that destructure these fields (``parsed_messages``, ``final_text``,
    ``timed_out``, ``timeout_reason``) keep working without edits.

    Attributes:
        exit_code: Process / HTTP exit code. ``0`` on success, non-zero on
            failure. Non-CLI providers use ``0`` for OK and a synthetic code
            (``1`` generic, ``-1`` killed, ``137`` SIGKILL etc.) on failure.
        stdout: Raw stdout from a subprocess provider; for non-subprocess
            providers, the concatenated JSON-encoded model/tool messages.
        stderr: Raw stderr; for non-subprocess providers, error excerpt or "".
        parsed_messages: Per-step protocol messages. For the Anthropic CLI
            provider, this is the stream-json line array. For non-CLI
            providers, a normalised list of ``{type, ...}`` records (system /
            assistant / user / result) that mirrors the stream-json schema so
            downstream TUI / trace code does not branch on provider.
        final_text: The model's final natural-language reply, if any.
        timed_out: True if the liveness monitor killed the subprocess /
            session; recorded as a dissent in verifier_pass.
        timeout_reason: ``"idle"`` (no CPU + no output for the idle window) or
            ``"ceiling"`` (max wall-clock exceeded). Empty when not timed out.
    """

    exit_code: int
    stdout: str
    stderr: str
    parsed_messages: list[dict[str, Any]] = field(default_factory=list)
    final_text: str = ""
    timed_out: bool = False
    timeout_reason: str = ""


class Provider(ABC):
    """Abstract base class for every AI engine MemoryHound can drive.

    Implementations live next to this file (``anthropic_cli.py``,
    ``anthropic_api.py``, ``openai.py``, ``ollama.py``). The registry's
    :func:`get_provider` factory picks one at runtime based on ``MH_PROVIDER``
    env or auto-detect order.

    Concrete providers are responsible for:
    - Loading the subagent persona from ``.claude/agents/<subagent_name>.md``
      (treated as plain markdown system prompt for non-CLI providers).
    - Driving the model + tool-call loop until either: model emits a final
      text reply, or the liveness window expires.
    - Translating their native event stream into the normalised
      stream-json-shaped ``parsed_messages`` list so TUI + trace code stays
      provider-agnostic.
    - Honoring ``MH_SUBAGENT_IDLE_TIMEOUT_SEC`` and ``MH_SUBAGENT_MAX_SEC``
      env vars (default 600s / 7200s).
    """

    #: Short identifier used by the registry. Override in subclasses.
    name: str = "provider"

    @abstractmethod
    def invoke(
        self,
        *,
        subagent_name: str,
        prompt: str,
        allowed_tools: list[str] | None = None,
        headless: bool = True,
    ) -> SubagentResult:
        """Run the named subagent against ``prompt`` and return its result.

        Args:
            subagent_name: One of ``linux-agent``, ``macos-agent``,
                ``windows-agent``, ``verifier``. Must correspond to a
                persona file at ``.claude/agents/<subagent_name>.md``.
            prompt: The user-turn payload for this run.
            allowed_tools: Subset of MCP tool names the model may call.
                ``None`` means "use the provider's default allowlist".
            headless: True for non-interactive operation (orchestrator
                LangGraph path). False for the interactive Claude TUI path,
                which only the ``anthropic-cli`` provider supports.

        Returns:
            A :class:`SubagentResult` with parsed_messages following the
            normalised stream-json schema.

        Raises:
            HeadlessBillingError: Anthropic CLI hit the billing gate.
            ProviderToolError: Tool-call loop failed in a structured way.
            RuntimeError: Provider-specific unrecoverable error.
        """
        raise NotImplementedError
