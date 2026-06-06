"""AI provider abstraction.

Every LLM-invoking orchestrator node calls ``invoke_subagent`` which delegates
to a ``Provider`` instance picked by the registry. Providers differ only in
transport (subprocess vs HTTP vs SDK); they share the same MCP tool surface
via ``providers.tool_dispatch`` and the same ``SubagentResult`` shape.

Public surface:
- ``Provider``                — abstract base class with one method, ``invoke``
- ``SubagentResult``          — dataclass returned by every provider
- ``ProviderToolError``       — typed error for unknown / failed tool dispatch
- ``HeadlessBillingError``    — typed error for Anthropic CLI billing gate
- ``get_provider``            — registry factory; honours ``MH_PROVIDER`` env
- ``dispatch_tool``           — re-exported MCP tool runner (for non-CLI providers)
"""
from __future__ import annotations

from .base import HeadlessBillingError, Provider, ProviderToolError, SubagentResult
from .registry import get_provider, list_providers, resolve_provider_name
from .tool_dispatch import dispatch_tool, mcp_tool_schemas

__all__ = [
    "HeadlessBillingError",
    "Provider",
    "ProviderToolError",
    "SubagentResult",
    "dispatch_tool",
    "get_provider",
    "list_providers",
    "mcp_tool_schemas",
    "resolve_provider_name",
]
