"""OpenAI provider — Chat Completions + function calling.

Drives GPT models via ``openai.OpenAI().chat.completions.create``. The MCP
forensic tool surface is translated to OpenAI's function-calling format and
dispatched in-process through ``providers.tool_dispatch``.

parsed_messages mirror the stream-json schema the TUI / trace tooling expects
so downstream code (tui.py, resume_verifier.py) does not branch by provider.

OpenAI function-calling requires ``additionalProperties: false`` and explicit
``required`` lists on the parameters schema; the MCP tool schemas mostly
already satisfy this but we patch any that don't before sending.
"""
from __future__ import annotations

import json
import os
import re
import time
from copy import deepcopy
from typing import Any

from .anthropic_cli import _resolve_project_dir, _write_subagent_trace
from .base import Provider, ProviderToolError, SubagentResult
from .persona import resolve_persona_path
from .tool_dispatch import dispatch_tool, mcp_tool_schemas


_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _strip_frontmatter(text: str) -> str:
    return _FRONTMATTER_RE.sub("", text, count=1)


def _load_persona(project_dir, subagent_name: str) -> str:
    # Resolve by frontmatter `name:` (mirrors `claude --agent`), not a naive
    # `<subagent_name>.md` lookup — nodes pass PascalCase ("WindowsAgent")
    # while the files are kebab-case ("windows-agent.md"). See providers.persona.
    persona_path = resolve_persona_path(project_dir, subagent_name)
    if persona_path is None:
        return (
            "You are a DFIR forensic specialist. Use the provided forensic tools "
            "to examine evidence and record findings. Return a concise final summary."
        )
    return _strip_frontmatter(persona_path.read_text())


def _filter_tool_schemas(schemas: list[dict[str, Any]], allowed: list[str] | None) -> list[dict[str, Any]]:
    if allowed is None:
        return schemas
    bare: set[str] = set()
    accept_all = False
    for entry in allowed:
        if entry == "mcp__protocol_sift":
            accept_all = True
            continue
        if entry.startswith("mcp__protocol_sift__"):
            bare.add(entry[len("mcp__protocol_sift__"):])
        else:
            bare.add(entry)
    if accept_all:
        return schemas
    return [s for s in schemas if s["name"] in bare]


def _patch_schema_for_openai(schema: dict[str, Any]) -> dict[str, Any]:
    """OpenAI is strict about JSON Schema. Patch in-place safely."""
    out = deepcopy(schema)
    if out.get("type") != "object":
        out["type"] = "object"
    out.setdefault("properties", {})
    out.setdefault("required", [])
    # OpenAI rejects unknown top-level keys; strip $schema if present.
    out.pop("$schema", None)
    return out


def _tools_openai_format(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": s["name"],
                "description": s["description"][:1024],
                "parameters": _patch_schema_for_openai(s["input_schema"]),
            },
        }
        for s in schemas
    ]


def _stringify_tool_result(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _trace_lines(parsed: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(m, default=str) for m in parsed) + "\n"


class OpenAiProvider(Provider):
    name = "openai"

    _DEFAULT_MODEL = "gpt-4o"
    _MAX_LOOP_ITERATIONS = 30

    def invoke(
        self,
        *,
        subagent_name: str,
        prompt: str,
        allowed_tools: list[str] | None = None,
        headless: bool = True,
    ) -> SubagentResult:
        try:
            import openai
        except ImportError as exc:
            raise RuntimeError(
                "OpenAiProvider requires the `openai` SDK. "
                "Install with: pip install openai"
            ) from exc

        from .. import tui

        project_dir = _resolve_project_dir()
        idle_timeout = _env_float("MH_SUBAGENT_IDLE_TIMEOUT_SEC", 600.0)
        max_sec = _env_float("MH_SUBAGENT_MAX_SEC", 7200.0)
        model = os.environ.get("MH_OPENAI_MODEL", self._DEFAULT_MODEL)
        max_tokens = _env_int("MH_MAX_TOKENS", 4096)

        system_prompt = _load_persona(project_dir, subagent_name)
        schemas = _filter_tool_schemas(mcp_tool_schemas(), allowed_tools)
        tools_payload = _tools_openai_format(schemas)

        try:
            tui.update_state(subagent=subagent_name)
            tui.now(
                f"{subagent_name} · openai / {model}",
                f"tools: {len(tools_payload)} · max_tokens={max_tokens}",
            )
        except Exception:  # noqa: BLE001
            pass

        parsed: list[dict[str, Any]] = [
            {"type": "system", "subtype": "init", "model": model, "subagent": subagent_name},
        ]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        client = openai.OpenAI()
        start = time.monotonic()
        last_active = start
        timed_out = False
        timeout_reason = ""
        final_text = ""
        error_excerpt = ""
        exit_code = 0

        for iteration in range(self._MAX_LOOP_ITERATIONS):
            now = time.monotonic()
            if now - start > max_sec:
                timed_out, timeout_reason = True, "ceiling"
                break
            if now - last_active > idle_timeout:
                timed_out, timeout_reason = True, "idle"
                break

            response = None
            last_exc: Exception | None = None
            for attempt in range(3):
                try:
                    kwargs: dict[str, Any] = {
                        "model": model,
                        "messages": messages,
                        "max_tokens": max_tokens,
                    }
                    if tools_payload:
                        kwargs["tools"] = tools_payload
                    response = client.chat.completions.create(**kwargs)
                    last_active = time.monotonic()
                    break
                except openai.APIStatusError as exc:
                    last_exc = exc
                    status = getattr(exc, "status_code", None)
                    if status in (429, 503) and attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                    if status in (401, 403):
                        raise RuntimeError(
                            f"OpenAiProvider auth failed (status={status}). "
                            f"Check OPENAI_API_KEY: {exc}"
                        ) from exc
                    raise
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                    raise
            if response is None:
                exit_code = 1
                error_excerpt = f"no response after retries: {last_exc!r}"
                break

            choice = response.choices[0]
            msg = choice.message
            content_text = (msg.content or "")
            tool_calls = msg.tool_calls or []
            finish_reason = choice.finish_reason

            assistant_content_blocks: list[dict[str, Any]] = []
            if content_text:
                assistant_content_blocks.append({"type": "text", "text": content_text})
            for tc in tool_calls:
                assistant_content_blocks.append({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": _safe_json(tc.function.arguments),
                })
            parsed.append({
                "type": "assistant",
                "message": {"content": assistant_content_blocks},
            })

            assistant_record: dict[str, Any] = {"role": "assistant", "content": content_text or ""}
            if tool_calls:
                assistant_record["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in tool_calls
                ]
            messages.append(assistant_record)

            if not tool_calls:
                final_text = content_text.strip()
                parsed.append({"type": "result", "subtype": "success", "result": final_text})
                break

            tool_results_for_parsed: list[dict[str, Any]] = []
            for tc in tool_calls:
                tool_name = tc.function.name
                tool_args = _safe_json(tc.function.arguments)
                arg_summary = " · ".join(
                    f"{k}={str(v)[:40]}" for k, v in list(tool_args.items())[:2]
                )
                try:
                    tui.now(f"{subagent_name} · calling {tool_name}", arg_summary or "(no args)")
                except Exception:  # noqa: BLE001
                    pass
                try:
                    result = dispatch_tool(tool_name, tool_args)
                    is_error = False
                except ProviderToolError as exc:
                    result = {"error": str(exc)}
                    is_error = True
                try:
                    tui.now(
                        f"{subagent_name} · tool returned" + (" (ERROR)" if is_error else ""),
                        "processing result",
                    )
                except Exception:  # noqa: BLE001
                    pass
                content_str = _stringify_tool_result(result)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content_str,
                })
                tool_results_for_parsed.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": content_str,
                    "is_error": is_error,
                })

            parsed.append({
                "type": "user",
                "message": {"content": tool_results_for_parsed},
            })
            last_active = time.monotonic()

            if finish_reason == "length":
                final_text = content_text.strip()
                parsed.append({"type": "result", "subtype": "error", "result": final_text})
                break
        else:
            timed_out, timeout_reason = True, "ceiling"

        if timed_out:
            try:
                tui.now(
                    f"{subagent_name} · timed out ({timeout_reason})",
                    "recorded as dissent · check audit.jsonl for the trace",
                )
            except Exception:  # noqa: BLE001
                pass
            parsed.append({"type": "result", "subtype": "error", "result": ""})
        elif exit_code != 0:
            parsed.append({"type": "result", "subtype": "error", "result": error_excerpt})

        stdout = _trace_lines(parsed)
        stderr = error_excerpt
        _write_subagent_trace(subagent_name, stdout, stderr)

        try:
            tui.now(
                f"{subagent_name} · openai returned (exit {exit_code})",
                f"messages: {len(parsed)} · final_text: {len(final_text)} chars",
            )
        except Exception:  # noqa: BLE001
            pass

        return SubagentResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            parsed_messages=parsed,
            final_text=final_text,
            timed_out=timed_out,
            timeout_reason=timeout_reason,
        )


def _safe_json(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        out = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return out if isinstance(out, dict) else {}
