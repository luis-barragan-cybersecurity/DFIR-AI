"""Ollama HTTP provider.

Drives a local Ollama daemon (default ``http://localhost:11434``) and adapts
the same MCP forensic tool surface the other providers use. Two paths:

- Path A: native OpenAI-shaped tool calling on ``/api/chat`` (preferred,
  modern Ollama + tool-capable models).
- Path B: text-tag fallback for older / non-tool-capable models. The model
  emits ``<tool>name({"json":"args"})</tool>`` blocks which we parse and
  feed back as system messages.

Zero non-stdlib deps — urllib only — so a judge with no pip-installed
packages can still drive a local model.
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .anthropic_cli import _resolve_project_dir, _write_subagent_trace
from .base import Provider, ProviderToolError, SubagentResult
from .tool_dispatch import dispatch_tool, mcp_tool_schemas


DEFAULT_ALLOWED_TOOLS: list[str] = ["mcp__protocol_sift"]
_TOOL_PREFIX = "mcp__protocol_sift__"
_BARE_SERVER = "mcp__protocol_sift"
_MAX_ITERATIONS = 20
_DEFAULT_PERSONA = (
    "You are a DFIR forensic specialist. Use the provided tools to "
    "investigate. Return your conclusions as plain text when done."
)
_REMINDER = (
    "\n\n## Tool usage\n"
    "Use the available forensic tools to gather evidence. When you have "
    "enough to answer, return your conclusions as plain text."
)
_TEXT_TOOL_REMINDER = (
    "\n\n## Tool calling (text mode)\n"
    "You do NOT have native tool calls. When you need a tool, emit a single "
    "line of the exact form:\n"
    "  <tool>tool_name({\"arg\": \"value\"})</tool>\n"
    "The runtime parses every <tool>...</tool> block, runs it, and replies "
    "with a system message containing the JSON result. Only one tool per "
    "block; multiple blocks per turn are fine. When you are done, emit "
    "<final>your conclusions</final> OR simply reply with prose containing "
    "no <tool> blocks."
)
_TOOL_RE = re.compile(r"<tool>\s*([A-Za-z0-9_]+)\s*\((\{.*?\})\)\s*</tool>", re.DOTALL)
_FINAL_RE = re.compile(r"<final>(.*?)</final>", re.DOTALL)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default) or default


def _strip_frontmatter(md: str) -> str:
    if not md.startswith("---"):
        return md
    lines = md.splitlines()
    if len(lines) < 2:
        return md
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[i + 1:]).lstrip("\n")
    return md


def _persona(project_dir: Path, subagent_name: str) -> str:
    persona_path = project_dir / ".claude" / "agents" / f"{subagent_name}.md"
    if not persona_path.is_file():
        import sys
        print(
            f"ollama provider: persona file missing at {persona_path}; "
            "falling back to minimal default system prompt",
            file=sys.stderr,
        )
        return _DEFAULT_PERSONA
    try:
        raw = persona_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        import sys
        print(
            f"ollama provider: failed to read persona {persona_path}: {exc}; "
            "using minimal default",
            file=sys.stderr,
        )
        return _DEFAULT_PERSONA
    return _strip_frontmatter(raw).strip() or _DEFAULT_PERSONA


def _filter_schemas(
    schemas: list[dict[str, Any]],
    allowed: list[str] | None,
) -> list[dict[str, Any]]:
    if allowed is None:
        return schemas
    bare_allowed: set[str] = set()
    allow_all = False
    for entry in allowed:
        if entry == _BARE_SERVER:
            allow_all = True
            break
        if entry.startswith(_TOOL_PREFIX):
            bare_allowed.add(entry[len(_TOOL_PREFIX):])
        else:
            bare_allowed.add(entry)
    if allow_all:
        return schemas
    return [s for s in schemas if s["name"] in bare_allowed]


def _tools_in_ollama_format(
    schemas: list[dict[str, Any]],
    allowed: list[str] | None,
) -> list[dict[str, Any]]:
    selected = _filter_schemas(schemas, allowed)
    out: list[dict[str, Any]] = []
    for s in selected:
        params = s.get("input_schema") or {"type": "object", "properties": {}}
        out.append({
            "type": "function",
            "function": {
                "name": s["name"],
                "description": (s.get("description") or "")[:1024],
                "parameters": params,
            },
        })
    return out


def _tools_text_catalog(
    schemas: list[dict[str, Any]],
    allowed: list[str] | None,
) -> str:
    selected = _filter_schemas(schemas, allowed)
    lines: list[str] = ["## Available tools", ""]
    for s in selected:
        params = s.get("input_schema") or {}
        props = (params.get("properties") or {})
        required = params.get("required") or []
        arg_bits: list[str] = []
        for pname, pspec in props.items():
            ptype = (pspec or {}).get("type", "any")
            marker = "" if pname in required else "?"
            arg_bits.append(f"{pname}{marker}:{ptype}")
        sig = ", ".join(arg_bits) if arg_bits else "<no args>"
        desc = (s.get("description") or "").strip().splitlines()
        head = desc[0][:160] if desc else ""
        lines.append(f"- `{s['name']}({sig})` — {head}")
    return "\n".join(lines)


def _call_chat(host: str, payload: dict[str, Any], timeout: float) -> tuple[int, dict[str, Any] | None, str]:
    url = host.rstrip("/") + "/api/chat"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — local daemon by config
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw), ""
            except json.JSONDecodeError as exc:
                return resp.status, None, f"json decode: {exc}; body[:300]={raw[:300]!r}"
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            err_body = ""
        return exc.code, None, f"HTTP {exc.code}: {exc.reason}; body={err_body[:500]}"
    except urllib.error.URLError as exc:
        return 0, None, f"url error: {exc.reason}"
    except socket.timeout:
        return 0, None, "socket timeout"
    except OSError as exc:
        return 0, None, f"os error: {exc}"


def _native_unsupported(err: str) -> bool:
    if not err:
        return False
    low = err.lower()
    return (
        "does not support tools" in low
        or "tools not supported" in low
        or "no tool support" in low
        or "does not support tool" in low
        or "registry.ollama.ai" in low and "tool" in low
    )


def _parse_tool_blocks(text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _TOOL_RE.finditer(text or "")]


def _final_block(text: str) -> str | None:
    m = _FINAL_RE.search(text or "")
    if m:
        return m.group(1).strip()
    return None


def _stringify(result: Any) -> str:
    try:
        if isinstance(result, str):
            return result
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return str(result)


def _tui_safe(call) -> None:  # noqa: ANN001
    try:
        call()
    except Exception:  # noqa: BLE001
        pass


class OllamaProvider(Provider):
    """Drive a local Ollama daemon over its HTTP API."""

    name = "ollama"

    def invoke(
        self,
        *,
        subagent_name: str,
        prompt: str,
        allowed_tools: list[str] | None = None,
        headless: bool = True,
    ) -> SubagentResult:
        from .. import tui  # local import — TUI may not be importable in CI

        host = _env_str("OLLAMA_HOST", "http://localhost:11434")
        model = _env_str("MH_OLLAMA_MODEL", "llama3.3")
        mode = _env_str("MH_OLLAMA_TOOLS_MODE", "auto").lower().strip()
        if mode not in {"auto", "native", "text"}:
            mode = "auto"
        idle_timeout = _env_float("MH_SUBAGENT_IDLE_TIMEOUT_SEC", 600.0)
        max_sec = _env_float("MH_SUBAGENT_MAX_SEC", 7200.0)

        project_dir = _resolve_project_dir()
        persona_body = _persona(project_dir, subagent_name)
        schemas = mcp_tool_schemas()
        tools_native = _tools_in_ollama_format(schemas, allowed_tools or DEFAULT_ALLOWED_TOOLS)
        tools_catalog = _tools_text_catalog(schemas, allowed_tools or DEFAULT_ALLOWED_TOOLS)

        _tui_safe(lambda: tui.update_state(subagent=subagent_name))
        _tui_safe(lambda: tui.now(
            f"{subagent_name} · ollama provider spawning",
            f"model={model} · mode={mode} · tools={len(tools_native)} · host={host}",
        ))
        if not headless:
            _tui_safe(lambda: tui.now(
                f"{subagent_name} · ollama has no interactive TUI",
                "running headlessly anyway",
            ))

        parsed_messages: list[dict[str, Any]] = [
            {"type": "system", "subtype": "init"}
        ]
        _tui_safe(lambda: tui.now(
            f"{subagent_name} · session initialized",
            "subagent loaded · ready for tool calls",
        ))

        # Determine effective path. We may downgrade A → B mid-call.
        use_native = mode != "text"

        system_prompt = persona_body + _REMINDER
        if not use_native:
            system_prompt += "\n\n" + tools_catalog + _TEXT_TOOL_REMINDER

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        start = time.monotonic()
        last_active = start
        final_text = ""
        stderr_chunks: list[str] = []
        exit_code = 0
        timed_out = False
        timeout_reason = ""
        tool_use_counter = 0

        for iteration in range(_MAX_ITERATIONS):
            now = time.monotonic()
            if now - start > max_sec:
                timed_out, timeout_reason = True, "ceiling"
                break
            if now - last_active > idle_timeout:
                timed_out, timeout_reason = True, "idle"
                break

            remaining = max(5.0, max_sec - (now - start))
            req_timeout = min(remaining, 600.0)

            payload: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.2},
            }
            if use_native and tools_native:
                payload["tools"] = tools_native

            status, body, err = _call_chat(host, payload, timeout=req_timeout)

            if body is None:
                # Auto-downgrade from native → text on tool-support error.
                if use_native and mode == "auto" and (status in (400, 404, 405, 422) or _native_unsupported(err)):
                    _tui_safe(lambda: tui.now(
                        f"{subagent_name} · ollama tools unsupported",
                        "falling back to text-tag mode",
                    ))
                    use_native = False
                    messages[0] = {
                        "role": "system",
                        "content": persona_body + _REMINDER + "\n\n" + tools_catalog + _TEXT_TOOL_REMINDER,
                    }
                    last_active = time.monotonic()
                    continue
                # Hard failure (daemon unreachable, malformed JSON, etc).
                stderr_chunks.append(f"ollama call failed: status={status} err={err}")
                _tui_safe(lambda: tui.now(
                    f"{subagent_name} · ollama call failed",
                    f"status={status} · check daemon at {host}",
                ))
                return SubagentResult(
                    exit_code=1,
                    stdout="\n".join(json.dumps(m) for m in parsed_messages),
                    stderr=f"Ollama at {host} not responding: {err or status}",
                    parsed_messages=parsed_messages,
                    final_text="",
                    timed_out=False,
                    timeout_reason="",
                )

            last_active = time.monotonic()

            message = body.get("message") or {}
            text = (message.get("content") or "")
            raw_tool_calls = message.get("tool_calls") or []

            if text:
                parsed_messages.append({
                    "type": "assistant",
                    "message": {"content": [{"type": "text", "text": text}]},
                })
                snippet = text.strip().splitlines()
                if snippet:
                    _tui_safe(lambda s=snippet[0]: tui.now(
                        f"{subagent_name} · model speaking",
                        s[:80],
                    ))

            invocations: list[tuple[str, dict[str, Any] | None, str | None]] = []
            # Path A: native tool_calls.
            if use_native and raw_tool_calls:
                for call in raw_tool_calls:
                    fn = (call or {}).get("function") or {}
                    name = fn.get("name") or ""
                    raw_args = fn.get("arguments")
                    if isinstance(raw_args, str):
                        try:
                            args = json.loads(raw_args) if raw_args.strip() else {}
                            invocations.append((name, args, None))
                        except json.JSONDecodeError as exc:
                            invocations.append((name, None, f"arguments JSON parse error: {exc}; raw={raw_args[:200]!r}"))
                    elif isinstance(raw_args, dict):
                        invocations.append((name, raw_args, None))
                    elif raw_args is None:
                        invocations.append((name, {}, None))
                    else:
                        invocations.append((name, None, f"arguments unexpected type: {type(raw_args).__name__}"))

            # Path B: parse <tool> blocks from the text reply.
            if not use_native and text:
                fin = _final_block(text)
                if fin is not None:
                    final_text = fin
                    parsed_messages.append({
                        "type": "result", "subtype": "success", "result": final_text,
                    })
                    _tui_safe(lambda: tui.now(
                        f"{subagent_name} · result · success",
                        "subagent finished",
                    ))
                    break
                for tname, args_blob in _parse_tool_blocks(text):
                    try:
                        args = json.loads(args_blob) if args_blob.strip() else {}
                        invocations.append((tname, args, None))
                    except json.JSONDecodeError as exc:
                        invocations.append((tname, None, f"arguments JSON parse error: {exc}; raw={args_blob[:200]!r}"))

            if not invocations:
                # No tool requested. If we have text, treat it as final.
                final_text = (text or "").strip()
                parsed_messages.append({
                    "type": "result",
                    "subtype": "success" if final_text else "error",
                    "result": final_text,
                })
                _tui_safe(lambda: tui.now(
                    f"{subagent_name} · result · {'success' if final_text else 'error'}",
                    "subagent finished",
                ))
                break

            # Record assistant tool_use blocks + dispatch each.
            tool_results_native: list[dict[str, Any]] = []
            tool_results_text_blobs: list[str] = []
            assistant_native_msg: dict[str, Any] = {
                "role": "assistant",
                "content": text or "",
            }
            if use_native:
                assistant_native_msg["tool_calls"] = raw_tool_calls

            for tname, args, parse_err in invocations:
                tool_use_id = tool_use_counter
                tool_use_counter += 1
                parsed_messages.append({
                    "type": "assistant",
                    "message": {"content": [{
                        "type": "tool_use",
                        "id": str(tool_use_id),
                        "name": tname,
                        "input": args or {},
                    }]},
                })
                argv_summary = " · ".join(
                    f"{k}={str(v)[:40]}" for k, v in list((args or {}).items())[:2]
                )
                _tui_safe(lambda tn=tname, av=argv_summary: tui.now(
                    f"{subagent_name} · calling {tn}",
                    av or "(no args)",
                ))

                if parse_err is not None:
                    result_payload = {"error": parse_err}
                    is_error = True
                else:
                    try:
                        raw_result = dispatch_tool(tname, args or {})
                        result_payload = raw_result
                        is_error = False
                    except ProviderToolError as exc:
                        result_payload = {"error": str(exc)}
                        is_error = True
                        stderr_chunks.append(str(exc))
                    except Exception as exc:  # noqa: BLE001
                        result_payload = {"error": f"{type(exc).__name__}: {exc}"}
                        is_error = True
                        stderr_chunks.append(f"{type(exc).__name__}: {exc}")

                result_str = _stringify(result_payload)
                parsed_messages.append({
                    "type": "user",
                    "message": {"content": [{
                        "type": "tool_result",
                        "tool_use_id": str(tool_use_id),
                        "content": result_str,
                        "is_error": is_error,
                    }]},
                })
                _tui_safe(lambda ie=is_error: tui.now(
                    f"{subagent_name} · tool returned" + (" (ERROR)" if ie else ""),
                    "processing result",
                ))

                if use_native:
                    tool_results_native.append({
                        "role": "tool",
                        "content": result_str[:32000],
                    })
                else:
                    tool_results_text_blobs.append(
                        f"Tool result for {tname}: {result_str[:32000]}"
                    )

                last_active = time.monotonic()

            if use_native:
                messages.append(assistant_native_msg)
                messages.extend(tool_results_native)
            else:
                # Keep the model's last text in the conversation as 'assistant'.
                if text:
                    messages.append({"role": "assistant", "content": text})
                messages.append({
                    "role": "system",
                    "content": "\n\n".join(tool_results_text_blobs),
                })

        else:
            # Loop exhausted iterations without natural termination.
            timed_out, timeout_reason = True, "ceiling"

        if timed_out:
            _tui_safe(lambda: tui.now(
                f"{subagent_name} · timed out ({timeout_reason})",
                "recorded as dissent · check audit.jsonl for the trace",
            ))
            parsed_messages.append({
                "type": "result",
                "subtype": "error",
                "result": final_text or "",
            })

        if not timed_out:
            _tui_safe(lambda: tui.now(
                f"{subagent_name} · subagent returned (exit {exit_code})",
                f"messages: {len(parsed_messages)} · final_text: {len(final_text)} chars",
            ))

        stdout_str = "\n".join(json.dumps(m) for m in parsed_messages)
        stderr_str = "\n".join(stderr_chunks)
        try:
            _write_subagent_trace(subagent_name, stdout_str, stderr_str)
        except Exception:  # noqa: BLE001
            pass

        return SubagentResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            parsed_messages=parsed_messages,
            final_text=final_text,
            timed_out=timed_out,
            timeout_reason=timeout_reason,
        )
