from __future__ import annotations

import json
import shutil
import sys
import textwrap
import threading
from typing import Any

from shared.utils.env import env_value
from shared.security.policy_loader import get_blocked_commands, get_prompt_injection_patterns


class Ansi:
    RESET = "\033[0m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"


_step_lock = threading.Lock()
_step_counter = 0


def _next_step() -> int:
    global _step_counter
    with _step_lock:
        _step_counter += 1
        return _step_counter


def _aop_enabled() -> bool:
    flag = (env_value("ADK_AOP_UI", "true") or "true").lower()
    return flag in {"1", "true", "yes"}


def _color_enabled() -> bool:
    force = (env_value("ADK_FORCE_COLOR", "true") or "true").lower()
    if force in {"0", "false", "no"}:
        return False
    return sys.stdout.isatty() or force in {"1", "true", "yes"}


def _color(text: str, color_code: str) -> str:
    if not _color_enabled():
        return text
    return f"{color_code}{text}{Ansi.RESET}"


def _to_mapping(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump(exclude_none=True)
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            return None
    return None


def _extract_field(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _safe_json(value: Any, max_len: int = 1600) -> str:
    try:
        rendered = json.dumps(value, default=str, indent=2)
    except TypeError:
        rendered = str(value)
    if len(rendered) <= max_len:
        return rendered
    return f"{rendered[:max_len - 3]}..."


def _terminal_width() -> int:
    width = shutil.get_terminal_size((120, 20)).columns
    return max(80, min(width, 160))


def _wrap_row(label: str, value: Any, width: int) -> list[str]:
    prefix = f"{label}: "
    available = max(12, width - len(prefix))
    raw_lines = str(value).splitlines() or [""]
    wrapped_chunks: list[str] = []
    for raw in raw_lines:
        wrapped = textwrap.wrap(raw, width=available) or [""]
        wrapped_chunks.extend(wrapped)
    lines = [f"{prefix}{wrapped_chunks[0]}"]
    indent = " " * len(prefix)
    for extra in wrapped_chunks[1:]:
        lines.append(f"{indent}{extra}")
    return lines


def _print_panel(title: str, rows: list[tuple[str, Any]], color_code: str) -> None:
    max_width = _terminal_width() - 2
    prepared_lines: list[str] = []
    for label, value in rows:
        prepared_lines.extend(_wrap_row(label, value, max_width - 4))

    title_text = f" {title} "
    content_width = max(
        len(title_text),
        max((len(line) for line in prepared_lines), default=0),
        44,
    )
    content_width = min(content_width, max_width - 2)

    normalized_lines = []
    for line in prepared_lines:
        if len(line) <= content_width:
            normalized_lines.append(line)
            continue
        normalized_lines.extend(textwrap.wrap(line, width=content_width))

    left = (content_width - len(title_text)) // 2
    right = content_width - len(title_text) - left
    top = f"╭{'─' * left}{title_text}{'─' * right}╮"
    bottom = f"╰{'─' * content_width}╯"

    print("")
    print(_color(top, color_code))
    for line in normalized_lines:
        print(_color(f"│{line.ljust(content_width)}│", color_code))
    print(_color(bottom, color_code))


def _agent_name_from_tool_context(tool_context: Any) -> str:
    direct = _extract_field(tool_context, "agent_name")
    if isinstance(direct, str) and direct:
        return direct
    invocation_context = _extract_field(tool_context, "_invocation_context") or _extract_field(
        tool_context, "invocation_context"
    )
    agent = _extract_field(invocation_context, "agent")
    name = _extract_field(agent, "name")
    if isinstance(name, str) and name:
        return name
    return "unknown_agent"


def _agent_name_from_callback_context(callback_context: Any) -> str:
    for field_name in ("agent_name", "agent"):
        value = _extract_field(callback_context, field_name)
        if isinstance(value, str) and value:
            return value
        nested_name = _extract_field(value, "name")
        if isinstance(nested_name, str) and nested_name:
            return nested_name
    invocation_context = _extract_field(callback_context, "_invocation_context") or _extract_field(
        callback_context, "invocation_context"
    )
    agent = _extract_field(invocation_context, "agent")
    name = _extract_field(agent, "name")
    if isinstance(name, str) and name:
        return name
    return "unknown_agent"


def _tool_name(tool: Any) -> str:
    name = _extract_field(tool, "name")
    if isinstance(name, str) and name:
        return name
    fallback = getattr(tool, "__name__", None)
    if isinstance(fallback, str) and fallback:
        return fallback
    return str(tool)


def _extract_model_message(llm_response: Any) -> tuple[str, list[str], str]:
    data = _to_mapping(llm_response)
    raw = _safe_json(data if data is not None else llm_response, max_len=1800)
    text_chunks: list[str] = []
    function_calls: list[str] = []

    if data and isinstance(data, dict):
        parts = []
        content = data.get("content")
        if isinstance(content, dict):
            parts = content.get("parts", [])
        if isinstance(parts, list):
            for part in parts:
                if not isinstance(part, dict):
                    continue
                text = part.get("text")
                if isinstance(text, str) and text.strip():
                    text_chunks.append(text.strip())
                function_call = part.get("function_call")
                if isinstance(function_call, dict):
                    call_name = function_call.get("name")
                    if isinstance(call_name, str) and call_name:
                        function_calls.append(call_name)

    summary = "(non-text model response)"
    if text_chunks:
        first = text_chunks[0]
        stripped = first.strip()
        if stripped.startswith("```json"):
            summary = "Text response with JSON payload (see Raw Output)."
        elif len(stripped) > 300:
            summary = f"{stripped[:297]}..."
        else:
            summary = stripped
    return summary, function_calls[:10], raw


def _check_blocked_commands(args: dict[str, Any] | None) -> str | None:
    """Return a reason string if any arg value contains a blocked pattern."""
    if not args:
        return None
    blocked = get_blocked_commands()
    for _key, val in args.items():
        if not isinstance(val, str):
            continue
        for pattern in blocked:
            if pattern in val:
                return f"Blocked by guardrail policy: command contains '{pattern}'"
    return None


def before_tool_callback(
    tool: Any = None,
    args: dict[str, Any] | None = None,
    tool_context: Any = None,
    **_: Any,
) -> dict | None:
    # ---- Guardrail: blocked command patterns ----
    block_reason = _check_blocked_commands(args)
    if block_reason:
        step = _next_step()
        _print_panel(
            "GUARDRAIL BLOCKED",
            [
                ("Step", f"{step:03d}"),
                ("Agent", _agent_name_from_tool_context(tool_context)),
                ("Tool", _tool_name(tool)),
                ("Reason", block_reason),
            ],
            Ansi.RED,
        )
        return {"error": block_reason, "blocked": True}

    # ---- AOP console logging (original behavior) ----
    if not _aop_enabled():
        return None
    step = _next_step()
    _print_panel(
        "AOP Tool Call",
        [
            ("Step", f"{step:03d}"),
            ("Agent", _agent_name_from_tool_context(tool_context)),
            ("Tool", _tool_name(tool)),
            ("Args", _safe_json(args or {}, max_len=1400)),
        ],
        Ansi.CYAN,
    )
    return None


def after_tool_callback(
    tool: Any = None,
    args: dict[str, Any] | None = None,
    tool_context: Any = None,
    tool_response: dict | None = None,
    response: dict | None = None,
    **_: Any,
) -> dict | None:
    if not _aop_enabled():
        return None
    step = _next_step()
    payload = tool_response if tool_response is not None else response
    _print_panel(
        "AOP Tool Response",
        [
            ("Step", f"{step:03d}"),
            ("Agent", _agent_name_from_tool_context(tool_context)),
            ("Tool", _tool_name(tool)),
            ("Raw Output", _safe_json(payload or {}, max_len=2000)),
        ],
        Ansi.GREEN,
    )
    return None


def on_tool_error_callback(
    tool: Any = None,
    args: dict[str, Any] | None = None,
    tool_context: Any = None,
    exc: Exception | None = None,
    error: Exception | None = None,
    **_: Any,
) -> dict | None:
    if not _aop_enabled():
        return None
    step = _next_step()
    resolved_error = error or exc or Exception("unknown tool error")
    _print_panel(
        "AOP Tool Error",
        [
            ("Step", f"{step:03d}"),
            ("Agent", _agent_name_from_tool_context(tool_context)),
            ("Tool", _tool_name(tool)),
            ("Args", _safe_json(args or {}, max_len=1000)),
            ("Error", str(resolved_error)),
        ],
        Ansi.RED,
    )
    return None


def before_model_callback(callback_context: Any, llm_request: Any) -> Any:
    """Screen prompts for injection patterns before sending to the model."""
    injection_patterns = get_prompt_injection_patterns()
    if not injection_patterns:
        return None

    # Extract text from the request to scan
    text_to_scan = ""
    data = _to_mapping(llm_request)
    if data and isinstance(data, dict):
        contents = data.get("contents", [])
        if isinstance(contents, list):
            for content in contents:
                if isinstance(content, dict):
                    parts = content.get("parts", [])
                    if isinstance(parts, list):
                        for part in parts:
                            if isinstance(part, dict):
                                text = part.get("text", "")
                                if isinstance(text, str):
                                    text_to_scan += text.lower() + " "

    for pattern in injection_patterns:
        if pattern.lower() in text_to_scan:
            step = _next_step()
            _print_panel(
                "GUARDRAIL: PROMPT INJECTION DETECTED",
                [
                    ("Step", f"{step:03d}"),
                    ("Agent", _agent_name_from_callback_context(callback_context)),
                    ("Pattern", pattern),
                ],
                Ansi.RED,
            )
            # Return a safe fallback response to prevent the injection
            from google.genai import types as genai_types
            return genai_types.GenerateContentResponse(
                candidates=[
                    genai_types.Candidate(
                        content=genai_types.Content(
                            parts=[genai_types.Part(text="Request blocked: potential prompt injection detected.")],
                            role="model",
                        )
                    )
                ]
            )
    return None


def after_model_callback(callback_context: Any, llm_response: Any) -> Any:
    if not _aop_enabled():
        return None
    step = _next_step()
    summary, function_calls, raw = _extract_model_message(llm_response)
    rows: list[tuple[str, Any]] = [
        ("Step", f"{step:03d}"),
        ("Agent", _agent_name_from_callback_context(callback_context)),
        ("Summary", summary),
    ]
    if function_calls:
        rows.append(("Function Calls", ", ".join(function_calls)))
    rows.append(("Raw Output", raw))
    _print_panel("AOP Agent Response", rows, Ansi.MAGENTA)
    return None
