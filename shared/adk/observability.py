"""
AOP observability callbacks for the SecOps pipeline.

Renders a rich terminal UI inspired by CTF-agent style panels:
  - Compact panels for tool invocations
  - Rich panels with nested output for tool responses
  - Agent response panels with token metrics and timing
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any

from shared.utils.env import env_value
from shared.security.policy_loader import get_blocked_commands, get_prompt_injection_patterns
from shared.utils.terminal_ui import (
    Ansi,
    color as _color,
    print_panel,
    print_compact_panel,
    print_rich_panel,
)


# ── Step counter (thread-safe) ───────────────────────────────────────

_step_lock = threading.Lock()
_step_counter = 0


def _next_step() -> int:
    global _step_counter
    with _step_lock:
        _step_counter += 1
        return _step_counter


# ── Tool-call timing tracker ────────────────────────────────────────

_timing_lock = threading.Lock()
_tool_start_times: dict[str, float] = {}  # tool_name -> start time


def _start_timer(tool_name: str) -> None:
    with _timing_lock:
        _tool_start_times[tool_name] = time.monotonic()


def _elapsed(tool_name: str) -> float:
    with _timing_lock:
        start = _tool_start_times.pop(tool_name, None)
    if start is None:
        return 0.0
    return time.monotonic() - start


# ── Session-level token accumulator ─────────────────────────────────

_metrics_lock = threading.Lock()
_session_tokens_in = 0
_session_tokens_out = 0
_session_cached = 0


def _accumulate_tokens(tokens_in: int, tokens_out: int, cached: int) -> tuple[int, int, int]:
    """Add to session totals and return (total_in, total_out, total_cached)."""
    global _session_tokens_in, _session_tokens_out, _session_cached
    with _metrics_lock:
        _session_tokens_in += tokens_in
        _session_tokens_out += tokens_out
        _session_cached += cached
        return _session_tokens_in, _session_tokens_out, _session_cached


# ── Internal helpers ─────────────────────────────────────────────────

def _aop_enabled() -> bool:
    flag = (env_value("ADK_AOP_UI", "true") or "true").lower()
    return flag in {"1", "true", "yes"}


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


def _format_args_inline(args: dict[str, Any] | None) -> str:
    """Format tool args as a compact inline string: tool_name(key=val, ...)."""
    if not args:
        return ""
    parts = []
    for k, v in args.items():
        val_str = str(v)
        if len(val_str) > 40:
            val_str = val_str[:37] + "..."
        parts.append(f"{k}={val_str}")
    return ", ".join(parts)


def _extract_token_metrics(llm_response: Any) -> dict[str, int]:
    """Extract token usage from an LLM response."""
    data = _to_mapping(llm_response)
    if not data:
        return {}
    usage = data.get("usage_metadata") or {}
    if not isinstance(usage, dict):
        return {}
    return {
        "prompt": usage.get("prompt_token_count", 0) or 0,
        "completion": usage.get("candidates_token_count", 0) or 0,
        "cached": usage.get("cached_content_token_count", 0) or 0,
        "total": usage.get("total_token_count", 0) or 0,
    }


def _extract_model_version(llm_response: Any) -> str:
    data = _to_mapping(llm_response)
    if data:
        version = data.get("model_version")
        if isinstance(version, str):
            return version
    return ""


def _extract_response_text(llm_response: Any) -> str:
    """Extract the text summary from an LLM response for display."""
    data = _to_mapping(llm_response)
    if not data:
        return "(non-text response)"

    content = data.get("content")
    if not isinstance(content, dict):
        return "(non-text response)"

    parts = content.get("parts", [])
    if not isinstance(parts, list):
        return "(non-text response)"

    text_chunks = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str) and text.strip():
            text_chunks.append(text.strip())

    if not text_chunks:
        # Check for function calls
        fc_names = []
        for part in parts:
            if isinstance(part, dict):
                fc = part.get("function_call")
                if isinstance(fc, dict):
                    name = fc.get("name", "?")
                    fc_names.append(name)
        if fc_names:
            return f"→ Calling: {', '.join(fc_names)}"
        return "(non-text response)"

    combined = "\n".join(text_chunks)
    if len(combined) > 500:
        return combined[:497] + "..."
    return combined


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


def _timestamp_str() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _format_metrics_line(
    tokens_in: int,
    tokens_out: int,
    cached: int,
    total_in: int,
    total_out: int,
    total_cached: int,
    model: str = "",
) -> str:
    """Build a metrics footer line like the CTF-agent style."""
    ts = _timestamp_str()
    model_tag = f" ({model})" if model else ""
    return (
        f" [{ts}{model_tag}] "
        f"Current: I:{tokens_in} O:{tokens_out} C:{cached} | "
        f"Total: I:{total_in} O:{total_out} C:{total_cached}"
    )


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC CALLBACKS
# ═══════════════════════════════════════════════════════════════════════

def before_tool_callback(
    tool: Any = None,
    args: dict[str, Any] | None = None,
    tool_context: Any = None,
    **_: Any,
) -> dict | None:
    # ── Guardrail: blocked command patterns ──
    block_reason = _check_blocked_commands(args)
    if block_reason:
        step = _next_step()
        agent = _agent_name_from_tool_context(tool_context)
        print_compact_panel(
            f"⛔ {agent} - GUARDRAIL BLOCKED",
            f"Step {step:03d} | {block_reason}",
            Ansi.RED,
        )
        return {"error": block_reason, "blocked": True}

    # ── AOP: compact tool-call panel ──
    if not _aop_enabled():
        return None
    step = _next_step()
    agent = _agent_name_from_tool_context(tool_context)
    name = _tool_name(tool)
    _start_timer(name)

    args_display = _safe_json(args or {}, max_len=200)
    print_compact_panel(
        f"{agent} - Executing Tool",
        f"[{step:03d}] {name}({_format_args_inline(args)})\n{args_display}",
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
    agent = _agent_name_from_tool_context(tool_context)
    name = _tool_name(tool)
    elapsed = _elapsed(name)

    payload = tool_response if tool_response is not None else response
    output_text = _safe_json(payload or {}, max_len=1400)

    args_inline = _format_args_inline(args)
    header = f"{name}({args_inline}) [Total: {elapsed:.1f}s]"

    print_rich_panel(
        f"{agent} - {name} [Completed]",
        header_line=f"[{step:03d}] {header}",
        sub_panel_title="Tool Output",
        sub_panel_body=output_text,
        color_code=Ansi.GREEN,
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
    agent = _agent_name_from_tool_context(tool_context)
    name = _tool_name(tool)
    elapsed = _elapsed(name)
    resolved_error = error or exc or Exception("unknown tool error")

    print_rich_panel(
        f"⚠ {agent} - {name} [Error]",
        header_line=f"[{step:03d}] {name} failed after {elapsed:.1f}s",
        sub_panel_title="Error Details",
        sub_panel_body=str(resolved_error),
        color_code=Ansi.RED,
    )
    return None


def before_model_callback(callback_context: Any, llm_request: Any) -> Any:
    """Screen prompts for injection patterns before sending to the model."""
    injection_patterns = get_prompt_injection_patterns()
    if not injection_patterns:
        return None

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
            agent = _agent_name_from_callback_context(callback_context)
            print_compact_panel(
                f"⛔ {agent} - PROMPT INJECTION DETECTED",
                f"Step {step:03d} | Blocked pattern: {pattern}",
                Ansi.RED,
            )
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
    agent = _agent_name_from_callback_context(callback_context)

    # Extract metrics
    metrics = _extract_token_metrics(llm_response)
    tokens_in = metrics.get("prompt", 0)
    tokens_out = metrics.get("completion", 0)
    cached = metrics.get("cached", 0)
    total_in, total_out, total_cached = _accumulate_tokens(tokens_in, tokens_out, cached)
    model = _extract_model_version(llm_response)

    # Extract response text
    response_text = _extract_response_text(llm_response)
    metrics_line = _format_metrics_line(
        tokens_in, tokens_out, cached,
        total_in, total_out, total_cached,
        model,
    )

    print_rich_panel(
        f"Agent: {agent}",
        header_line=f"[{step:03d}] {agent} >> {response_text}",
        footer_line=metrics_line,
        color_code=Ansi.MAGENTA,
    )
    return None
