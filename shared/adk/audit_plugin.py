"""
Security Audit Plugin — centralized audit logging for the SecOps pipeline.

Implements ``BasePlugin`` to automatically log agent lifecycle events and tool
invocations to a structured JSONL audit trail at ``data/audit/audit.jsonl``.

Usage:
    The plugin is registered with the Runner at startup::

        from shared.adk.audit_plugin import SecurityAuditPlugin
        runner = Runner(agent=secops_pipeline, plugins=[SecurityAuditPlugin()])
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from google.adk.plugins import BasePlugin


# Default audit log path (overridable via AUDIT_LOG_PATH env var)
_DEFAULT_AUDIT_DIR = Path(__file__).resolve().parents[2] / "data" / "audit"
_AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", str(_DEFAULT_AUDIT_DIR / "audit.jsonl")))


def _ensure_dir() -> None:
    _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _write_entry(entry: dict[str, Any]) -> None:
    """Append a single JSON line to the audit log."""
    _ensure_dir()
    with open(_AUDIT_LOG_PATH, "a") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_name(obj: Any, fallback: str = "unknown") -> str:
    """Best-effort extract a name from an ADK object."""
    if isinstance(obj, str):
        return obj
    for attr in ("name", "__name__"):
        val = getattr(obj, attr, None)
        if isinstance(val, str) and val:
            return val
    return fallback


class SecurityAuditPlugin(BasePlugin):
    """Logs all pipeline events to a structured JSONL audit trail."""

    def __init__(self, name: str = "security_audit") -> None:
        super().__init__(name=name)

    # ---- Agent lifecycle ----

    def before_agent_callback(self, *, callback_context: Any = None, **kwargs: Any) -> None:
        agent_name = _extract_name(
            getattr(callback_context, "agent", callback_context), "unknown_agent"
        )
        _write_entry({
            "event": "agent_start",
            "agent": agent_name,
            "timestamp": _now_iso(),
        })

    def after_agent_callback(self, *, callback_context: Any = None, **kwargs: Any) -> None:
        agent_name = _extract_name(
            getattr(callback_context, "agent", callback_context), "unknown_agent"
        )
        _write_entry({
            "event": "agent_end",
            "agent": agent_name,
            "timestamp": _now_iso(),
        })

    # ---- Tool invocations ----

    def before_tool_callback(
        self,
        *,
        tool: Any = None,
        args: dict[str, Any] | None = None,
        tool_context: Any = None,
        **kwargs: Any,
    ) -> dict | None:
        tool_name = _extract_name(tool, "unknown_tool")
        agent_name = _extract_name(
            getattr(tool_context, "agent", tool_context), "unknown_agent"
        )
        # Store start time on tool_context for duration calculation
        if tool_context is not None:
            try:
                tool_context._audit_start = time.monotonic()
            except AttributeError:
                pass
        _write_entry({
            "event": "tool_call",
            "agent": agent_name,
            "tool": tool_name,
            "args": _safe_args(args),
            "timestamp": _now_iso(),
        })
        return None  # Don't intercept — just log

    def after_tool_callback(
        self,
        *,
        tool: Any = None,
        args: dict[str, Any] | None = None,
        tool_context: Any = None,
        tool_response: Any = None,
        **kwargs: Any,
    ) -> dict | None:
        tool_name = _extract_name(tool, "unknown_tool")
        agent_name = _extract_name(
            getattr(tool_context, "agent", tool_context), "unknown_agent"
        )
        duration = None
        if tool_context is not None:
            start = getattr(tool_context, "_audit_start", None)
            if start is not None:
                duration = round(time.monotonic() - start, 3)

        success = True
        if isinstance(tool_response, dict):
            success = tool_response.get("success", not tool_response.get("blocked", False))

        _write_entry({
            "event": "tool_result",
            "agent": agent_name,
            "tool": tool_name,
            "success": success,
            "duration_seconds": duration,
            "timestamp": _now_iso(),
        })
        return None

    def on_tool_error_callback(
        self,
        *,
        tool: Any = None,
        args: dict[str, Any] | None = None,
        tool_context: Any = None,
        error: Exception | None = None,
        **kwargs: Any,
    ) -> dict | None:
        tool_name = _extract_name(tool, "unknown_tool")
        agent_name = _extract_name(
            getattr(tool_context, "agent", tool_context), "unknown_agent"
        )
        _write_entry({
            "event": "tool_error",
            "agent": agent_name,
            "tool": tool_name,
            "error": str(error),
            "timestamp": _now_iso(),
        })
        return None


def _safe_args(args: dict[str, Any] | None) -> dict[str, Any]:
    """Redact sensitive fields from tool args before logging."""
    if not args:
        return {}
    redacted = dict(args)
    sensitive_keys = {"password", "secret", "token", "api_key", "credential"}
    for key in redacted:
        if any(s in key.lower() for s in sensitive_keys):
            redacted[key] = "***REDACTED***"
    return redacted
