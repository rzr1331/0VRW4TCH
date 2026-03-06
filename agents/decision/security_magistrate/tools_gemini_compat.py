"""
JSON wrapper for magistrate tools - fixes Gemini compatibility.

Gemini rejects function parameters with Dict[str, Any] type hints because they
generate OpenAPI schemas with `additionalProperties`, which isn't supported.

This module wraps all magistrate tools to accept/return JSON strings instead.
"""
from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Callable

from agents.decision.security_magistrate import tools as raw_tools


def _deep_parse(value: Any) -> Any:
    """Recursively parse JSON strings into Python objects."""
    if isinstance(value, str) and value.strip() and value.strip()[0] in '[{':
        try:
            parsed = json.loads(value)
            return _deep_parse(parsed)
        except (json.JSONDecodeError, ValueError):
            return value
    if isinstance(value, list):
        return [_deep_parse(item) for item in value]
    if isinstance(value, dict):
        return {k: _deep_parse(v) for k, v in value.items()}
    return value


def _json_wrapper(func: Callable) -> Callable:
    """Wrap a tool to accept/return JSON strings instead of dicts/lists."""
    @functools.wraps(func)
    def wrapped(**kwargs: Any) -> str:
        # Parse JSON string kwargs back to Python objects (deep)
        parsed_kwargs = {}
        for key, value in kwargs.items():
            parsed_kwargs[key] = _deep_parse(value)

        # Call original tool
        result = func(**parsed_kwargs)

        # Serialize result to JSON if it's not already a string
        if not isinstance(result, str):
            return json.dumps(result)
        return result

    # Rewrite signature: replace Dict/List annotations with str
    orig_sig = inspect.signature(func)
    new_params = []
    for param in orig_sig.parameters.values():
        ann = param.annotation
        if ann is not inspect.Parameter.empty and ('Dict' in str(ann) or 'List' in str(ann)):
            param = param.replace(annotation=str)
        new_params.append(param)
    wrapped.__signature__ = orig_sig.replace(parameters=new_params, return_annotation=str)
    wrapped.__annotations__ = {
        k: str if 'Dict' in str(v) or 'List' in str(v) else v
        for k, v in (func.__annotations__ or {}).items()
    }

    return wrapped


# Re-export wrapped tools
analyze_threat_signals = _json_wrapper(raw_tools.analyze_threat_signals)
assess_severity = _json_wrapper(raw_tools.assess_severity)
classify_attack_type = _json_wrapper(raw_tools.classify_attack_type)
prioritize_actions = _json_wrapper(raw_tools.prioritize_actions)
