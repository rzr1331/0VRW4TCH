"""
JSON wrapper for magistrate tools - fixes Gemini compatibility.

Gemini rejects function parameters with Dict[str, Any] type hints because they
generate OpenAPI schemas with `additionalProperties`, which isn't supported.

This module wraps all magistrate tools to accept/return JSON strings instead.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from agents.decision.security_magistrate import tools as raw_tools


def _json_wrapper(func: Callable) -> Callable:
    """Wrap a tool to accept/return JSON strings instead of dicts/lists."""
    def wrapped(**kwargs: Any) -> str:
        # Parse JSON string kwargs back to Python objects
        parsed_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str) and value.strip() and (value.strip()[0] in '[{'):
                try:
                    parsed_kwargs[key] = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    parsed_kwargs[key] = value
            else:
                parsed_kwargs[key] = value
       
        # Call original tool
        result = func(**parsed_kwargs)
        
        # Serialize result to JSON if it's not already a string
        if not isinstance(result, str):
            return json.dumps(result)
        return result
    
    # Preserve function metadata
    wrapped.__name__ = func.__name__
    wrapped.__doc__ = func.__doc__
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
