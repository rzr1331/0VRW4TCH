"""
Policy Loader — loads and caches YAML policy files at startup.

Provides accessor functions for guardrails, security policies, and compliance
policies used by callbacks and plugins across the agent pipeline.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


_POLICY_DIR = Path(__file__).resolve().parents[2] / "config" / "policies"


def _load_yaml(filename: str) -> dict[str, Any]:
    """Load a YAML file from the policies directory."""
    path = _POLICY_DIR / filename
    if not path.exists():
        return {}
    with open(path, "r") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


@lru_cache(maxsize=1)
def get_guardrails() -> dict[str, Any]:
    """Return the guardrails policy (cached singleton)."""
    data = _load_yaml("guardrails.yaml")
    return data.get("guardrails", {})


@lru_cache(maxsize=1)
def get_security_policies() -> dict[str, Any]:
    """Return the security policies (cached singleton)."""
    data = _load_yaml("security_policies.yaml")
    return data.get("policies", [])


@lru_cache(maxsize=1)
def get_compliance_policies() -> dict[str, Any]:
    """Return the compliance policies (cached singleton)."""
    data = _load_yaml("compliance_policies.yaml")
    return data.get("policies", [])


def get_blocked_commands() -> list[str]:
    """Return the list of blocked shell command patterns."""
    return get_guardrails().get("blocked_commands", [])


def get_confirmation_tools() -> list[str]:
    """Return tool names that require human confirmation."""
    return get_guardrails().get("require_confirmation", [])


def get_prompt_injection_patterns() -> list[str]:
    """Return prompt injection patterns to screen for."""
    return get_guardrails().get("prompt_injection_patterns", [])


def get_max_timeout(tool_name: str) -> int | None:
    """Return the max timeout for a tool, or None if unlimited."""
    timeouts = get_guardrails().get("max_timeout_seconds", {})
    return timeouts.get(tool_name)
