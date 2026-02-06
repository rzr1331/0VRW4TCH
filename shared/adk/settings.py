from __future__ import annotations

from shared.utils.env import env_value

def default_model() -> str:
    return env_value("ADK_MODEL", "gemini-2.5-flash-lite") or "gemini-2.5-flash-lite"


def app_name() -> str:
    return env_value("ADK_APP_NAME", "autonomous-secops-platform") or "autonomous-secops-platform"
