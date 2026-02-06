from __future__ import annotations

from .actuators import enforce_policy
from .safety import guardrail_check


def enforce_with_guardrails(action: dict) -> dict:
    if not guardrail_check(action):
        return {"status": "blocked", "action": action}
    return enforce_policy(action)


TOOLS = [enforce_with_guardrails]
