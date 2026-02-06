from __future__ import annotations

import os


UNSET_SENTINELS = {
    "",
    "none",
    "not_available",
    "n/a",
    "na",
    "null",
    "undefined",
    "off",
    "disabled",
}


def env_value(name: str, default: str | None = None) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip()
    if value.lower() in UNSET_SENTINELS:
        return default
    return value
