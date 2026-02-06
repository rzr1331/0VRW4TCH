from __future__ import annotations

from datetime import datetime


def next_tick(interval_seconds: int) -> datetime:
    # TODO: implement scheduler logic
    return datetime.utcnow()
