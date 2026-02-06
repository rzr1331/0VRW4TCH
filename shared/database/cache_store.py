from typing import Any


class CacheStore:
    def __init__(self, url: str) -> None:
        self.url = url

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        # TODO: integrate Redis
        _ = (key, value, ttl)
