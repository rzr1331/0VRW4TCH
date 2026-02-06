from typing import Any, Dict


class GraphStore:
    def __init__(self, uri: str, user: str, password: str) -> None:
        self.uri = uri
        self.user = user
        self.password = password

    def upsert_asset(self, asset: Dict[str, Any]) -> None:
        # TODO: integrate Neo4j
        _ = asset
