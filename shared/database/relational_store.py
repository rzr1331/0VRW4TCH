from typing import Any, Dict


class RelationalStore:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def record_incident(self, incident: Dict[str, Any]) -> None:
        # TODO: integrate PostgreSQL
        _ = incident
