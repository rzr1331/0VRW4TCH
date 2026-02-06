from typing import Any, Dict


class TimeSeriesStore:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def write_metric(self, name: str, value: float, labels: Dict[str, Any]) -> None:
        # TODO: integrate VictoriaMetrics
        _ = (name, value, labels)
