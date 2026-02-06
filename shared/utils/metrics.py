from typing import Any


def emit_metric(name: str, value: float, **labels: Any) -> None:
    # TODO: wire to Prometheus or OpenTelemetry
    _ = (name, value, labels)
