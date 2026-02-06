from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List

import requests
from shared.utils.env import env_value


@dataclass(frozen=True)
class MetricDef:
    name: str
    unit: str
    query_overrides_env: str
    query_candidates: List[str]


METRIC_DEFS: List[MetricDef] = [
    MetricDef(
        name="cpu_usage_percent",
        unit="percent",
        query_overrides_env="METRIC_QUERY_CPU_USAGE_PERCENT",
        query_candidates=[
            '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])))',
            "avg(system_cpu_usage_percent)",
        ],
    ),
    MetricDef(
        name="memory_usage_percent",
        unit="percent",
        query_overrides_env="METRIC_QUERY_MEMORY_USAGE_PERCENT",
        query_candidates=[
            "100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))",
            "avg(system_memory_usage_percent)",
        ],
    ),
    MetricDef(
        name="disk_usage_percent",
        unit="percent",
        query_overrides_env="METRIC_QUERY_DISK_USAGE_PERCENT",
        query_candidates=[
            '100 * (1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}))',
            "avg(system_disk_usage_percent)",
        ],
    ),
    MetricDef(
        name="network_io_mbps",
        unit="mbps",
        query_overrides_env="METRIC_QUERY_NETWORK_IO_MBPS",
        query_candidates=[
            "8 * sum(rate(node_network_receive_bytes_total[5m]) + rate(node_network_transmit_bytes_total[5m])) / 1000000",
            "sum(rate(system_network_io_bytes_total[5m])) * 8 / 1000000",
        ],
    ),
    MetricDef(
        name="request_p95_ms",
        unit="ms",
        query_overrides_env="METRIC_QUERY_REQUEST_P95_MS",
        query_candidates=[
            "1000 * histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))",
            "1000 * histogram_quantile(0.95, sum by (le) (rate(request_duration_seconds_bucket[5m])))",
        ],
    ),
    MetricDef(
        name="error_rate_percent",
        unit="percent",
        query_overrides_env="METRIC_QUERY_ERROR_RATE_PERCENT",
        query_candidates=[
            '100 * (sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])))',
            "100 * (sum(rate(http_server_requests_seconds_count{status=~\"5..\"}[5m])) / sum(rate(http_server_requests_seconds_count[5m])))",
        ],
    ),
]


def _mock_series(name: str, points: List[float], unit: str) -> Dict[str, Any]:
    return {
        "name": name,
        "unit": unit,
        "points": points,
        "latest": points[-1] if points else None,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def _metric_name_filter(query: str) -> set[str]:
    normalized = query.lower()
    include = set()
    for metric in METRIC_DEFS:
        if metric.name in normalized:
            include.add(metric.name)
    keyword_to_metric = {
        "cpu": "cpu_usage_percent",
        "memory": "memory_usage_percent",
        "disk": "disk_usage_percent",
        "network": "network_io_mbps",
        "latency": "request_p95_ms",
        "error": "error_rate_percent",
        "health": "",
    }
    for keyword, metric_name in keyword_to_metric.items():
        if keyword in normalized and metric_name:
            include.add(metric_name)
    return include


def _backend_url() -> str | None:
    for env_name in ["METRICS_BACKEND_URL", "PROMETHEUS_URL", "VICTORIAMETRICS_URL"]:
        value = env_value(env_name)
        if value:
            return value.rstrip("/")
    return None


def _request_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    token = env_value("METRICS_BEARER_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _extract_float_values(result: Any) -> List[float]:
    values: List[float] = []
    if not isinstance(result, list):
        return values
    for sample in result:
        if not isinstance(sample, dict):
            continue
        value_field = sample.get("value")
        if (
            isinstance(value_field, list)
            and len(value_field) >= 2
            and isinstance(value_field[1], str)
        ):
            try:
                values.append(float(value_field[1]))
            except ValueError:
                continue
    return values


def _query_metric(endpoint: str, promql: str, timeout: float = 3.0) -> List[float]:
    response = requests.get(
        f"{endpoint}/api/v1/query",
        params={"query": promql},
        headers=_request_headers(),
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "success":
        return []
    return _extract_float_values(payload.get("data", {}).get("result", []))


def _build_live_series(selected_metric_names: set[str]) -> Dict[str, Any]:
    endpoint = _backend_url()
    if not endpoint:
        return {"series": [], "missing": [], "errors": ["No metrics backend URL configured."]}

    series: List[Dict[str, Any]] = []
    missing: List[str] = []
    errors: List[str] = []
    selected = [m for m in METRIC_DEFS if not selected_metric_names or m.name in selected_metric_names]

    for metric in selected:
        query_candidates = []
        override = env_value(metric.query_overrides_env)
        if override:
            query_candidates.append(override)
        query_candidates.extend(metric.query_candidates)

        metric_values: List[float] = []
        for promql in query_candidates:
            try:
                metric_values = _query_metric(endpoint, promql)
            except requests.RequestException as exc:
                errors.append(f"{metric.name}: {exc}")
                continue
            if metric_values:
                break

        if not metric_values:
            missing.append(metric.name)
            continue

        latest = sum(metric_values) / len(metric_values)
        series.append(
            {
                "name": metric.name,
                "unit": metric.unit,
                "points": [latest],
                "latest": latest,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    return {"series": series, "missing": missing, "errors": errors, "endpoint": endpoint}


def _mock_series_bundle(selected_metric_names: set[str]) -> List[Dict[str, Any]]:
    mock_map = {
        "cpu_usage_percent": _mock_series("cpu_usage_percent", [58.2, 61.7, 64.3], "percent"),
        "memory_usage_percent": _mock_series("memory_usage_percent", [67.4, 71.2, 74.9], "percent"),
        "disk_usage_percent": _mock_series("disk_usage_percent", [52.1, 53.0, 54.4], "percent"),
        "network_io_mbps": _mock_series("network_io_mbps", [86.0, 92.0, 105.0], "mbps"),
        "request_p95_ms": _mock_series("request_p95_ms", [142.0, 165.0, 189.0], "ms"),
        "error_rate_percent": _mock_series("error_rate_percent", [0.6, 0.8, 1.3], "percent"),
    }
    if not selected_metric_names:
        return list(mock_map.values())
    return [series for name, series in mock_map.items() if name in selected_metric_names]


def fetch_metrics(query: str) -> Dict[str, Any]:
    selected_metric_names = _metric_name_filter(query)
    live_result = _build_live_series(selected_metric_names)
    live_series = live_result.get("series", [])
    missing = live_result.get("missing", [])
    errors = live_result.get("errors", [])

    # Use live mode only if all requested/selected metrics were resolved.
    if live_series and not missing:
        return {
            "query": query,
            "series": live_series,
            "source": "live",
            "backend_url": live_result.get("endpoint"),
            "missing_metrics": [],
            "note": "Live telemetry from configured metrics backend.",
        }

    fallback_series = _mock_series_bundle(selected_metric_names)
    return {
        "query": query,
        "series": fallback_series,
        "source": "mock",
        "backend_url": live_result.get("endpoint"),
        "missing_metrics": missing,
        "errors": errors[:10],
        "note": "Mock telemetry in use. Configure METRICS_BACKEND_URL/PROMETHEUS_URL/VICTORIAMETRICS_URL for live data.",
    }
