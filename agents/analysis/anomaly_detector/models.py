from __future__ import annotations


def score_anomaly(features: dict) -> float:
    metrics = features.get("metrics", {})
    findings = features.get("findings", [])

    score = 0.0

    # Weight explicit anomaly findings from the system analyzer.
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "")).lower()
        if severity == "critical":
            score += 0.35
        elif severity == "high":
            score += 0.22
        elif severity == "medium":
            score += 0.12
        elif severity == "low":
            score += 0.06

    # Add metric pressure when metric values are elevated.
    series = metrics.get("series", []) if isinstance(metrics, dict) else []
    for sample in series:
        if not isinstance(sample, dict):
            continue
        name = sample.get("name")
        latest = sample.get("latest")
        if not isinstance(latest, (float, int)):
            continue
        value = float(latest)
        if name in {"cpu_usage_percent", "memory_usage_percent", "disk_usage_percent"}:
            if value >= 95:
                score += 0.2
            elif value >= 85:
                score += 0.12
            elif value >= 75:
                score += 0.07
        elif name == "error_rate_percent":
            if value >= 5:
                score += 0.2
            elif value >= 2:
                score += 0.12
            elif value >= 1:
                score += 0.07
        elif name == "request_p95_ms":
            if value >= 1200:
                score += 0.2
            elif value >= 700:
                score += 0.12
            elif value >= 350:
                score += 0.07

    return round(min(score, 1.0), 3)
