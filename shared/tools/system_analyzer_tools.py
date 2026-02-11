from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Literal

from shared.tools.asset_discovery_tools import discover_runtime_assets
from shared.tools.monitoring_tools import fetch_metrics

Severity = Literal["low", "medium", "high", "critical"]

SEVERITY_POINTS: Dict[Severity, int] = {
    "low": 8,
    "medium": 18,
    "high": 30,
    "critical": 45,
}

SENSITIVE_PORTS: Dict[int, str] = {
    21: "FTP control port exposed",
    22: "SSH management port exposed",
    23: "Telnet management port exposed",
    2375: "Docker API exposed without TLS",
    3306: "MySQL database port exposed",
    3389: "RDP management port exposed",
    5432: "PostgreSQL database port exposed",
    6379: "Redis port exposed",
    6443: "Kubernetes API server port exposed",
    9200: "Elasticsearch HTTP port exposed",
    11211: "Memcached port exposed",
    27017: "MongoDB port exposed",
}

SUSPICIOUS_PROCESS_PATTERNS: Dict[str, str] = {
    "nmap ": "Active network scanning command detected",
    "masscan": "High-speed port scanning pattern detected",
    "sqlmap": "SQL injection tooling pattern detected",
    "hydra ": "Credential brute-force tooling pattern detected",
    "mimikatz": "Credential extraction tooling pattern detected",
    "xmrig": "Cryptominer process pattern detected",
    "nc -e": "Netcat reverse shell style execution detected",
    "bash -i": "Interactive shell launch pattern detected",
    "curl | sh": "Piped remote shell execution pattern detected",
    "wget http": "External binary/script download pattern detected",
}

METRIC_THRESHOLDS: Dict[str, Dict[Severity, float]] = {
    "cpu_usage_percent": {"medium": 75.0, "high": 85.0, "critical": 93.0, "low": 60.0},
    "memory_usage_percent": {
        "medium": 78.0,
        "high": 88.0,
        "critical": 95.0,
        "low": 65.0,
    },
    "disk_usage_percent": {"medium": 80.0, "high": 90.0, "critical": 96.0, "low": 70.0},
    "request_p95_ms": {
        "medium": 350.0,
        "high": 700.0,
        "critical": 1200.0,
        "low": 250.0,
    },
    "error_rate_percent": {"medium": 1.5, "high": 3.0, "critical": 5.0, "low": 0.7},
}


def _public_listener(local_address: str) -> bool:
    normalized = (local_address or "").strip().lower()
    return (
        normalized.startswith("0.0.0.0:")
        or normalized.startswith("*:")
        or normalized.startswith("[::]:")
        or normalized.startswith(":::")
    )


def _severity_from_threshold(
    value: float, thresholds: Dict[Severity, float]
) -> Severity | None:
    if value >= thresholds["critical"]:
        return "critical"
    if value >= thresholds["high"]:
        return "high"
    if value >= thresholds["medium"]:
        return "medium"
    if value >= thresholds["low"]:
        return "low"
    return None


def _add_finding(
    findings: List[Dict[str, Any]],
    *,
    finding_id: str,
    category: Literal["monitoring", "cybersecurity"],
    severity: Severity,
    title: str,
    description: str,
    evidence: List[str],
    recommendation: str,
) -> None:
    findings.append(
        {
            "id": finding_id,
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def _metric_anomalies(
    metrics_bundle: Dict[str, Any], findings: List[Dict[str, Any]]
) -> None:
    series = (
        metrics_bundle.get("series", []) if isinstance(metrics_bundle, dict) else []
    )
    for sample in series:
        if not isinstance(sample, dict):
            continue
        name = sample.get("name")
        latest = sample.get("latest")
        if (
            not isinstance(name, str)
            or name not in METRIC_THRESHOLDS
            or not isinstance(latest, (float, int))
        ):
            continue
        severity = _severity_from_threshold(float(latest), METRIC_THRESHOLDS[name])
        if not severity:
            continue
        _add_finding(
            findings,
            finding_id=f"metric-{name}",
            category="monitoring",
            severity=severity,
            title=f"Anomalous metric: {name}",
            description=f"{name} exceeded expected threshold with latest value {latest}.",
            evidence=[
                f"metric={name}",
                f"latest={latest}",
                f"source={metrics_bundle.get('source', 'unknown')}",
            ],
            recommendation="Review workload saturation, regressions, and alert routing for this metric.",
        )


def _port_exposure_anomalies(
    discovered_assets: Dict[str, Any], findings: List[Dict[str, Any]]
) -> None:
    listeners = discovered_assets.get("open_ports", {}).get("listeners", [])
    for listener in listeners:
        if not isinstance(listener, dict):
            continue
        port = listener.get("port")
        local_address = listener.get("local_address", "")
        if not isinstance(port, int) or port not in SENSITIVE_PORTS:
            continue
        if not _public_listener(str(local_address)):
            continue
        severity: Severity = "critical" if port in {2375, 6443} else "high"
        _add_finding(
            findings,
            finding_id=f"port-{port}",
            category="cybersecurity",
            severity=severity,
            title=f"Sensitive service exposed on {port}",
            description=SENSITIVE_PORTS[port],
            evidence=[
                f"port={port}",
                f"local_address={local_address}",
                f"process={listener.get('process', 'unknown')}",
                f"pid={listener.get('pid', 'unknown')}",
            ],
            recommendation="Restrict listener exposure with firewall rules, network policy, and service authentication.",
        )


def _suspicious_process_anomalies(
    discovered_assets: Dict[str, Any], findings: List[Dict[str, Any]]
) -> None:
    process_sample = discovered_assets.get("processes", {}).get("sample", [])
    for process in process_sample:
        if not isinstance(process, dict):
            continue
        command = str(process.get("command", ""))
        args = str(process.get("args", ""))
        fingerprint = f"{command} {args}".lower()
        for pattern, reason in SUSPICIOUS_PROCESS_PATTERNS.items():
            if pattern not in fingerprint:
                continue
            _add_finding(
                findings,
                finding_id=f"proc-{process.get('pid', 'unknown')}-{pattern.replace(' ', '-')}",
                category="cybersecurity",
                severity="critical",
                title="Suspicious process pattern detected",
                description=reason,
                evidence=[
                    f"pid={process.get('pid', 'unknown')}",
                    f"command={command}",
                    f"args={args[:180]}",
                ],
                recommendation="Validate process provenance, isolate host if malicious, and preserve forensic evidence.",
            )
            break


def _compose_recommendations(findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    monitoring: List[str] = []
    cybersecurity: List[str] = []
    for finding in findings:
        if finding.get("category") == "monitoring":
            monitoring.append(str(finding.get("recommendation", "")))
        if finding.get("category") == "cybersecurity":
            cybersecurity.append(str(finding.get("recommendation", "")))
    # Preserve order, remove duplicates.
    return {
        "monitoring": list(dict.fromkeys(monitoring)),
        "cybersecurity": list(dict.fromkeys(cybersecurity)),
    }


def _risk_scores(findings: List[Dict[str, Any]], metrics_source: str) -> Dict[str, Any]:
    monitoring = 0
    cybersecurity = 0
    for finding in findings:
        severity = finding.get("severity")
        points = SEVERITY_POINTS.get(severity, 0)
        if finding.get("category") == "monitoring":
            monitoring += points
        elif finding.get("category") == "cybersecurity":
            cybersecurity += points

    monitoring = min(monitoring, 100)
    cybersecurity = min(cybersecurity, 100)
    overall = min(round((monitoring + cybersecurity) / 2), 100)
    confidence = (
        0.45 if metrics_source == "mock" else 0.8 if metrics_source == "live" else 0.6
    )
    return {
        "monitoring_risk": monitoring,
        "cybersecurity_risk": cybersecurity,
        "overall_risk": overall,
        "confidence": confidence,
    }


def analyze_system_services(
    discovered_assets: Dict[str, Any],
    metrics_bundle: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    metrics_bundle = metrics_bundle or {}
    findings: List[Dict[str, Any]] = []

    _port_exposure_anomalies(discovered_assets, findings)
    _suspicious_process_anomalies(discovered_assets, findings)
    _metric_anomalies(metrics_bundle, findings)

    recommendations = _compose_recommendations(findings)
    metrics_source = str(metrics_bundle.get("source", "unknown"))

    services_count = int(discovered_assets.get("systemd", {}).get("count", 0))
    containers_count = int(discovered_assets.get("docker", {}).get("count", 0))
    open_ports_count = int(discovered_assets.get("open_ports", {}).get("count", 0))
    python_services = int(
        discovered_assets.get("processes", {}).get("python_service_count", 0)
    )

    notes: List[str] = []
    if metrics_source == "mock":
        notes.append("Telemetry source is mock; anomaly confidence is reduced.")
    if services_count == 0 and containers_count == 0:
        notes.append(
            "No running systemd services or docker containers were discovered."
        )

    risk = _risk_scores(findings, metrics_source)

    return {
        "analyzed_at": datetime.now(UTC).isoformat(),
        "runtime_profile": discovered_assets.get("runtime_profile", "unknown"),
        "services_summary": {
            "systemd_services": services_count,
            "containers": containers_count,
            "open_ports": open_ports_count,
            "python_services": python_services,
        },
        "telemetry_source": metrics_source,
        "risk_scores": risk,
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "total": len(findings),
        },
        "monitoring_recommendations": recommendations["monitoring"],
        "cybersecurity_recommendations": recommendations["cybersecurity"],
        "notes": notes,
    }


def analyze_local_system(
    query: str = "Analyze system services, monitoring posture, and cybersecurity anomalies.",
) -> Dict[str, Any]:
    discovered_assets = discover_runtime_assets()
    metrics_bundle = fetch_metrics(query)
    analysis = analyze_system_services(
        discovered_assets=discovered_assets, metrics_bundle=metrics_bundle
    )
    return {
        "query": query,
        "analysis": analysis,
    }
