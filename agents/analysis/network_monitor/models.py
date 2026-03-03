from __future__ import annotations


# Severity base points — mirrors the weighting style in anomaly_detector/models.py
_SEVERITY_POINTS: dict[str, float] = {
    "critical": 0.40,
    "high": 0.25,
    "medium": 0.12,
    "low": 0.05,
}

# Signal-type multipliers for network-specific detections
_SIGNAL_TYPE_MULTIPLIERS: dict[str, float] = {
    "data_exfiltration": 1.4,
    "c2_communication": 1.5,
    "dns_tunneling": 1.3,
    "arp_spoofing": 1.2,
    "ip_spoofing": 1.2,
    "suspicious_outbound": 1.0,
    "lateral_movement": 1.2,
    "port_scan": 0.8,
    "large_transfer": 1.0,
    "unusual_connection": 0.9,
}


def score_network_threat(features: dict) -> float:
    """Score network threat level from 0.0 (clean) to 1.0 (critical).

    ``features`` shape::

        {
            "findings": [{"severity": "high", "signal_type": "c2_communication", ...}, ...],
            "bytes_out_mbps": float,       # optional — egress rate
            "unique_external_ips": int,    # optional — distinct external peers
        }
    """
    findings = features.get("findings", [])
    score = 0.0

    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "")).lower()
        signal_type = str(finding.get("signal_type", "")).lower()

        base = _SEVERITY_POINTS.get(severity, 0.0)
        multiplier = _SIGNAL_TYPE_MULTIPLIERS.get(signal_type, 1.0)
        score += base * multiplier

    # Elevated egress adds pressure
    bytes_out_mbps = features.get("bytes_out_mbps")
    if isinstance(bytes_out_mbps, (int, float)):
        mbps = float(bytes_out_mbps)
        if mbps >= 500:
            score += 0.20
        elif mbps >= 100:
            score += 0.10
        elif mbps >= 50:
            score += 0.05

    # Many distinct external IPs suggests scanning or spray behaviour
    unique_external = features.get("unique_external_ips")
    if isinstance(unique_external, int):
        if unique_external >= 50:
            score += 0.15
        elif unique_external >= 20:
            score += 0.08
        elif unique_external >= 10:
            score += 0.04

    return round(min(score, 1.0), 3)
