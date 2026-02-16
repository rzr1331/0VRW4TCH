"""
Tools for the Magistrate Agent.

These tools help the Magistrate analyze, correlate, and make decisions about threats.

TODO: For production, these tools would integrate with real threat intelligence,
SIEM systems, and security databases.
"""

import time
import json
from typing import List, Dict, Any, Optional

from config.settings import MOCK_MODE, MOCK_DELAY_SECONDS
from config.constants import SEVERITY_WEIGHTS, ATTACK_TYPE_DEFAULT_SEVERITY
from shared.security.models import SeverityLevel, AttackType


def analyze_threat_signals(
    signals: List[Dict[str, Any]],
    correlation_window_minutes: int = 30
) -> Dict[str, Any]:
    """
    Analyze and correlate multiple threat signals to identify patterns.
    
    This tool helps identify if multiple signals are related to the same attack
    by looking for common affected systems, timing, and indicators.
    
    Args:
        signals: List of threat signal dictionaries from monitoring agents
        correlation_window_minutes: Time window to consider signals as related
        
    Returns:
        Analysis results including correlations, patterns, and recommendations
    """
    if MOCK_MODE:
        time.sleep(MOCK_DELAY_SECONDS)
    
    if not signals:
        return {
            "status": "no_signals",
            "message": "No signals provided for analysis",
            "correlated_groups": [],
            "recommendations": ["Request signals from monitoring agents"]
        }
    
    # Extract common affected systems
    all_affected_systems = set()
    all_sources = set()
    signal_types = set()
    
    for signal in signals:
        if isinstance(signal, dict):
            all_affected_systems.update(signal.get("affected_systems", []))
            all_sources.add(signal.get("source", "unknown"))
            signal_types.add(signal.get("signal_type", "unknown"))
    
    # Determine if signals are correlated
    correlation_score = 0.0
    correlation_reasons = []
    
    # Multiple signals affecting same systems suggests correlation
    if len(signals) > 1 and len(all_affected_systems) < len(signals) * 2:
        correlation_score += 0.3
        correlation_reasons.append("Multiple signals affect overlapping systems")
    
    # Signals from multiple sources about same systems suggests real attack
    if len(all_sources) > 1:
        correlation_score += 0.3
        correlation_reasons.append(f"Signals from {len(all_sources)} different monitoring agents")
    
    # Check for known attack patterns
    attack_patterns_detected = []
    signal_type_set = signal_types
    
    if "suspicious_process" in signal_type_set and "c2_communication" in signal_type_set:
        attack_patterns_detected.append("ransomware_pattern")
        correlation_score += 0.4
    
    if "credential_anomaly" in signal_type_set and "lateral_movement" in signal_type_set:
        attack_patterns_detected.append("credential_theft_and_movement")
        correlation_score += 0.4
    
    if "data_exfiltration" in signal_type_set:
        attack_patterns_detected.append("data_breach")
        correlation_score += 0.3
    
    return {
        "status": "analyzed",
        "signal_count": len(signals),
        "affected_systems": list(all_affected_systems),
        "signal_sources": list(all_sources),
        "signal_types": list(signal_types),
        "correlation_score": min(correlation_score, 1.0),
        "correlation_reasons": correlation_reasons,
        "attack_patterns_detected": attack_patterns_detected,
        "is_likely_real_attack": correlation_score >= 0.5,
        "recommendations": _generate_analysis_recommendations(
            correlation_score, attack_patterns_detected, list(all_affected_systems)
        )
    }


def assess_severity(
    attack_type: str,
    affected_systems_count: int,
    has_active_data_loss: bool = False,
    has_credential_compromise: bool = False,
    is_spreading: bool = False
) -> Dict[str, Any]:
    """
    Assess the severity level of a confirmed or suspected attack.
    
    Uses multiple factors to determine severity:
    - Attack type inherent severity
    - Number of affected systems
    - Active data loss
    - Credential compromise
    - Spreading behavior
    
    Args:
        attack_type: Type of attack (e.g., "ransomware", "data_exfiltration")
        affected_systems_count: Number of systems affected
        has_active_data_loss: Whether data is actively being exfiltrated/destroyed
        has_credential_compromise: Whether credentials have been compromised
        is_spreading: Whether the attack is actively spreading
        
    Returns:
        Severity assessment with level, score, and factors
    """
    if MOCK_MODE:
        time.sleep(MOCK_DELAY_SECONDS)
    
    # Base severity from attack type
    base_severity = ATTACK_TYPE_DEFAULT_SEVERITY.get(attack_type.lower(), "medium")
    severity_score = SEVERITY_WEIGHTS.get(base_severity, 50)
    
    factors = [f"Base severity for {attack_type}: {base_severity}"]
    
    # Increase severity based on factors
    if affected_systems_count > 10:
        severity_score += 25
        factors.append(f"Large blast radius: {affected_systems_count} systems affected (+25)")
    elif affected_systems_count > 5:
        severity_score += 15
        factors.append(f"Multiple systems affected: {affected_systems_count} (+15)")
    elif affected_systems_count > 1:
        severity_score += 5
        factors.append(f"More than one system affected: {affected_systems_count} (+5)")
    
    if has_active_data_loss:
        severity_score += 30
        factors.append("Active data loss detected (+30)")
    
    if has_credential_compromise:
        severity_score += 20
        factors.append("Credentials compromised (+20)")
    
    if is_spreading:
        severity_score += 25
        factors.append("Attack actively spreading (+25)")
    
    # Determine final severity level
    if severity_score >= 100:
        final_severity = SeverityLevel.CRITICAL
    elif severity_score >= 75:
        final_severity = SeverityLevel.HIGH
    elif severity_score >= 50:
        final_severity = SeverityLevel.MEDIUM
    else:
        final_severity = SeverityLevel.LOW
    
    return {
        "severity_level": final_severity.value,
        "severity_score": min(severity_score, 100),
        "factors": factors,
        "requires_immediate_action": final_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH],
        "recommended_response_time": _get_response_time(final_severity),
    }


def classify_attack_type(
    signal_types: List[str],
    indicators: Dict[str, Any],
    process_names: Optional[List[str]] = None,
    network_behavior: Optional[str] = None
) -> Dict[str, Any]:
    """
    Classify the type of attack based on signals and indicators.
    
    Args:
        signal_types: List of signal types from monitoring agents
        indicators: Technical indicators (IPs, hashes, behaviors)
        process_names: Optional list of suspicious process names detected
        network_behavior: Optional description of network behavior
        
    Returns:
        Classification with attack type, confidence, and evidence
    """
    if MOCK_MODE:
        time.sleep(MOCK_DELAY_SECONDS)
    
    classifications = []
    evidence = []
    
    signal_set = set(signal_types)
    
    # Check for ransomware indicators
    if "suspicious_process" in signal_set or "configuration_change" in signal_set:
        if indicators.get("files_modified", 0) > 100:
            classifications.append((AttackType.RANSOMWARE, 0.9))
            evidence.append("Mass file modification detected")
        if indicators.get("file_extension_added"):
            classifications.append((AttackType.RANSOMWARE, 0.85))
            evidence.append(f"New file extension: {indicators.get('file_extension_added')}")
    
    # Check for data exfiltration
    if "data_exfiltration" in signal_set:
        classifications.append((AttackType.DATA_EXFILTRATION, 0.9))
        evidence.append("Unusual outbound data transfer detected")
        if indicators.get("bytes_transferred", 0) > 100_000_000:  # 100MB
            evidence.append(f"Large data transfer: {indicators.get('bytes_transferred')} bytes")
    
    # Check for credential theft
    if "credential_anomaly" in signal_set:
        classifications.append((AttackType.CREDENTIAL_THEFT, 0.85))
        evidence.append("Credential anomaly detected")
        if indicators.get("impossible_travel"):
            evidence.append("Impossible travel detected")
    
    # Check for privilege escalation
    if "privilege_escalation" in signal_set:
        classifications.append((AttackType.PRIVILEGE_ESCALATION, 0.8))
        evidence.append("Privilege escalation attempt detected")
    
    # Check for container escape
    if "container_escape_attempt" in signal_set:
        classifications.append((AttackType.CONTAINER_ESCAPE, 0.9))
        evidence.append("Container escape attempt detected")
    
    # Check for cryptomining
    if process_names:
        known_miners = ["xmrig", "minerd", "cpuminer", "ethminer", "phoenixminer"]
        for proc in process_names:
            if any(miner in proc.lower() for miner in known_miners):
                classifications.append((AttackType.CRYPTOMINING, 0.95))
                evidence.append(f"Known cryptominer process: {proc}")
    
    # Check for lateral movement
    if "lateral_movement" in signal_set:
        classifications.append((AttackType.LATERAL_MOVEMENT, 0.8))
        evidence.append("Lateral movement detected")
    
    # Determine primary classification
    if classifications:
        # Sort by confidence and take highest
        classifications.sort(key=lambda x: x[1], reverse=True)
        primary_type, confidence = classifications[0]
    else:
        primary_type = AttackType.UNKNOWN
        confidence = 0.5
        evidence.append("Unable to classify with high confidence")
    
    return {
        "primary_attack_type": primary_type.value,
        "confidence": confidence,
        "evidence": evidence,
        "all_classifications": [
            {"type": t.value, "confidence": c} for t, c in classifications
        ],
        "needs_further_investigation": confidence < 0.7,
    }


def prioritize_actions(
    threats: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Prioritize multiple threats and determine order of remediation.
    
    Args:
        threats: List of threat assessments with severity and type
        
    Returns:
        Prioritized list of actions with reasoning
    """
    if MOCK_MODE:
        time.sleep(MOCK_DELAY_SECONDS)
    
    if not threats:
        return {
            "status": "no_threats",
            "prioritized_actions": [],
            "message": "No threats to prioritize"
        }
    
    # Score each threat
    scored_threats = []
    for i, threat in enumerate(threats):
        severity = threat.get("severity_level", "medium")
        attack_type = threat.get("attack_type", "unknown")
        affected_count = len(threat.get("affected_systems", []))
        
        score = SEVERITY_WEIGHTS.get(severity, 50)
        
        # Bonus for actively spreading threats
        if threat.get("is_spreading"):
            score += 20
        
        # Bonus for data-loss threats
        if attack_type in ["ransomware", "data_exfiltration"]:
            score += 15
        
        scored_threats.append({
            "original_index": i,
            "threat": threat,
            "priority_score": score,
        })
    
    # Sort by priority score (highest first)
    scored_threats.sort(key=lambda x: x["priority_score"], reverse=True)
    
    prioritized = []
    for rank, item in enumerate(scored_threats, 1):
        prioritized.append({
            "priority_rank": rank,
            "priority_score": item["priority_score"],
            "threat": item["threat"],
            "recommended_action": _recommend_action_for_threat(item["threat"]),
        })
    
    return {
        "status": "prioritized",
        "total_threats": len(threats),
        "prioritized_actions": prioritized,
        "immediate_action_count": sum(
            1 for t in prioritized if t["priority_score"] >= 75
        ),
    }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _generate_analysis_recommendations(
    correlation_score: float,
    attack_patterns: List[str],
    affected_systems: List[str]
) -> List[str]:
    """Generate recommendations based on analysis results."""
    recommendations = []
    
    if correlation_score >= 0.7:
        recommendations.append("High correlation detected - treat as coordinated attack")
        recommendations.append("Immediately assess severity and classify attack type")
    elif correlation_score >= 0.4:
        recommendations.append("Moderate correlation - investigate further before action")
    else:
        recommendations.append("Low correlation - may be unrelated incidents")
    
    if "ransomware_pattern" in attack_patterns:
        recommendations.append("CRITICAL: Ransomware pattern detected - consider immediate isolation")
    
    if "data_breach" in attack_patterns:
        recommendations.append("CRITICAL: Data exfiltration detected - block egress immediately")
    
    if len(affected_systems) > 5:
        recommendations.append(f"Wide impact: {len(affected_systems)} systems - prioritize containment")
    
    return recommendations


def _get_response_time(severity: SeverityLevel) -> str:
    """Get recommended response time based on severity."""
    response_times = {
        SeverityLevel.CRITICAL: "Immediate (within minutes)",
        SeverityLevel.HIGH: "Urgent (within 1 hour)",
        SeverityLevel.MEDIUM: "Soon (within 4 hours)",
        SeverityLevel.LOW: "Scheduled (within 24-48 hours)",
    }
    return response_times.get(severity, "As soon as possible")


def _recommend_action_for_threat(threat: Dict[str, Any]) -> str:
    """Recommend specific action for a threat type."""
    attack_type = threat.get("attack_type", "unknown")
    
    action_map = {
        "ransomware": "Isolate affected systems, disable network access, preserve evidence",
        "data_exfiltration": "Block external connections, disable compromised accounts",
        "credential_theft": "Rotate credentials, invalidate sessions, enable MFA",
        "privilege_escalation": "Revoke elevated permissions, audit access logs",
        "container_escape": "Terminate container, isolate host, audit other containers",
        "cryptomining": "Terminate malicious processes, patch entry vector",
        "lateral_movement": "Segment network, block inter-host SSH, audit credentials",
    }
    
    return action_map.get(attack_type, "Investigate and contain as appropriate")
