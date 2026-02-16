"""
Domain constants for the SecOps platform.

These values encode business logic and security domain knowledge.
They don't change per deployment — only per business rule update.

For runtime/deployment config, see config.settings.
"""
from __future__ import annotations


# =============================================================================
# SEVERITY CONFIGURATION
# =============================================================================

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}

# Threshold for auto-remediation (severities >= this trigger immediate action)
AUTO_REMEDIATION_THRESHOLD: str = "high"


# =============================================================================
# ATTACK TYPE CONFIGURATION
# =============================================================================

ATTACK_TYPE_DEFAULT_SEVERITY: dict[str, str] = {
    "ransomware": "critical",
    "data_exfiltration": "critical",
    "container_escape": "critical",
    "privilege_escalation": "high",
    "unauthorized_access": "high",
    "credential_theft": "high",
    "cryptomining": "medium",
    "lateral_movement": "medium",
    "suspicious_process": "medium",
    "configuration_change": "low",
}


# =============================================================================
# REMEDIATION ACTIONS
# =============================================================================

REMEDIATION_ACTIONS: dict[str, dict] = {
    "disable_credentials": {
        "description": "Disable compromised user credentials",
        "risk_level": "medium",
        "reversible": True,
    },
    "rotate_credentials": {
        "description": "Rotate credentials for a user or service",
        "risk_level": "low",
        "reversible": False,
    },
    "isolate_system": {
        "description": "Network-isolate a compromised system",
        "risk_level": "high",
        "reversible": True,
    },
    "block_network_traffic": {
        "description": "Block specific IP/port combinations",
        "risk_level": "medium",
        "reversible": True,
    },
    "terminate_process": {
        "description": "Kill a malicious process",
        "risk_level": "medium",
        "reversible": False,
    },
    "rollback_changes": {
        "description": "Revert configuration or file changes",
        "risk_level": "medium",
        "reversible": False,
    },
}


# =============================================================================
# SIGNAL SOURCES
# =============================================================================

SIGNAL_SOURCES: list[str] = [
    "scope_analyser",
    "gatekeeper",
    "network_monitor",
    "fault_finder",
]
