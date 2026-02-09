"""
Mock signals for testing the security agent system.

These simulate signals that would come from other agents:
- Scope Analyser
- Gatekeeper  
- Network Monitor
- Fault Finder

TODO: Replace these with real function calls when integrating with other agents.
"""

from typing import List
from datetime import datetime
import uuid

from shared.security.models import ThreatSignal


def generate_signal_id() -> str:
    """Generate a unique signal ID."""
    return f"sig-{uuid.uuid4().hex[:8]}"


# =============================================================================
# MOCK SIGNALS FROM SCOPE ANALYSER
# =============================================================================

def mock_scope_analyser_cryptomining() -> ThreatSignal:
    """Simulates Scope Analyser detecting cryptomining behavior."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="scope_analyser",
        signal_type="suspicious_process",
        description="Detected process 'xmrig' consuming 95% CPU on container 'web-app-01'. Matches known cryptominer signatures.",
        affected_systems=["web-app-01", "host-node-03"],
        indicators={
            "process_name": "xmrig",
            "process_pid": 4521,
            "cpu_usage": 0.95,
            "memory_usage_mb": 512,
            "matched_signatures": ["xmrig", "monero-miner"],
            "process_hash": "a1b2c3d4e5f6789012345678901234567890abcd",
        },
        timestamp=datetime.now().isoformat(),
    )


def mock_scope_analyser_container_escape() -> ThreatSignal:
    """Simulates Scope Analyser detecting container escape attempt."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="scope_analyser",
        signal_type="container_escape_attempt",
        description="Container 'backend-api-02' attempted to access host namespace. Detected mount of /host/proc.",
        affected_systems=["backend-api-02", "host-node-01"],
        indicators={
            "container_id": "abc123def456",
            "container_name": "backend-api-02",
            "escape_technique": "proc_mount",
            "suspicious_mounts": ["/host/proc", "/host/sys"],
            "capabilities_requested": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
        },
        timestamp=datetime.now().isoformat(),
    )


# =============================================================================
# MOCK SIGNALS FROM GATEKEEPER
# =============================================================================

def mock_gatekeeper_credential_theft() -> ThreatSignal:
    """Simulates Gatekeeper detecting credential theft."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="gatekeeper",
        signal_type="credential_anomaly",
        description="User 'admin@company.com' credentials used from unusual location (Russia) after successful login from USA 5 minutes ago.",
        affected_systems=["auth-service", "user-database"],
        indicators={
            "user_id": "admin@company.com",
            "original_location": {"country": "USA", "city": "San Francisco", "ip": "192.168.1.100"},
            "suspicious_location": {"country": "Russia", "city": "Moscow", "ip": "45.33.32.156"},
            "time_between_logins_seconds": 300,
            "impossible_travel": True,
            "session_ids": ["sess-abc123", "sess-xyz789"],
        },
        timestamp=datetime.now().isoformat(),
    )


def mock_gatekeeper_privilege_escalation() -> ThreatSignal:
    """Simulates Gatekeeper detecting privilege escalation attempt."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="gatekeeper",
        signal_type="privilege_escalation",
        description="User 'dev-user-05' attempted to access admin API endpoints without proper permissions. Multiple failed attempts detected.",
        affected_systems=["api-gateway", "admin-panel"],
        indicators={
            "user_id": "dev-user-05",
            "attempted_endpoints": ["/admin/users", "/admin/config", "/admin/secrets"],
            "failure_count": 15,
            "time_window_minutes": 10,
            "source_ip": "10.0.0.55",
        },
        timestamp=datetime.now().isoformat(),
    )


# =============================================================================
# MOCK SIGNALS FROM NETWORK MONITOR
# =============================================================================

def mock_network_monitor_data_exfiltration() -> ThreatSignal:
    """Simulates Network Monitor detecting data exfiltration."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="network_monitor",
        signal_type="data_exfiltration",
        description="Unusual outbound data transfer detected. Container 'db-backup-01' sent 500MB to external IP 185.199.108.1 over port 443.",
        affected_systems=["db-backup-01", "firewall-01"],
        indicators={
            "source_ip": "10.0.1.50",
            "destination_ip": "185.199.108.1",
            "destination_port": 443,
            "bytes_transferred": 524288000,  # 500MB
            "duration_seconds": 120,
            "protocol": "HTTPS",
            "geo_location": {"country": "Netherlands", "city": "Amsterdam"},
            "domain": "suspicious-storage.example.com",
        },
        timestamp=datetime.now().isoformat(),
    )


def mock_network_monitor_lateral_movement() -> ThreatSignal:
    """Simulates Network Monitor detecting lateral movement."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="network_monitor",
        signal_type="lateral_movement",
        description="Container 'compromised-app' making SSH connections to multiple internal hosts. Potential lateral movement.",
        affected_systems=["compromised-app", "internal-host-01", "internal-host-02", "internal-host-03"],
        indicators={
            "source_container": "compromised-app",
            "source_ip": "10.0.2.100",
            "target_hosts": [
                {"ip": "10.0.2.101", "port": 22, "success": True},
                {"ip": "10.0.2.102", "port": 22, "success": False},
                {"ip": "10.0.2.103", "port": 22, "success": True},
            ],
            "connection_count": 25,
            "time_window_minutes": 5,
        },
        timestamp=datetime.now().isoformat(),
    )


# =============================================================================
# MOCK SIGNALS FROM FAULT FINDER
# =============================================================================

def mock_fault_finder_exposed_secrets() -> ThreatSignal:
    """Simulates Fault Finder detecting exposed secrets."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="fault_finder",
        signal_type="exposed_secrets",
        description="Exposed secrets detected in container 'payment-service'. Environment variables contain unencrypted API keys and database passwords.",
        affected_systems=["payment-service", "database-prod"],
        indicators={
            "container_name": "payment-service",
            "exposed_secrets": [
                {"name": "DATABASE_PASSWORD", "type": "password", "location": "env_var"},
                {"name": "STRIPE_API_KEY", "type": "api_key", "location": "env_var"},
                {"name": "AWS_SECRET_KEY", "type": "cloud_credential", "location": "env_var"},
            ],
            "risk_score": 9.5,
        },
        timestamp=datetime.now().isoformat(),
    )


def mock_fault_finder_vulnerable_component() -> ThreatSignal:
    """Simulates Fault Finder detecting vulnerable components."""
    return ThreatSignal(
        signal_id=generate_signal_id(),
        source="fault_finder",
        signal_type="vulnerability",
        description="Critical vulnerability CVE-2024-1234 detected in 'log4j' library used by container 'java-app'. Allows remote code execution.",
        affected_systems=["java-app"],
        indicators={
            "container_name": "java-app",
            "vulnerability_id": "CVE-2024-1234",
            "severity": "critical",
            "cvss_score": 10.0,
            "affected_library": "log4j",
            "affected_version": "2.14.0",
            "fixed_version": "2.17.1",
            "exploitable": True,
        },
        timestamp=datetime.now().isoformat(),
    )


# =============================================================================
# COMBINED SCENARIO SIGNALS
# =============================================================================

def mock_ransomware_attack_signals() -> List[ThreatSignal]:
    """
    Simulates a multi-signal ransomware attack scenario.
    
    Returns multiple correlated signals that together indicate ransomware.
    """
    base_time = datetime.now()
    
    return [
        ThreatSignal(
            signal_id=generate_signal_id(),
            source="scope_analyser",
            signal_type="suspicious_process",
            description="Detected mass file encryption. Process 'cryptor.exe' modifying files in /data with .encrypted extension.",
            affected_systems=["file-server-01"],
            indicators={
                "process_name": "cryptor.exe",
                "files_modified": 1500,
                "file_extension_added": ".encrypted",
                "encryption_speed_files_per_second": 50,
            },
            timestamp=base_time.isoformat(),
        ),
        ThreatSignal(
            signal_id=generate_signal_id(),
            source="network_monitor",
            signal_type="c2_communication",
            description="Command and control communication detected. File server contacting known ransomware C2 server.",
            affected_systems=["file-server-01"],
            indicators={
                "destination_ip": "203.0.113.50",
                "destination_domain": "ransom-c2.evil.com",
                "protocol": "HTTPS",
                "beacon_interval_seconds": 60,
            },
            timestamp=base_time.isoformat(),
        ),
        ThreatSignal(
            signal_id=generate_signal_id(),
            source="fault_finder",
            signal_type="configuration_change",
            description="Shadow copies deleted. VSS service disabled on file-server-01.",
            affected_systems=["file-server-01"],
            indicators={
                "service_disabled": "VSS",
                "shadow_copies_deleted": True,
                "backup_integrity": "compromised",
            },
            timestamp=base_time.isoformat(),
        ),
    ]


def get_all_mock_signals() -> List[ThreatSignal]:
    """Get a list of all individual mock signals for testing."""
    return [
        mock_scope_analyser_cryptomining(),
        mock_scope_analyser_container_escape(),
        mock_gatekeeper_credential_theft(),
        mock_gatekeeper_privilege_escalation(),
        mock_network_monitor_data_exfiltration(),
        mock_network_monitor_lateral_movement(),
        mock_fault_finder_exposed_secrets(),
        mock_fault_finder_vulnerable_component(),
    ]
