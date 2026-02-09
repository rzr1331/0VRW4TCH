"""
Scenario: Ransomware Attack

Tests detection and response to active ransomware encryption.

Signals:
- Rapid file modifications (mass encryption)
- Ransom note created
- Known ransomware process detected
"""

from tests.base import ScenarioTest, ThreatScenario, register_scenario


@register_scenario
class RansomwareScenario(ScenarioTest):
    """Test: Detect and contain ransomware attack."""
    
    @property
    def scenario(self) -> ThreatScenario:
        return ThreatScenario(
            name="ransomware",
            description="Detect active ransomware encryption and contain immediately",
            threat_signals=[
                {
                    "source": "fault_finder",
                    "signal_type": "mass_file_modification",
                    "description": "15,000+ files modified in /data partition within 5 minutes",
                    "affected_systems": ["file-server-01"],
                    "indicators": {
                        "files_modified": 15342,
                        "time_window_minutes": 5,
                        "modification_pattern": "rename with .encrypted extension",
                        "affected_directories": ["/data/documents", "/data/backups", "/data/shared"],
                    }
                },
                {
                    "source": "fault_finder",
                    "signal_type": "ransom_note_created",
                    "description": "File 'README_DECRYPT.txt' created in multiple directories",
                    "affected_systems": ["file-server-01"],
                    "indicators": {
                        "filename": "README_DECRYPT.txt",
                        "content_preview": "YOUR FILES HAVE BEEN ENCRYPTED. Send 5 BTC to...",
                        "bitcoin_address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                        "copies_found": 847,
                    }
                },
                {
                    "source": "scope_analyser",
                    "signal_type": "suspicious_process",
                    "description": "Process 'svchost32.exe' running high I/O operations (Linux system)",
                    "affected_systems": ["file-server-01"],
                    "indicators": {
                        "process_name": "svchost32.exe",
                        "process_path": "/tmp/svchost32.exe",
                        "pid": 9847,
                        "io_bytes_sec": 524288000,  # 500MB/s
                        "suspicious_reason": "Windows executable name on Linux",
                    }
                },
                {
                    "source": "gatekeeper",
                    "signal_type": "c2_communication",
                    "description": "Outbound HTTP POST to known ransomware C2 server",
                    "affected_systems": ["file-server-01"],
                    "indicators": {
                        "destination_ip": "185.141.63.92",
                        "destination_port": 443,
                        "threat_intel_match": "LockBit ransomware C2",
                        "data_exfiltrated_mb": 25.3,
                    }
                },
            ],
            expected_severity="critical",
            expected_attack_type="ransomware",
            expected_actions=[
                "isolate_system",
                "terminate_process",
                "block_network_traffic",
                "disable_network_shares",
            ]
        )
    
    def validate_response(self, response: str) -> dict:
        """Validate ransomware response - must recommend isolation."""
        issues = []
        response_lower = response.lower()
        
        # MUST be critical severity
        if "critical" not in response_lower:
            issues.append("Ransomware must be classified as CRITICAL severity")
        
        # MUST identify as ransomware
        if "ransomware" not in response_lower:
            issues.append("Ransomware not identified")
        
        # MUST recommend isolation
        isolation_terms = ["isolate", "disconnect", "quarantine", "network isolation", "contain"]
        if not any(term in response_lower for term in isolation_terms):
            issues.append("Network isolation not recommended for ransomware")
        
        # Should recommend process termination
        if "terminate" not in response_lower and "kill" not in response_lower:
            issues.append("Process termination not recommended")
        
        return {"valid": len(issues) == 0, "issues": issues}
