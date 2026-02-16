"""
Scenario: Data Exfiltration

Tests detection of data being stolen from the network.

Signals:
- Unusual data transfer to external IP
- After-hours database queries
- Large archive file created
"""

from tests.base import ScenarioTest, ThreatScenario, register_scenario


@register_scenario
class DataExfiltrationScenario(ScenarioTest):
    """Test: Detect and block data exfiltration attempt."""
    
    @property
    def scenario(self) -> ThreatScenario:
        return ThreatScenario(
            name="data_exfiltration",
            description="Detect and block active data exfiltration",
            threat_signals=[
                {
                    "source": "gatekeeper",
                    "signal_type": "unusual_data_transfer",
                    "description": "4.7GB data transferred to external IP over past hour",
                    "affected_systems": ["db-prod-02", "web-admin-01"],
                    "indicators": {
                        "data_size_gb": 4.7,
                        "destination_ip": "91.234.56.78",
                        "destination_country": "Unknown/VPN",
                        "transfer_duration_minutes": 58,
                        "protocol": "HTTPS",
                        "port": 443,
                    }
                },
                {
                    "source": "scope_analyser",
                    "signal_type": "suspicious_database_activity",
                    "description": "Bulk SELECT queries on customer_data table at 3AM",
                    "affected_systems": ["db-prod-02"],
                    "indicators": {
                        "query_type": "SELECT *",
                        "table": "customer_data",
                        "rows_accessed": 2500000,
                        "timestamp": "2024-01-15T03:15:00Z",
                        "source_user": "service_account_backup",
                        "normal_access_time": "09:00-18:00",
                    }
                },
                {
                    "source": "fault_finder",
                    "signal_type": "suspicious_file_creation",
                    "description": "Large encrypted archive created in /tmp",
                    "affected_systems": ["web-admin-01"],
                    "indicators": {
                        "filename": "/tmp/.cache/backup_data.tar.gz.enc",
                        "size_mb": 4850,
                        "created_at": "2024-01-15T03:45:00Z",
                        "accessed_by": "www-data",
                    }
                },
            ],
            expected_severity="critical",
            expected_attack_type="data_exfiltration",
            expected_actions=[
                "block_network_traffic",
                "disable_credentials",
                "preserve_evidence",
            ]
        )
    
    def validate_response(self, response: str) -> dict:
        """Validate data exfiltration response."""
        issues = []
        response_lower = response.lower()
        
        # Should be high/critical
        if "high" not in response_lower and "critical" not in response_lower:
            issues.append("Data exfiltration should be high/critical severity")
        
        # Should identify exfiltration
        exfil_terms = ["exfiltration", "data theft", "data leak", "stealing data", "data breach"]
        if not any(term in response_lower for term in exfil_terms):
            issues.append("Data exfiltration not identified")
        
        # Should block traffic or investigate source
        action_terms = ["block", "stop", "investigate", "disable", "credential"]
        if not any(term in response_lower for term in action_terms):
            issues.append("No blocking or investigation action recommended")
        
        return {"valid": len(issues) == 0, "issues": issues}
