"""
Scenario: Credential Theft

Tests detection of credential harvesting/stealing attempts.

Signals:
- Failed login attempts followed by success
- Suspicious authentication patterns
- Credential dumping tool detected
"""

from tests.base import ScenarioTest, ThreatScenario, register_scenario


@register_scenario
class CredentialTheftScenario(ScenarioTest):
    """Test: Detect credential theft and secure accounts."""
    
    @property
    def scenario(self) -> ThreatScenario:
        return ThreatScenario(
            name="credential_theft",
            description="Detect credential theft and secure compromised accounts",
            threat_signals=[
                {
                    "source": "gatekeeper",
                    "signal_type": "brute_force_success",
                    "description": "47 failed logins followed by successful login for admin@company.com",
                    "affected_systems": ["auth-server-01"],
                    "indicators": {
                        "target_account": "admin@company.com",
                        "failed_attempts": 47,
                        "success_at": "2024-01-15T14:32:00Z",
                        "source_ips": ["185.234.72.11", "185.234.72.12", "185.234.72.13"],
                        "source_country": "Unknown/Tor",
                        "account_type": "admin",
                    }
                },
                {
                    "source": "scope_analyser",
                    "signal_type": "credential_dumping_tool",
                    "description": "Mimikatz detected running on workstation-42",
                    "affected_systems": ["workstation-42"],
                    "indicators": {
                        "tool_name": "mimikatz.exe",
                        "process_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\m.exe",
                        "detection_method": "behavioral + signature",
                        "lsass_access": True,
                        "credentials_extracted": ["local_admin", "domain_user"],
                    }
                },
                {
                    "source": "gatekeeper",
                    "signal_type": "impossible_travel",
                    "description": "User jsmith logged in from NYC and Singapore within 30 minutes",
                    "affected_systems": ["vpn-gateway-01"],
                    "indicators": {
                        "user": "jsmith",
                        "location_1": {"city": "New York", "time": "14:00"},
                        "location_2": {"city": "Singapore", "time": "14:28"},
                        "travel_time_hours": 18,
                        "actual_gap_minutes": 28,
                    }
                },
            ],
            expected_severity="critical",
            expected_attack_type="credential_theft",
            expected_actions=[
                "disable_credentials",
                "rotate_credentials",
                "terminate_sessions",
                "investigate_lateral_movement",
            ]
        )
    
    def validate_response(self, response: str) -> dict:
        """Validate credential theft response - must disable/rotate credentials."""
        issues = []
        response_lower = response.lower()
        
        # Should be high/critical
        if "high" not in response_lower and "critical" not in response_lower:
            issues.append("Credential theft should be high/critical severity")
        
        # Should identify credential-related attack
        cred_terms = ["credential", "password", "account", "authentication", "mimikatz", "brute force"]
        if not any(term in response_lower for term in cred_terms):
            issues.append("Credential theft not identified")
        
        # MUST recommend credential action
        action_terms = ["disable", "reset", "rotate", "revoke", "block account", "lock account"]
        if not any(term in response_lower for term in action_terms):
            issues.append("Credential disable/reset not recommended")
        
        return {"valid": len(issues) == 0, "issues": issues}
