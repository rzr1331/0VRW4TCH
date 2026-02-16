"""
Scenario: Cryptomining Attack

Tests detection and response to cryptomining activity on a server.

Signals:
- High CPU usage detected by monitoring agent
- Suspicious process (xmrig) found
- Outbound connections to mining pool
"""

from tests.base import ScenarioTest, ThreatScenario, register_scenario


@register_scenario
class CryptominingScenario(ScenarioTest):
    """Test: Detect and neutralize cryptomining activity."""
    
    @property
    def scenario(self) -> ThreatScenario:
        return ThreatScenario(
            name="cryptomining",
            description="Detect and neutralize cryptomining on production server",
            threat_signals=[
                {
                    "source": "scope_analyser",
                    "signal_type": "high_cpu_usage", 
                    "description": "Server web-prod-01 showing 98% CPU usage for 2+ hours",
                    "affected_systems": ["web-prod-01"],
                    "indicators": {
                        "cpu_percent": 98,
                        "duration_hours": 2.5,
                    }
                },
                {
                    "source": "scope_analyser",
                    "signal_type": "suspicious_process",
                    "description": "Unknown process 'xmrig' consuming 95% CPU resources",
                    "affected_systems": ["web-prod-01"],
                    "indicators": {
                        "process_name": "xmrig",
                        "process_path": "/tmp/.hidden/xmrig",
                        "cpu_percent": 95,
                        "pid": 28451,
                    }
                },
                {
                    "source": "gatekeeper",
                    "signal_type": "suspicious_outbound_connection",
                    "description": "Connections to known mining pool stratum+tcp://pool.minexmr.com:4444",
                    "affected_systems": ["web-prod-01"],
                    "indicators": {
                        "destination_ip": "142.93.12.45",
                        "destination_port": 4444,
                        "protocol": "stratum",
                        "domain": "pool.minexmr.com",
                    }
                },
            ],
            expected_severity="high",
            expected_attack_type="cryptomining",
            expected_actions=[
                "terminate_process",
                "block_network_traffic",
                "investigate_persistence",
            ]
        )
    
    def validate_response(self, response: str) -> dict:
        """Validate cryptomining detection response."""
        issues = []
        response_lower = response.lower()
        
        # Check severity
        if "high" not in response_lower and "critical" not in response_lower:
            issues.append("Expected high/critical severity for cryptomining")
        
        # Check if cryptomining was identified
        cryptomining_terms = ["cryptomining", "crypto mining", "miner", "xmrig", "mining"]
        if not any(term in response_lower for term in cryptomining_terms):
            issues.append("Cryptomining not identified in response")
        
        # Check for recommended actions
        action_terms = ["terminate", "kill", "stop", "block", "isolate"]
        if not any(term in response_lower for term in action_terms):
            issues.append("No remediation action recommended")
        
        return {"valid": len(issues) == 0, "issues": issues}
