"""
Scenario: Container Escape

Tests detection of container breakout/escape attempts.

Signals:
- Privileged container operations
- Host filesystem access from container
- Escape exploit detected
"""

from tests.integration.base import ScenarioTest, ThreatScenario, register_scenario


@register_scenario
class ContainerEscapeScenario(ScenarioTest):
    """Test: Detect container escape and contain threat."""
    
    @property
    def scenario(self) -> ThreatScenario:
        return ThreatScenario(
            name="container_escape",
            description="Detect container escape attempt and isolate affected nodes",
            threat_signals=[
                {
                    "source": "scope_analyser",
                    "signal_type": "container_privilege_escalation",
                    "description": "Container attempting to access /proc/sys from pod webapp-frontend-7d8f9",
                    "affected_systems": ["k8s-worker-03", "pod/webapp-frontend-7d8f9"],
                    "indicators": {
                        "container_id": "abc123def456",
                        "image": "webapp:latest",
                        "namespace": "production",
                        "access_attempt": "/proc/sys/kernel/core_pattern",
                        "privileged": False,
                        "capabilities": ["SYS_ADMIN", "NET_ADMIN"],
                    }
                },
                {
                    "source": "scope_analyser",
                    "signal_type": "host_filesystem_access",
                    "description": "Container gained access to host filesystem via mounted docker.sock",
                    "affected_systems": ["k8s-worker-03"],
                    "indicators": {
                        "mount_path": "/var/run/docker.sock",
                        "host_path_access": ["/etc/shadow", "/root/.ssh"],
                        "files_read": ["/etc/shadow", "/root/.ssh/id_rsa"],
                        "container_id": "abc123def456",
                    }
                },
                {
                    "source": "fault_finder",
                    "signal_type": "container_escape_exploit",
                    "description": "CVE-2022-0185 exploit detected - container escape via file_handle",
                    "affected_systems": ["k8s-worker-03"],
                    "indicators": {
                        "cve": "CVE-2022-0185",
                        "exploit_method": "file_handle overflow",
                        "kernel_version": "5.4.0-100-generic",
                        "escape_successful": True,
                        "host_process_spawned": True,
                        "host_pid": 1847,
                    }
                },
            ],
            expected_severity="critical",
            expected_attack_type="container_escape",
            expected_actions=[
                "isolate_system",
                "terminate_process",
                "kill_container",
                "cordon_node",
            ]
        )
    
    def validate_response(self, response: str) -> dict:
        """Validate container escape response - must isolate node."""
        issues = []
        response_lower = response.lower()
        
        # MUST be critical
        if "critical" not in response_lower:
            issues.append("Container escape must be CRITICAL severity")
        
        # Should identify container escape
        escape_terms = ["container escape", "breakout", "privilege escalation", "cve-2022", "host access"]
        if not any(term in response_lower for term in escape_terms):
            issues.append("Container escape not identified")
        
        # MUST recommend node isolation or container kill
        action_terms = ["isolate", "cordon", "kill", "terminate", "stop container", "quarantine"]
        if not any(term in response_lower for term in action_terms):
            issues.append("Node isolation or container termination not recommended")
        
        return {"valid": len(issues) == 0, "issues": issues}
