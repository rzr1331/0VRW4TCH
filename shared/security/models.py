"""
Pydantic models for structured threat data and inter-agent communication.

These models define the data structures passed between agents:
- ThreatSignal: Input from monitoring agents
- ThreatVerdict: Magistrate's decision
- RemediationOrder: Instructions for Action Kamen
- RemediationResult: Outcome of remediation actions
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Severity classification for threats."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackType(str, Enum):
    """Classification of attack types."""
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE = "ransomware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CRYPTOMINING = "cryptomining"
    CONTAINER_ESCAPE = "container_escape"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    SUSPICIOUS_PROCESS = "suspicious_process"
    CONFIGURATION_CHANGE = "configuration_change"
    UNKNOWN = "unknown"


class RemediationActionType(str, Enum):
    """Types of remediation actions Action Kamen can perform."""
    DISABLE_CREDENTIALS = "disable_credentials"
    ROTATE_CREDENTIALS = "rotate_credentials"
    ISOLATE_SYSTEM = "isolate_system"
    BLOCK_NETWORK_TRAFFIC = "block_network_traffic"
    TERMINATE_PROCESS = "terminate_process"
    ROLLBACK_CHANGES = "rollback_changes"
    EXECUTE_COMMAND = "execute_command"


class ThreatSignal(BaseModel):
    """
    Input signal from monitoring agents (Scope Analyser, Gatekeeper, etc.).
    
    This is what other team members' agents will send to Magistrate.
    """
    signal_id: str = Field(description="Unique identifier for this signal")
    source: str = Field(description="Source agent (e.g., 'scope_analyser', 'gatekeeper')")
    signal_type: str = Field(description="Type of signal (e.g., 'suspicious_process', 'unusual_traffic')")
    description: str = Field(description="Human-readable description of the detected issue")
    affected_systems: List[str] = Field(default_factory=list, description="List of affected system IDs")
    indicators: Dict[str, Any] = Field(default_factory=dict, description="Technical indicators (IPs, hashes, etc.)")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Raw data from the source agent")


class ThreatVerdict(BaseModel):
    """
    Magistrate's decision after analyzing threat signals.
    
    This contains the judgment and recommended actions.
    """
    verdict_id: str = Field(description="Unique identifier for this verdict")
    is_confirmed_attack: bool = Field(description="Whether this is a confirmed attack")
    attack_type: Optional[AttackType] = Field(default=None, description="Classification of the attack")
    severity: SeverityLevel = Field(description="Assessed severity level")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the verdict (0-1)")
    affected_systems: List[str] = Field(default_factory=list, description="Systems affected by this threat")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended remediation actions")
    reasoning: str = Field(description="Explanation of the verdict and reasoning")
    requires_immediate_action: bool = Field(default=False, description="Whether immediate action is needed")
    related_signal_ids: List[str] = Field(default_factory=list, description="IDs of signals that led to this verdict")


class RemediationOrder(BaseModel):
    """
    Instructions from Magistrate to Action Kamen.
    
    This is what Magistrate sends when delegating remediation.
    """
    order_id: str = Field(description="Unique identifier for this order")
    verdict_id: str = Field(description="Related verdict ID")
    action_type: RemediationActionType = Field(description="Type of action to perform")
    target_systems: List[str] = Field(description="Systems to apply the action to")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")
    priority: int = Field(ge=1, le=10, default=5, description="Priority (1=lowest, 10=highest)")
    safety_checks_required: bool = Field(default=True, description="Whether to perform safety checks")
    rollback_plan: Optional[str] = Field(default=None, description="How to rollback if action fails")


class RemediationResult(BaseModel):
    """
    Outcome of a remediation action performed by Action Kamen.
    """
    order_id: str = Field(description="Related order ID")
    success: bool = Field(description="Whether the action succeeded")
    action_taken: str = Field(description="Description of what was done")
    affected_systems: List[str] = Field(description="Systems that were modified")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
    execution_time_seconds: float = Field(description="Time taken to execute")
    changes_made: List[str] = Field(default_factory=list, description="List of specific changes made")
    rollback_available: bool = Field(default=False, description="Whether changes can be rolled back")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
