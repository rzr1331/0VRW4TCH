"""
Central configuration for Security Agents.

All hardcoded values go here. No other file should contain hardcoded configurations.
Load from environment variables with sensible defaults.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


# =============================================================================
# MODEL CONFIGURATION
# =============================================================================

# Model provider: "gemini" or "zai" (Z.AI GLM via LiteLLM)
MODEL_PROVIDER = "zai"

# Default model (LiteLLM uses "zai/model-name" format for Z.AI)
# glm-4.5-flash is free tier, glm-4.7 requires paid resource package
DEFAULT_MODEL = "zai/glm-4.7-flash"

# Z.AI Configuration
# Only ZAI_API_KEY needs to be exported: export ZAI_API_KEY=your_key
# LiteLLM reads ZAI_API_KEY directly - no OPENAI vars needed!

# Model configuration per agent
AGENT_MODELS = {
    "magistrate": DEFAULT_MODEL,
    "action_kamen": DEFAULT_MODEL,
    "thought": DEFAULT_MODEL,
}


# =============================================================================
# SEVERITY CONFIGURATION
# =============================================================================

# Severity level weights for prioritization (higher = more urgent)
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}

# Threshold for auto-remediation (severities >= this trigger immediate action)
AUTO_REMEDIATION_THRESHOLD = "high"


# =============================================================================
# ATTACK TYPE CONFIGURATION
# =============================================================================

# Known attack types and their default severity
ATTACK_TYPE_DEFAULT_SEVERITY = {
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
# REMEDIATION ACTIONS CONFIGURATION
# =============================================================================

# Available remediation actions and their risk levels
# TODO: These will need real implementations when moving from mock to production
REMEDIATION_ACTIONS = {
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
# MOCK MODE CONFIGURATION
# =============================================================================

# When True, tools simulate actions instead of executing real commands
# TODO: Set to False and implement real tools for production
MOCK_MODE = False

# Mock delay in seconds (simulates real operation time)
MOCK_DELAY_SECONDS = float(os.getenv("SECURITY_AGENTS_MOCK_DELAY", "0.5"))


# =============================================================================
# SIGNAL SOURCE CONFIGURATION
# =============================================================================

# Expected signal sources (other agents that will send signals)
# These are placeholders until integrated with actual agents
SIGNAL_SOURCES = [
    "scope_analyser",
    "gatekeeper",
    "network_monitor",
    "fault_finder",
]


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

LOG_LEVEL = os.getenv("SECURITY_AGENTS_LOG_LEVEL", "INFO")


def get_model_for_agent(agent_name: str):
    model_name = AGENT_MODELS.get(agent_name.lower(), DEFAULT_MODEL)
    
    if MODEL_PROVIDER == "zai":
        # Use LiteLLM wrapper for Z.AI models
        from google.adk.models.lite_llm import LiteLlm
        model = LiteLlm(
            model=model_name,  # Your Z.ai model
            api_key=os.getenv("ZAI_API_KEY"),
            litellm_params={
                "max_parallel_requests": 1,  # Forces concurrency=1
                "tpm_limit": 5000,         # Optional rate limit
                "rpm_limit": 40
            }
        )

        return model
    
    # Gemini models use string directly
    return model_name


