"""
Magistrate Agent - Central Decision Maker for Security System.

The Magistrate is the judge and coordinator of the security agent system.
Uses self-contained tools (no CAI dependency).

Tools:
- think: For caching complex reasoning
- analyze_threat_signals, assess_severity, classify_attack_type, prioritize_actions

Sub-agents:
- Thought Agent: Deep reasoning for complex cases
- Action Kamen: Remediation execution
"""

from google.adk.agents import Agent

from config.security_config import get_model_for_agent
from agents.decision.security_magistrate.prompts import MAGISTRATE_INSTRUCTION, MAGISTRATE_DESCRIPTION
from agents.decision.security_magistrate.tools import (
    analyze_threat_signals,
    assess_severity,
    classify_attack_type,
    prioritize_actions,
)

# =============================================================================
# Reasoning Tool (self-contained, no CAI dependency)
# =============================================================================
from shared.security_tools.reasoning import think


# =============================================================================
# Sub-Agents (lazy loading to avoid circular imports)
# =============================================================================

_thought_agent = None
_security_enforcer_agent = None


def _get_thought_agent():
    """Lazy load Thought Agent."""
    global _thought_agent
    if _thought_agent is None:
        from agents.analysis.thought_agent.agent import thought_agent
        _thought_agent = thought_agent
    return _thought_agent


def _get_security_enforcer_agent():
    """Lazy load Security Enforcer Agent (formerly Action Kamen)."""
    global _security_enforcer_agent
    if _security_enforcer_agent is None:
        from agents.action.security_enforcer.agent import security_enforcer_agent
        _security_enforcer_agent = security_enforcer_agent
    return _security_enforcer_agent


def initialize_magistrate_sub_agents():
    """
    Initialize sub-agents after all modules are loaded.
    Call this after importing all agents.
    """
    magistrate_agent.sub_agents = [
        _get_thought_agent(),
        _get_security_enforcer_agent(),
    ]


# =============================================================================
# Agent Configuration
# =============================================================================

magistrate_tools = [
    think,                    # Reasoning/memory cache
    analyze_threat_signals,   # Correlate signals
    assess_severity,          # Determine severity
    classify_attack_type,     # Identify attack type
    prioritize_actions,       # Rank threats
]


# Create the Magistrate agent
magistrate_agent = Agent(
    model=get_model_for_agent("magistrate"),
    name="security_magistrate",
    description=MAGISTRATE_DESCRIPTION,
    instruction=MAGISTRATE_INSTRUCTION,
    tools=magistrate_tools,
    sub_agents=[],  # Populated by initialize_magistrate_sub_agents()
)


__all__ = ["magistrate_agent", "initialize_magistrate_sub_agents"]
