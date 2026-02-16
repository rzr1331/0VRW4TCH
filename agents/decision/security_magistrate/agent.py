"""
Magistrate Agent - Central Decision Maker for Security System.

The Magistrate is the judge and coordinator of the security agent system.
Uses self-contained tools (no CAI dependency).

Tools:
- think: For caching complex reasoning
- analyze_threat_signals, assess_severity, classify_attack_type, prioritize_actions

Sub-agents:
- Thought Agent: Deep reasoning for complex cases
- Security Enforcer: Remediation execution
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
# Sub-Agents (direct imports — wired at module load time)
# =============================================================================
from agents.analysis.thought_agent.agent import thought_agent
from agents.action.security_enforcer.agent import security_enforcer_agent


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
    output_key="decision_verdict",
    sub_agents=[thought_agent, security_enforcer_agent],
)


__all__ = ["magistrate_agent"]
