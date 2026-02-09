"""
Thought Agent - Deep Reasoning Specialist.

The Thought Agent helps Magistrate with complex analysis that requires
careful reasoning, pattern recognition, and strategic thinking.

This agent has no tools - it relies purely on LLM reasoning capabilities.
The Magistrate delegates to it when facing ambiguous or complex cases.
"""

from google.adk.agents import Agent

from config.security_config import get_model_for_agent
from agents.analysis.thought_agent.prompts import THOUGHT_INSTRUCTION, THOUGHT_DESCRIPTION


# =============================================================================
# Agent Configuration
# =============================================================================
# Thought agent uses no tools - pure LLM reasoning
# This matches the CAI pattern where Thought Agent is a reasoning specialist

thought_agent = Agent(
    model=get_model_for_agent("thought"),
    name="thought",
    description=THOUGHT_DESCRIPTION,
    instruction=THOUGHT_INSTRUCTION,
    tools=[],  # No tools - pure reasoning
)


__all__ = ["thought_agent"]
