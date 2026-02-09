"""
Action Kamen Agent - Active Responder and Remediation Specialist.

This agent executes remediation actions ordered by Magistrate.
Uses self-contained execution tools (no CAI dependency).

Tools:
- Execution: generic_linux_command, run_ssh_command_with_credentials, execute_code
- Remediation: disable_credentials, rotate_credentials, isolate_system, etc.
"""

from google.adk.agents import Agent

from config.security_config import get_model_for_agent
from agents.action.security_enforcer.prompts import ACTION_KAMEN_INSTRUCTION, ACTION_KAMEN_DESCRIPTION

# =============================================================================
# Execution Tools (self-contained, no CAI dependency)
# =============================================================================
from shared.security_tools.linux_command import generic_linux_command_sync as generic_linux_command
from shared.security_tools.ssh_command import run_ssh_command_with_credentials
from shared.security_tools.code_executor import execute_code

# =============================================================================
# Remediation Tools
# =============================================================================
from agents.action.security_enforcer.tools import (
    disable_credentials,
    rotate_credentials,
    isolate_system,
    block_network_traffic,
    terminate_process,
    rollback_changes,
    execute_command,
    verify_remediation,
)

# =============================================================================
# Agent Configuration
# =============================================================================

# All tools available to Action Kamen
security_enforcer_tools = [
    # Execution tools
    generic_linux_command,            # Execute any command with guardrails
    run_ssh_command_with_credentials, # Remote SSH execution
    execute_code,                     # Multi-language code execution
    # Remediation tools
    disable_credentials,
    rotate_credentials,
    isolate_system,
    block_network_traffic,
    terminate_process,
    rollback_changes,
    execute_command,
    verify_remediation,
]


# Create the Action Kamen agent (renamed to security_enforcer for consistency)
security_enforcer_agent = Agent(
    model=get_model_for_agent("action_kamen"),
    name="security_enforcer",
    description=ACTION_KAMEN_DESCRIPTION,
    instruction=ACTION_KAMEN_INSTRUCTION,
    tools=security_enforcer_tools,
)


__all__ = ["security_enforcer_agent"]
