"""
Action Kamen Agent - Active Responder and Remediation Specialist.

This agent executes remediation actions ordered by Magistrate.
Uses self-contained execution tools (no CAI dependency).

Tools:
- Execution: generic_linux_command, run_ssh_command_with_credentials, execute_code
- Remediation: disable_credentials, rotate_credentials, isolate_system, etc.

High-risk tools are wrapped with FunctionTool(require_confirmation=True)
to gate destructive actions behind human approval.
"""

from google.adk.agents import Agent
from google.adk.tools import FunctionTool

from config.settings import get_model_for_agent
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
# Tool confirmation wrappers — high-risk tools require human approval
# =============================================================================

# These 5 tools can execute arbitrary commands, kill processes, or isolate
# systems. They MUST be gated behind confirmation before running.
_confirmed_terminate_process = FunctionTool(
    func=terminate_process, require_confirmation=True
)
_confirmed_isolate_system = FunctionTool(
    func=isolate_system, require_confirmation=True
)
_confirmed_execute_command = FunctionTool(
    func=execute_command, require_confirmation=True
)
_confirmed_linux_command = FunctionTool(
    func=generic_linux_command, require_confirmation=True
)
_confirmed_execute_code = FunctionTool(
    func=execute_code, require_confirmation=True
)
_confirmed_ssh_command = FunctionTool(
    func=run_ssh_command_with_credentials, require_confirmation=True
)


# =============================================================================
# Agent Configuration
# =============================================================================

# All tools available to Action Kamen
security_enforcer_tools = [
    # High-risk (require confirmation)
    _confirmed_linux_command,
    _confirmed_ssh_command,
    _confirmed_execute_code,
    _confirmed_terminate_process,
    _confirmed_isolate_system,
    _confirmed_execute_command,
    # Low-risk (no confirmation)
    disable_credentials,
    rotate_credentials,
    block_network_traffic,
    rollback_changes,
    verify_remediation,
]


# Create the Action Kamen agent (renamed to security_enforcer for consistency)
security_enforcer_agent = Agent(
    model=get_model_for_agent("action_kamen"),
    name="security_enforcer",
    description=ACTION_KAMEN_DESCRIPTION,
    instruction=ACTION_KAMEN_INSTRUCTION,
    tools=security_enforcer_tools,
    output_key="enforcement_result",
)


__all__ = ["security_enforcer_agent"]
