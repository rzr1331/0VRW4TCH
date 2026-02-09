"""
Execution Tools - Self-contained tools for command execution.

This module provides core execution tools copied and adapted from CAI.
No external CAI dependency required.

Tools:
- generic_linux_command: Execute any command with session management and guardrails
- run_ssh_command_with_credentials: Remote SSH command execution
- execute_code: Multi-language code execution
- think: Reasoning/memory cache tool
"""

from .linux_command import generic_linux_command_sync as generic_linux_command
from .ssh_command import run_ssh_command_with_credentials
from .code_executor import execute_code
from .reasoning import think

__all__ = [
    "generic_linux_command",
    "run_ssh_command_with_credentials",
    "execute_code",
    "think",
]
