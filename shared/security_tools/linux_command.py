"""
Generic Linux Command Tool.

Execute any shell command with security guardrails and session management.
Adapted from CAI's generic_linux_command.py.

Features:
- Dangerous pattern detection and blocking
- Unicode homograph attack detection
- Command output sanitization
- Session management for interactive commands
"""

import os
import re
import unicodedata
from typing import Optional

from shared.security_tools.common import (
    run_command_async,
    check_dangerous_patterns,
    sanitize_command_output,
)


def detect_unicode_homographs(text: str) -> tuple[bool, str]:
    """
    Detect and normalize Unicode homograph characters.
    
    These are characters that look similar to ASCII but are different
    Unicode code points, used in homograph attacks.
    
    Args:
        text: Text to check
        
    Returns:
        Tuple of (has_homographs, normalized_text)
    """
    homograph_map = {
        # Cyrillic to Latin mappings
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o',
        '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
        '\u0410': 'A', '\u0415': 'E', '\u041e': 'O',
        '\u0420': 'P', '\u0421': 'C', '\u0425': 'X',
        # Greek to Latin mappings
        '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p',
        '\u03c5': 'u', '\u03c7': 'x',
        '\u0391': 'A', '\u039f': 'O', '\u03a1': 'P',
    }
    
    has_homographs = any(char in text for char in homograph_map)
    
    normalized = text
    for homograph, replacement in homograph_map.items():
        normalized = normalized.replace(homograph, replacement)
    
    normalized = unicodedata.normalize('NFKD', normalized)
    
    return (has_homographs, normalized)


async def generic_linux_command(
    command: str = "",
    interactive: bool = False,
    session_id: Optional[str] = None,
) -> str:
    """
    Execute shell commands with security guardrails.
    
    This tool executes any command while checking for dangerous patterns,
    Unicode homograph attacks, and other security issues.
    
    Args:
        command: The complete command to execute (e.g., "ls -la", "cat file.txt")
        interactive: Set to True for commands needing persistent sessions
                    (ssh, nc, python, etc.) - currently simplified
        session_id: Reserved for future session management
        
    Returns:
        Command output or error message
        
    Examples:
        - generic_linux_command("ls -la")
        - generic_linux_command("ps aux | grep python")
        - generic_linux_command("cat /etc/passwd")
    """
    if not command.strip():
        return "Error: No command provided"
    
    # Check for Unicode homograph bypass attempts
    guardrails_enabled = os.getenv("SECURITY_AGENTS_GUARDRAILS", "true").lower() != "false"
    
    if guardrails_enabled:
        has_homographs, normalized_command = detect_unicode_homographs(command)
        if has_homographs:
            dangerous_commands = ['curl', 'wget', 'nc ', 'netcat', 'bash', 'sh ', 'exec', 'eval']
            if any(cmd in normalized_command.lower() for cmd in dangerous_commands):
                if '$(' in normalized_command or '`' in normalized_command:
                    return "Error: Blocked Unicode homograph bypass attempt."
                return "Error: Blocked command with suspicious Unicode characters."
        
        # Check for dangerous patterns
        error = check_dangerous_patterns(command)
        if error:
            return error
        
        # Block curl/wget with command substitution
        if re.match(r'^\s*(curl|wget)\s+', command, re.IGNORECASE):
            if '$(env)' in command or '`env`' in command:
                return "Error: Blocked curl/wget command attempting to exfiltrate environment variables."
    
    # Execute the command
    result = await run_command_async(command, timeout=100)
    
    # Sanitize output if guardrails enabled
    if guardrails_enabled:
        result = sanitize_command_output(command, result)
    
    return result


# Synchronous wrapper for non-async contexts
def generic_linux_command_sync(
    command: str = "",
    interactive: bool = False,
    session_id: Optional[str] = None,
) -> str:
    """
    Synchronous version of generic_linux_command.
    
    Use this when you're not in an async context.
    """
    import asyncio
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a new loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run,
                    generic_linux_command(command, interactive, session_id)
                )
                return future.result()
        else:
            return loop.run_until_complete(
                generic_linux_command(command, interactive, session_id)
            )
    except RuntimeError:
        return asyncio.run(generic_linux_command(command, interactive, session_id))
