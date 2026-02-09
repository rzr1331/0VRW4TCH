"""
SSH Command Tool.

Execute commands on remote hosts via SSH using password authentication.
Adapted from CAI's sshpass.py.

Requires: sshpass installed on the system
"""

import shlex
from .common import run_command


def run_ssh_command_with_credentials(
    host: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
) -> str:
    """
    Execute a command on a remote host via SSH using password authentication.
    
    Uses sshpass for non-interactive password authentication.
    Requires sshpass to be installed on the local system.
    
    Args:
        host: Remote host address (IP or hostname)
        username: SSH username
        password: SSH password
        command: Command to execute on remote host
        port: SSH port (default: 22)
        
    Returns:
        Output from the remote command execution
        
    Examples:
        - run_ssh_command_with_credentials("192.168.1.100", "admin", "pass123", "ls -la")
        - run_ssh_command_with_credentials("server.example.com", "root", "secret", "whoami", port=2222)
    """
    # Validate port
    try:
        port = int(port)
        if port <= 0 or port > 65535:
            return "Error: Port must be between 1 and 65535"
    except (ValueError, TypeError):
        return "Error: Port is not a valid integer"
    
    # Escape special characters to prevent shell injection
    quoted_password = shlex.quote(password)
    quoted_username = shlex.quote(username)
    quoted_host = shlex.quote(host)
    quoted_command = shlex.quote(command)
    
    # Build SSH command with sshpass
    ssh_command = (
        f"sshpass -p {quoted_password} "
        f"ssh -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o LogLevel=ERROR "
        f"{quoted_username}@{quoted_host} -p {port} "
        f"{quoted_command}"
    )
    
    return run_command(ssh_command, timeout=60)
