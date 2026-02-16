"""
Reasoning Tools.

Tools for agent reasoning, thought caching, and state management.
Adapted from CAI's reasoning.py.
"""


def think(thought: str) -> str:
    """
    Tool for caching complex reasoning and thoughts.
    
    Use this tool when you need to think through something complex.
    It doesn't obtain new information or change state, but helps
    structure reasoning and cache thoughts for later reference.
    
    Particularly useful for:
    - Breaking down complex problems
    - Tracking reasoning chains
    - Documenting decision rationale
    - Memory/cache for multi-step reasoning
    
    Args:
        thought: A thought or reasoning to process and cache
        
    Returns:
        The thought that was processed (echoed back)
        
    Examples:
        - think("The signals indicate a coordinated attack because...")
        - think("Considering options: 1) Isolate system 2) Block traffic...")
    """
    return f"{thought}"


def thought(
    breakdowns: str = "",
    reflection: str = "",
    action: str = "",
    next_step: str = "",
    key_clues: str = "",
) -> str:
    """
    Structured thought tool for detailed analysis.
    
    Use this for more structured reasoning with specific categories.
    
    Args:
        breakdowns: Detailed breakdown of current situation/findings
        reflection: Reflections on progress and insights gained
        action: Current or planned actions
        next_step: Next steps to take
        key_clues: Important clues or hints discovered
        
    Returns:
        Formatted string containing the provided thoughts
    """
    output = []
    if breakdowns:
        output.append(f"Breakdown: {breakdowns}")
    if reflection:
        output.append(f"Reflection: {reflection}")
    if action:
        output.append(f"Action: {action}")
    if next_step:
        output.append(f"Next Step: {next_step}")
    if key_clues:
        output.append(f"Key Clues: {key_clues}")
    return "\n".join(output) if output else "(no thoughts provided)"


def write_findings(findings: str, filename: str = "findings.txt") -> str:
    """
    Write key findings to a file for persistence.
    
    Use to record critical information like:
    - Discovered credentials
    - Found vulnerabilities
    - Important system access details
    
    Args:
        findings: The findings to write
        filename: File to write to (default: findings.txt)
        
    Returns:
        Confirmation message
    """
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write("\n" + findings + "\n")
        return f"Successfully wrote findings to {filename}"
    except Exception as e:
        return f"Error writing findings: {str(e)}"


def read_findings(filename: str = "findings.txt") -> str:
    """
    Read previously recorded findings.
    
    Args:
        filename: File to read from (default: findings.txt)
        
    Returns:
        Contents of the findings file
    """
    try:
        with open(filename, encoding="utf-8") as f:
            return f.read() or "(no findings recorded)"
    except FileNotFoundError:
        return f"{filename} not found. No findings have been recorded."
    except Exception as e:
        return f"Error reading findings: {str(e)}"
