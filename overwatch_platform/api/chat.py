"""
Escalation chat — agentic investigation of escalated sweeps.

Provides a stateful chat per escalation session where the LLM can
run diagnostic commands and tools to answer the operator's questions.
Runs an agentic tool loop: model calls tools → we execute → feed results
back → repeat until the model produces a final text answer.
"""
from __future__ import annotations

import json
import logging
import shlex
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from google import genai

from config.settings import DEFAULT_MODEL

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT_DIR / "data" / "overwatch.db"

logger = logging.getLogger("overwatch.chat")

router = APIRouter(prefix="/dashboard/api/chat", tags=["chat"])

# In-memory conversation history keyed by session ID
_conversations: dict[str, list[dict[str, Any]]] = {}

# Max tool call iterations to prevent infinite loops
MAX_TOOL_ITERATIONS = 8

# Commands allowed for diagnostic execution
_ALLOWED_COMMANDS = {
    "lsof", "ss", "netstat", "ps", "top", "who", "w", "last",
    "df", "du", "free", "uptime", "uname", "hostname", "id",
    "ifconfig", "ip", "arp", "route", "dig", "nslookup", "host",
    "cat", "head", "tail", "wc", "grep", "find", "ls", "stat",
    "file", "strings", "md5sum", "sha256sum", "openssl",
    "systemctl", "journalctl", "dmesg", "sysctl",
    "docker", "kubectl",
}

# Patterns that are never allowed
_BLOCKED_PATTERNS = [
    "rm ", "rm\t", "rmdir", "mkfs", "dd ", "dd\t",
    "> /dev/", "chmod 777", "curl | sh", "wget | sh",
    "eval ", "exec ", ":(){ ", "fork",
]


class ChatRequest(BaseModel):
    session_id: str
    message: str


class ChatResponse(BaseModel):
    reply: str
    session_id: str
    tool_calls: list[dict[str, Any]] = []


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DEFAULT_DB)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _run_diagnostic_command(command: str, timeout: int = 10) -> dict[str, Any]:
    """Execute a safe diagnostic command and return the output."""
    command = command.strip()

    # Safety checks
    for pattern in _BLOCKED_PATTERNS:
        if pattern in command:
            return {"error": f"Blocked: command contains dangerous pattern '{pattern}'"}

    # Check first word against allowlist
    parts = shlex.split(command) if command else []
    if not parts:
        return {"error": "Empty command"}

    base_cmd = parts[0].split("/")[-1]  # handle /usr/bin/lsof etc.
    if base_cmd not in _ALLOWED_COMMANDS:
        return {"error": f"Command '{base_cmd}' not in allowed list. Allowed: {sorted(_ALLOWED_COMMANDS)}"}

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout[:5000] if result.stdout else ""
        stderr = result.stderr[:1000] if result.stderr else ""
        return {
            "command": command,
            "exit_code": result.returncode,
            "stdout": output,
            "stderr": stderr,
        }
    except subprocess.TimeoutExpired:
        return {"command": command, "error": f"Timed out after {timeout}s"}
    except Exception as exc:
        return {"command": command, "error": str(exc)}


def _check_port(port: int, proto: str = "tcp") -> dict[str, Any]:
    """Check what process is using a specific port."""
    return _run_diagnostic_command(f"lsof -nP -i {proto}:{port}")


def _check_process(pid: int) -> dict[str, Any]:
    """Get detailed info about a process by PID."""
    return _run_diagnostic_command(f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,stat,start,command")


def _check_connections(ip: str | None = None, port: int | None = None) -> dict[str, Any]:
    """Check active connections, optionally filtered by IP or port."""
    if ip:
        return _run_diagnostic_command(f"lsof -nP -i @{ip}")
    elif port:
        return _run_diagnostic_command(f"lsof -nP -i :{port}")
    else:
        return _run_diagnostic_command("netstat -an | head -50")


def _list_listening_ports() -> dict[str, Any]:
    """List all listening ports with their processes."""
    return _run_diagnostic_command("lsof -nP -iTCP -sTCP:LISTEN")


def _check_network_interface(interface: str = "") -> dict[str, Any]:
    """Get network interface details."""
    if interface:
        return _run_diagnostic_command(f"ifconfig {interface}")
    return _run_diagnostic_command("ifconfig -a")


def _read_log(log_path: str, lines: int = 50) -> dict[str, Any]:
    """Read the tail of a log file."""
    # Only allow reading from safe paths
    safe_prefixes = ("/var/log/", "/tmp/", str(ROOT_DIR / "data/"))
    if not any(log_path.startswith(p) for p in safe_prefixes):
        return {"error": f"Can only read logs from: {safe_prefixes}"}
    return _run_diagnostic_command(f"tail -n {min(lines, 200)} {shlex.quote(log_path)}")


# Tool registry — maps tool names to (function, description)
INVESTIGATION_TOOLS: dict[str, dict[str, Any]] = {
    "run_command": {
        "fn": _run_diagnostic_command,
        "description": "Execute a diagnostic shell command. Only safe read-only commands are allowed (lsof, ss, netstat, ps, grep, cat, etc.). Returns stdout, stderr, and exit code.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The shell command to run"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 10, max 30)"},
            },
            "required": ["command"],
        },
    },
    "check_port": {
        "fn": _check_port,
        "description": "Check which process is using a specific port. Returns lsof output for that port.",
        "parameters": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "Port number to check"},
                "proto": {"type": "string", "description": "Protocol: tcp or udp (default tcp)"},
            },
            "required": ["port"],
        },
    },
    "check_process": {
        "fn": _check_process,
        "description": "Get detailed info about a process by its PID (user, CPU, memory, command).",
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID"},
            },
            "required": ["pid"],
        },
    },
    "check_connections": {
        "fn": _check_connections,
        "description": "Check active network connections, optionally filtered by remote IP or port.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Filter by remote IP address"},
                "port": {"type": "integer", "description": "Filter by port number"},
            },
        },
    },
    "list_listening_ports": {
        "fn": _list_listening_ports,
        "description": "List all TCP ports in LISTEN state with their owning processes.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    "check_network_interface": {
        "fn": _check_network_interface,
        "description": "Get network interface details (IP, MAC, status). Pass interface name or leave empty for all.",
        "parameters": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Interface name (e.g. en0, eth0). Empty for all."},
            },
        },
    },
    "read_log": {
        "fn": _read_log,
        "description": "Read the last N lines of a log file. Only allows /var/log/, /tmp/, and project data/ paths.",
        "parameters": {
            "type": "object",
            "properties": {
                "log_path": {"type": "string", "description": "Absolute path to the log file"},
                "lines": {"type": "integer", "description": "Number of lines to read (default 50, max 200)"},
            },
            "required": ["log_path"],
        },
    },
}


def _build_tool_declarations() -> list[genai.types.FunctionDeclaration]:
    """Build Gemini function declarations from tool registry."""
    declarations = []
    for name, tool in INVESTIGATION_TOOLS.items():
        declarations.append(genai.types.FunctionDeclaration(
            name=name,
            description=tool["description"],
            parameters=tool["parameters"],
        ))
    return declarations


def _execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a registered tool and return its result."""
    tool = INVESTIGATION_TOOLS.get(name)
    if not tool:
        return {"error": f"Unknown tool: {name}"}

    fn = tool["fn"]
    try:
        # Clamp timeout for run_command
        if name == "run_command" and "timeout" in args:
            args["timeout"] = min(int(args["timeout"]), 30)
        return fn(**args)
    except Exception as exc:
        return {"error": f"Tool execution failed: {exc}"}


# ---------------------------------------------------------------------------
# Escalation context loading
# ---------------------------------------------------------------------------

def _load_escalation_context(session_id: str) -> str | None:
    """Load verdict + sweep data for a given pipeline session ID."""
    try:
        with _connect() as conn:
            verdict_rows = conn.execute(
                "SELECT payload_json FROM scan_snapshots WHERE snapshot_type = 'verdict' ORDER BY id DESC",
            ).fetchall()

        verdict_payload = None
        for row in verdict_rows:
            payload = json.loads(row["payload_json"])
            pipeline = payload.get("pipeline", {})
            if pipeline.get("session_id") == session_id:
                verdict_payload = payload
                break

        if not verdict_payload:
            return None

        # Also load the sweep from the same cycle for raw findings
        cycle = verdict_payload.get("cycle")
        sweep_payload = None
        if cycle is not None:
            with _connect() as conn:
                sweep_rows = conn.execute(
                    "SELECT payload_json FROM scan_snapshots WHERE snapshot_type = 'sweep' ORDER BY id DESC",
                ).fetchall()
            for row in sweep_rows:
                sp = json.loads(row["payload_json"])
                if sp.get("cycle") == cycle:
                    sweep_payload = sp
                    break

        return _format_context(verdict_payload, sweep_payload)

    except (sqlite3.OperationalError, FileNotFoundError):
        return None


def _format_findings(findings: list) -> str:
    """Format findings into a readable list with ports/IPs extracted."""
    lines = []
    for i, f in enumerate(findings[:20], 1):
        if not isinstance(f, dict):
            continue
        severity = f.get("severity", "unknown")
        sig_type = f.get("signal_type", f.get("type", "unknown"))
        desc = f.get("description", "")
        indicators = f.get("indicators", {})
        ports = indicators.get("ports", []) if isinstance(indicators, dict) else []
        ips = indicators.get("remote_ips", []) if isinstance(indicators, dict) else []

        line = f"  {i}. [{severity.upper()}] {sig_type}: {desc}"
        if ports:
            line += f"\n     Ports: {ports}"
        if ips:
            line += f"\n     IPs: {ips}"
        lines.append(line)
    return "\n".join(lines) if lines else "  (none)"


def _format_context(verdict_payload: dict[str, Any], sweep_payload: dict[str, Any] | None) -> str:
    ev = verdict_payload.get("evaluation", {})
    pipeline = verdict_payload.get("pipeline", {})

    parts = [
        "# Escalation Context",
        "",
        f"Cycle: {verdict_payload.get('cycle', '?')}",
        f"Session: {pipeline.get('session_id', '?')}",
        f"Network Threat Score: {ev.get('network_threat_score', 0):.3f}",
        f"Total Findings: {ev.get('total_findings', 0)}",
        f"High/Critical: {ev.get('high_or_critical_count', 0)}",
        f"Escalation Reasons: {', '.join(ev.get('reasons', []))}",
    ]

    # Extract and format sweep findings (raw data — most detailed)
    if sweep_payload:
        network = sweep_payload.get("network", {})
        system = sweep_payload.get("system", {})
        net_findings = network.get("findings", []) if isinstance(network, dict) else []
        sys_findings = (
            system.get("analysis", {}).get("findings", [])
            if isinstance(system, dict) else []
        )

        if net_findings:
            parts.append("")
            parts.append("## Network Findings (from sweep)")
            parts.append(_format_findings(net_findings))

        if sys_findings:
            parts.append("")
            parts.append("## System Findings (from sweep)")
            parts.append(_format_findings(sys_findings))

        # Extract all flagged ports for easy reference
        all_ports: set[int] = set()
        all_ips: set[str] = set()
        for f in net_findings + sys_findings:
            if not isinstance(f, dict):
                continue
            indicators = f.get("indicators", {})
            if isinstance(indicators, dict):
                for p in indicators.get("ports", []):
                    if isinstance(p, int):
                        all_ports.add(p)
                for ip in indicators.get("remote_ips", []):
                    if isinstance(ip, str):
                        all_ips.add(ip)

        if all_ports:
            parts.append("")
            parts.append(f"## All Flagged Ports: {sorted(all_ports)}")
        if all_ips:
            parts.append(f"## All Suspicious IPs: {sorted(all_ips)}")

    # Pipeline analysis results
    parts.append("")
    parts.append("## Verdict")
    parts.append(str(pipeline.get("verdict", "No verdict"))[:3000])

    enforcement = pipeline.get("enforcement", "")
    if enforcement:
        parts.append("")
        parts.append("## Enforcement Actions")
        parts.append(str(enforcement)[:1000])

    # Anomaly analysis (parsed from JSON if possible)
    anomalies_raw = pipeline.get("analysis_anomalies", "")
    if anomalies_raw and anomalies_raw != "(not yet available)":
        parts.append("")
        parts.append("## Anomaly Analysis")
        try:
            anomalies = json.loads(anomalies_raw) if isinstance(anomalies_raw, str) else anomalies_raw
            if isinstance(anomalies, list):
                parts.append(_format_findings(anomalies))
            else:
                parts.append(str(anomalies_raw)[:2000])
        except (json.JSONDecodeError, TypeError):
            parts.append(str(anomalies_raw)[:2000])

    return "\n".join(parts)


def _get_system_prompt(context: str) -> str:
    return f"""You are the 0VRW4TCH Security Analyst. You are helping a security operator investigate an escalated security event.

You have access to diagnostic tools that let you run commands on the system being investigated. USE THEM. When the operator asks a question that requires live system data (processes, ports, connections, logs), call the appropriate tool to get the answer. Do not guess — investigate.

Available tools:
- run_command: Run any allowed diagnostic command (lsof, ss, netstat, ps, grep, cat, etc.)
- check_port: Check what process is on a specific port
- check_process: Get details about a process by PID
- check_connections: Check connections by IP or port
- list_listening_ports: List all listening services
- check_network_interface: Get interface details
- read_log: Read log file contents

Investigation workflow:
1. When asked about a finding, USE TOOLS to gather live data
2. Correlate tool results with the escalation context below
3. Give a clear, technical answer with evidence
4. When recommending actions, be specific (exact commands, risks, verification steps)

IMPORTANT CONTEXT RULES:
- The escalation context below contains the FULL details of the sweep that triggered this investigation, including specific ports, IPs, findings, and their severities.
- When the operator refers to "these ports", "the findings", "the flagged IPs", etc., they mean the ones listed in the context below.
- Always use tools to verify before answering. Never say "I would need to run..." — just run the tool.
- If the operator asks about "these ports", check ALL flagged ports from the context.

{context}"""


# ---------------------------------------------------------------------------
# Agentic chat endpoint
# ---------------------------------------------------------------------------

@router.post("/send", response_model=ChatResponse)
async def chat_send(req: ChatRequest) -> ChatResponse:
    """Send a message and get a response. The LLM can call tools in a loop."""
    session_id = req.session_id
    message = req.message.strip()

    if not message:
        return ChatResponse(reply="Please enter a message.", session_id=session_id)

    # Load escalation context on first message
    if session_id not in _conversations:
        context = _load_escalation_context(session_id)
        if not context:
            return ChatResponse(
                reply="Could not find escalation data for this session. The verdict may not exist yet.",
                session_id=session_id,
            )
        _conversations[session_id] = [{
            "role": "system",
            "context": context,
        }]

    conv = _conversations[session_id]
    context = conv[0]["context"]

    # Rebuild Gemini history from stored Content objects
    history: list[genai.types.Content] = list(conv[0].get("history", []))

    # Add new user message
    history.append(genai.types.Content(
        role="user",
        parts=[genai.types.Part(text=message)],
    ))

    # Tool declarations
    tools = [genai.types.Tool(function_declarations=_build_tool_declarations())]

    client = genai.Client()
    tool_calls_log: list[dict[str, Any]] = []

    # Agentic loop
    for iteration in range(MAX_TOOL_ITERATIONS):
        try:
            response = client.models.generate_content(
                model=DEFAULT_MODEL,
                contents=history,
                config=genai.types.GenerateContentConfig(
                    system_instruction=_get_system_prompt(context),
                    temperature=0.3,
                    max_output_tokens=4096,
                    tools=tools,
                ),
            )
        except Exception as exc:
            reply = f"Error communicating with model: {exc}"
            # Add model error reply to history
            history.append(genai.types.Content(
                role="model",
                parts=[genai.types.Part(text=reply)],
            ))
            conv[0]["history"] = history
            return ChatResponse(reply=reply, session_id=session_id, tool_calls=tool_calls_log)

        # Check if the model wants to call tools
        candidate = response.candidates[0] if response.candidates else None
        if not candidate or not candidate.content or not candidate.content.parts:
            reply = response.text or "No response generated."
            break

        function_calls = [p for p in candidate.content.parts if p.function_call]

        if not function_calls:
            # Model produced a text response — we're done
            reply = response.text or "No response generated."
            break

        # Model wants to call tools — execute them
        logger.info("chat tool_calls session=%s iteration=%d calls=%d",
                     session_id, iteration, len(function_calls))

        # Add model's function call to history
        history.append(candidate.content)

        # Execute each tool and collect responses
        function_response_parts = []
        for fc in function_calls:
            name = fc.function_call.name
            args = dict(fc.function_call.args)

            logger.info("chat executing tool=%s args=%s session=%s", name, args, session_id)
            result = _execute_tool(name, args)

            tool_calls_log.append({
                "tool": name,
                "args": args,
                "result": result,
                "result_preview": str(result)[:300],
            })

            function_response_parts.append(genai.types.Part(
                function_response=genai.types.FunctionResponse(
                    name=name,
                    response=result,
                ),
            ))

        # Add tool results to history
        history.append(genai.types.Content(
            role="user",
            parts=function_response_parts,
        ))

    else:
        reply = "Reached maximum tool call iterations. Here's what I found so far based on the tool results above."

    # Add model's final text reply to history
    history.append(genai.types.Content(
        role="model",
        parts=[genai.types.Part(text=reply)],
    ))

    # Persist the full history (Content objects) back into conversation state
    conv[0]["history"] = history

    return ChatResponse(reply=reply, session_id=session_id, tool_calls=tool_calls_log)


@router.get("/history/{session_id}")
async def chat_history(session_id: str) -> list[dict[str, str]]:
    conv = _conversations.get(session_id)
    if not conv:
        return []
    history: list[genai.types.Content] = conv[0].get("history", [])
    result = []
    for content in history:
        text_parts = [p.text for p in (content.parts or []) if p.text]
        if text_parts:
            result.append({"role": content.role, "text": " ".join(text_parts)})
    return result


@router.delete("/history/{session_id}")
async def chat_clear(session_id: str) -> dict:
    _conversations.pop(session_id, None)
    return {"status": "cleared", "session_id": session_id}
