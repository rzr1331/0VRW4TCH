from __future__ import annotations

from google.adk.agents import Agent

from shared.adk.observability import (
    after_model_callback,
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
)
from shared.adk.memory import auto_save_session_to_memory_callback, memory_tools
from shared.models.contracts import RootAgentResponse
from shared.adk.settings import default_model

from agents.perception.scope_scanner.agent import agent as scope_scanner_agent
from agents.perception.system_health.agent import agent as system_health_agent
from agents.analysis.anomaly_detector.agent import agent as anomaly_detector_agent
from agents.analysis.vulnerability_assessor.agent import agent as vulnerability_assessor_agent


SUB_AGENTS = [
    scope_scanner_agent,
    system_health_agent,
    anomaly_detector_agent,
    vulnerability_assessor_agent,
]

ROOT_INSTRUCTION = (
    "You are the root orchestrator for the focused security and operations monitoring platform.\n"
    "Delegation rules (delegate by exact sub-agent name):\n"
    "- scope_scanner: use first for runtime asset inventory and monitoring target discovery.\n"
    "- system_health: use for host/service/container health, key metrics, and security posture checks.\n"
    "- anomaly_detector: use for anomaly scoring and evidence-backed monitoring/cybersecurity findings.\n"
    "- vulnerability_assessor: use for targeted vulnerability scans when security findings need validation.\n"
    "Delegation policy:\n"
    "- Always choose one primary sub-agent first.\n"
    "- For comprehensive scans use this order: scope_scanner -> system_health -> anomaly_detector.\n"
    "- Delegate to vulnerability_assessor when there are exposed services, suspicious processes, or high-risk anomalies.\n"
    "- Add supporting delegations only if additional evidence is required.\n"
    "Output policy:\n"
    f"- Return JSON only and conform to RootAgentResponse fields: {', '.join(RootAgentResponse.model_fields.keys())}.\n"
    "- Include recommended_next_steps in every final response."
)

from config.security_config import get_model_for_agent

root_agent = Agent(
    name="secops_root",
    description="Root orchestrator for the autonomous SecOps platform.",
    model=get_model_for_agent("root"),
    instruction=ROOT_INSTRUCTION,
    sub_agents=SUB_AGENTS,
    tools=memory_tools(),
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    on_tool_error_callback=on_tool_error_callback,
    after_model_callback=after_model_callback,
    after_agent_callback=auto_save_session_to_memory_callback,
)
