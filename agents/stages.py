"""
Pipeline stages for the SecOps platform.

Defines the deterministic SequentialAgent → ParallelAgent pipeline that
replaces the old LLM-delegated root agent.

Pipeline order:
  1. perception_stage  (ParallelAgent: scope_scanner ∥ system_health)
  2. analysis_stage    (ParallelAgent: anomaly_detector ∥ vulnerability_assessor)
  3. security_magistrate (Agent: decision + delegation to thought/enforcer)
"""
from __future__ import annotations

from typing import Any
from google.adk.agents import SequentialAgent, ParallelAgent

# ----- Perception layer agents -----
from agents.perception.scope_scanner.agent import agent as scope_scanner_agent
from agents.perception.system_health.agent import agent as system_health_agent

# ----- Analysis layer agents -----
from agents.analysis.anomaly_detector.agent import agent as anomaly_detector_agent
from agents.analysis.vulnerability_assessor.agent import agent as vulnerability_assessor_agent

# ----- Decision layer -----
from agents.decision.security_magistrate.agent import magistrate_agent


# =============================================================================
# State key defaults — pre-seeded so template resolution never fails
# =============================================================================
PIPELINE_STATE_DEFAULTS: dict[str, str] = {
    "perception_scope": "(not yet available)",
    "perception_health": "(not yet available)",
    "analysis_anomalies": "(not yet available)",
    "analysis_vulnerabilities": "(not yet available)",
    "decision_verdict": "",
    "enforcement_result": "",
}


def _seed_state(callback_context: Any) -> None:
    """Ensure all pipeline state keys exist with defaults before any agent runs."""
    state = getattr(callback_context, "state", None)
    if state is None:
        return
    for key, default in PIPELINE_STATE_DEFAULTS.items():
        if state.get(key) is None:
            state[key] = default


# =============================================================================
# Stage 1 — Perception (parallel)
# =============================================================================
perception_stage = ParallelAgent(
    name="perception_stage",
    sub_agents=[scope_scanner_agent, system_health_agent],
)

# =============================================================================
# Stage 2 — Analysis (parallel)
# =============================================================================
analysis_stage = ParallelAgent(
    name="analysis_stage",
    sub_agents=[anomaly_detector_agent, vulnerability_assessor_agent],
)

# =============================================================================
# Root — deterministic sequential pipeline
# =============================================================================
secops_pipeline = SequentialAgent(
    name="secops_pipeline",
    description="Deterministic SecOps pipeline: Perception → Analysis → Decision.",
    sub_agents=[
        perception_stage,
        analysis_stage,
        magistrate_agent,
    ],
    before_agent_callback=_seed_state,
)

