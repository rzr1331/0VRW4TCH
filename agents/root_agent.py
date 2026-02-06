from __future__ import annotations

from google.adk.agents import Agent

from shared.adk.memory import auto_save_session_to_memory_callback, memory_tools
from shared.models.contracts import RootAgentResponse
from shared.adk.settings import default_model

from agents.perception.scope_scanner.agent import agent as scope_scanner_agent
from agents.perception.network_observer.agent import agent as network_observer_agent
from agents.perception.application_monitor.agent import agent as application_monitor_agent
from agents.perception.gatekeeper.agent import agent as gatekeeper_agent
from agents.perception.system_health.agent import agent as system_health_agent
from agents.perception.threat_intelligence.agent import agent as threat_intelligence_agent
from agents.analysis.anomaly_detector.agent import agent as anomaly_detector_agent
from agents.analysis.correlation_engine.agent import agent as correlation_engine_agent
from agents.analysis.root_cause_analyzer.agent import agent as root_cause_analyzer_agent
from agents.analysis.vulnerability_assessor.agent import agent as vulnerability_assessor_agent
from agents.analysis.pattern_learner.agent import agent as pattern_learner_agent
from agents.analysis.predictive_forecaster.agent import agent as predictive_forecaster_agent
from agents.decision.security_magistrate.agent import agent as security_magistrate_agent
from agents.decision.health_magistrate.agent import agent as health_magistrate_agent
from agents.decision.compliance_magistrate.agent import agent as compliance_magistrate_agent
from agents.decision.consensus_engine.agent import agent as consensus_engine_agent
from agents.decision.impact_assessor.agent import agent as impact_assessor_agent
from agents.decision.runbook_selector.agent import agent as runbook_selector_agent
from agents.decision.risk_evaluator.agent import agent as risk_evaluator_agent
from agents.action.security_enforcer.agent import agent as security_enforcer_agent
from agents.action.ops_remediator.agent import agent as ops_remediator_agent
from agents.action.config_manager.agent import agent as config_manager_agent
from agents.action.rollback_orchestrator.agent import agent as rollback_orchestrator_agent
from agents.action.notification_broker.agent import agent as notification_broker_agent
from agents.action.evidence_collector.agent import agent as evidence_collector_agent
from agents.learning.feedback_loop.agent import agent as feedback_loop_agent
from agents.learning.model_trainer.agent import agent as model_trainer_agent
from agents.learning.knowledge_curator.agent import agent as knowledge_curator_agent


SUB_AGENTS = [
    scope_scanner_agent,
    network_observer_agent,
    application_monitor_agent,
    gatekeeper_agent,
    system_health_agent,
    threat_intelligence_agent,
    anomaly_detector_agent,
    correlation_engine_agent,
    root_cause_analyzer_agent,
    vulnerability_assessor_agent,
    pattern_learner_agent,
    predictive_forecaster_agent,
    security_magistrate_agent,
    health_magistrate_agent,
    compliance_magistrate_agent,
    consensus_engine_agent,
    impact_assessor_agent,
    runbook_selector_agent,
    risk_evaluator_agent,
    security_enforcer_agent,
    ops_remediator_agent,
    config_manager_agent,
    rollback_orchestrator_agent,
    notification_broker_agent,
    evidence_collector_agent,
    feedback_loop_agent,
    model_trainer_agent,
    knowledge_curator_agent,
]

ROOT_INSTRUCTION = (
    "You are the root orchestrator for the autonomous security and operations platform.\n"
    "Delegation rules (delegate by exact sub-agent name):\n"
    "- scope_scanner: use for asset inventory, target discovery, and scope expansion.\n"
    "- network_observer: use for network traffic, reachability, ports, and flow anomalies.\n"
    "- application_monitor: use for app uptime, latency, error rates, and service-level symptoms.\n"
    "- gatekeeper: use for access-control, policy gating, and preflight authorization checks.\n"
    "- system_health: use for host/service/container health and monitoring coverage assessment.\n"
    "- threat_intelligence: use for IOC enrichment, external threat context, and CVE intel.\n"
    "- anomaly_detector: use when behavior deviates from baseline and anomaly scoring is needed.\n"
    "- correlation_engine: use to merge multi-source alerts/events into a single incident view.\n"
    "- root_cause_analyzer: use for causal analysis, failure chain reconstruction, and root cause.\n"
    "- vulnerability_assessor: use for vulnerability validation, severity, and remediation priority.\n"
    "- pattern_learner: use to identify recurring incident patterns and repeated failure motifs.\n"
    "- predictive_forecaster: use for incident forecasting and capacity/risk trend prediction.\n"
    "- security_magistrate: use for security decision adjudication and policy interpretation.\n"
    "- health_magistrate: use for operational health decisions and resilience tradeoffs.\n"
    "- compliance_magistrate: use for compliance impact, controls, and audit implications.\n"
    "- consensus_engine: use when magistrates disagree or a unified decision is required.\n"
    "- impact_assessor: use to estimate blast radius, business impact, and user impact.\n"
    "- runbook_selector: use to choose the best runbook for a validated incident path.\n"
    "- risk_evaluator: use for final risk scoring and urgency classification.\n"
    "- security_enforcer: use to execute approved security controls and containment actions.\n"
    "- ops_remediator: use to apply operational fixes and restore service health.\n"
    "- config_manager: use for config drift checks and safe configuration changes.\n"
    "- rollback_orchestrator: use when remediation fails and rollback coordination is needed.\n"
    "- notification_broker: use for human/system notifications, escalation, and status updates.\n"
    "- evidence_collector: use for forensic capture, evidence preservation, and audit trails.\n"
    "- feedback_loop: use to capture post-incident feedback and outcome quality signals.\n"
    "- model_trainer: use for retraining workflows when model quality/regression is identified.\n"
    "- knowledge_curator: use to update knowledge base entries and durable operating guidance.\n"
    "Delegation policy:\n"
    "- Always choose one primary sub-agent first.\n"
    "- Add supporting delegations only if additional evidence is required.\n"
    "- Require human approval before any destructive action delegation.\n"
    "- If uncertain, delegate to system_health first, then to analysis/decision agents.\n"
    "Output policy:\n"
    f"- Return JSON only and conform to RootAgentResponse fields: {', '.join(RootAgentResponse.model_fields.keys())}.\n"
    "- Include recommended_next_steps in every final response."
)

root_agent = Agent(
    name="secops_root",
    description="Root orchestrator for the autonomous SecOps platform.",
    model=default_model(),
    instruction=ROOT_INSTRUCTION,
    sub_agents=SUB_AGENTS,
    tools=memory_tools(),
    after_agent_callback=auto_save_session_to_memory_callback,
)
