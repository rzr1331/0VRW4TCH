"""
CLI output for the orchestrator — startup banner and conclusion report.

Reads pipeline results from **session state** (not scraped tool responses),
which is the correct approach for the deterministic pipeline architecture.
"""
from __future__ import annotations

from typing import Any

from agents.stages import secops_pipeline
from config.settings import app_name
from shared.utils.terminal_ui import Ansi, print_panel


def _extract_field(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _format_model_name(model: Any) -> str:
    if isinstance(model, str):
        return model
    model_name = _extract_field(model, "model")
    if isinstance(model_name, str):
        return model_name
    return str(model)


def print_config_banner(prompt: str, user_id: str, session_id: str) -> None:
    """Print the startup configuration panel."""
    sub_agents = _extract_field(secops_pipeline, "sub_agents")
    sub_agent_count = len(sub_agents) if isinstance(sub_agents, list) else 0
    root_tools = _extract_field(secops_pipeline, "tools")
    root_tool_count = len(root_tools) if isinstance(root_tools, list) else 0
    model = _extract_field(secops_pipeline, "model")
    rows = [
        ("App", app_name()),
        ("Active Agent", _extract_field(secops_pipeline, "name") or "unknown"),
        ("Model", _format_model_name(model)),
        ("Sub-Agents", sub_agent_count),
        ("Root Tools", root_tool_count),
        ("User/Session", f"{user_id} / {session_id}"),
        ("Prompt", prompt),
    ]
    print_panel("Current Configuration", rows, Ansi.BLUE)


def print_conclusion(state: dict[str, Any], event_count: int = 0) -> None:
    """Print the conclusion report from pipeline session state."""
    # Read directly from pipeline state keys
    verdict = state.get("decision_verdict", "")
    enforcement = state.get("enforcement_result", "")
    perception_scope = state.get("perception_scope", "")
    perception_health = state.get("perception_health", "")
    anomalies = state.get("analysis_anomalies", "")
    vulnerabilities = state.get("analysis_vulnerabilities", "")

    # Build summary rows
    rows: list[tuple[str, Any]] = [
        ("Result", "Pipeline execution finished"),
        ("Events", event_count),
    ]

    # Add non-empty pipeline outputs
    if perception_scope and perception_scope != "(not yet available)":
        scope_preview = str(perception_scope)[:200]
        rows.append(("Scope", scope_preview))
    if perception_health and perception_health != "(not yet available)":
        health_preview = str(perception_health)[:200]
        rows.append(("Health", health_preview))
    if anomalies and anomalies != "(not yet available)":
        anomalies_preview = str(anomalies)[:200]
        rows.append(("Anomalies", anomalies_preview))
    if vulnerabilities and vulnerabilities != "(not yet available)":
        vuln_preview = str(vulnerabilities)[:200]
        rows.append(("Vulnerabilities", vuln_preview))

    # Verdict is the main output from the magistrate
    if verdict:
        rows.append(("Verdict", str(verdict)[:400]))
    else:
        rows.append(("Verdict", "No verdict produced"))

    if enforcement:
        rows.append(("Enforcement", str(enforcement)[:200]))

    print_panel("Conclusion Report", rows, Ansi.GREEN)

    # Print warnings from state if present
    warnings = state.get("warnings", [])
    if isinstance(warnings, list) and warnings:
        warning_rows = [
            (f"Warning {i}", w) for i, w in enumerate(warnings[:6], start=1)
            if isinstance(w, str)
        ]
        if warning_rows:
            print_panel("Warnings", warning_rows, Ansi.YELLOW)
