from __future__ import annotations
# ruff: noqa: E402

import asyncio
import ast
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import shutil
import sys
import textwrap
from typing import Any

from dotenv import load_dotenv
from google.adk.errors.already_exists_error import AlreadyExistsError
from google.adk.runners import Runner
from google.adk.sessions import DatabaseSessionService
from google.genai.types import Content, Part

ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")

from agents.root_agent import root_agent
from shared.adk.memory import build_memory_service
from shared.adk.settings import app_name
from shared.utils.env import env_value
from shared.utils.logging import setup_logging


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE = "\033[34m"


@dataclass
class RuntimeTrace:
    total_events: int = 0
    total_steps: int = 0
    function_calls: int = 0
    function_responses: int = 0
    text_messages: int = 0
    final_text_parts: list[str] = field(default_factory=list)
    root_final_summary: str | None = None
    root_next_steps: list[str] = field(default_factory=list)
    discovered_assets: int | None = None
    anomaly_findings: int | None = None
    vulnerability_findings: int | None = None
    highest_risk_score: int | None = None
    missing_tools: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


def _color_enabled() -> bool:
    force = (env_value("ADK_FORCE_COLOR", "true") or "true").lower()
    if force in {"0", "false", "no"}:
        return False
    return sys.stdout.isatty() or force in {"1", "true", "yes"}


def _color(text: str, color_code: str) -> str:
    if not _color_enabled():
        return text
    return f"{color_code}{text}{Ansi.RESET}"


def _terminal_width() -> int:
    width = shutil.get_terminal_size((120, 20)).columns
    return max(72, min(width, 140))


def _wrap_row(label: str, value: Any, width: int) -> list[str]:
    prefix = f"{label}: "
    text_value = str(value).replace("\n", " | ")
    available = max(12, width - len(prefix))
    wrapped = textwrap.wrap(text_value, width=available) or [""]
    lines = [f"{prefix}{wrapped[0]}"]
    indent = " " * len(prefix)
    for extra in wrapped[1:]:
        lines.append(f"{indent}{extra}")
    return lines


def _print_panel(title: str, rows: list[tuple[str, Any]], color_code: str) -> None:
    max_width = _terminal_width() - 2
    prepared_lines: list[str] = []
    for label, value in rows:
        prepared_lines.extend(_wrap_row(label, value, max_width - 4))

    title_text = f" {title} "
    content_width = max(
        len(title_text),
        max((len(line) for line in prepared_lines), default=0),
        36,
    )
    content_width = min(content_width, max_width - 2)

    normalized_lines = []
    for line in prepared_lines:
        if len(line) <= content_width:
            normalized_lines.append(line)
            continue
        normalized_lines.extend(textwrap.wrap(line, width=content_width))

    left = (content_width - len(title_text)) // 2
    right = content_width - len(title_text) - left
    top = f"╭{'─' * left}{title_text}{'─' * right}╮"
    bottom = f"╰{'─' * content_width}╯"

    print("")
    print(_color(top, color_code))
    for line in normalized_lines:
        print(_color(f"│{line.ljust(content_width)}│", color_code))
    print(_color(bottom, color_code))


def _to_mapping(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump(exclude_none=True)
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            return None
    return None


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


def _print_run_configuration(prompt: str, user_id: str, session_id: str) -> None:
    sub_agents = _extract_field(root_agent, "sub_agents")
    sub_agent_count = len(sub_agents) if isinstance(sub_agents, list) else 0
    root_tools = _extract_field(root_agent, "tools")
    root_tool_count = len(root_tools) if isinstance(root_tools, list) else 0
    model = _extract_field(root_agent, "model")
    rows = [
        ("App", app_name()),
        ("Active Agent", _extract_field(root_agent, "name") or "unknown"),
        ("Model", _format_model_name(model)),
        ("Sub-Agents", sub_agent_count),
        ("Root Tools", root_tool_count),
        ("User/Session", f"{user_id} / {session_id}"),
        ("Prompt", prompt),
    ]
    _print_panel("Current Configuration", rows, Ansi.BLUE)


def _parse_json_text(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if not candidate:
        return None
    if candidate.startswith("```"):
        lines = [line for line in candidate.splitlines() if not line.strip().startswith("```")]
        candidate = "\n".join(lines).strip()
    try:
        decoded = json.loads(candidate)
        if isinstance(decoded, dict):
            return decoded
    except json.JSONDecodeError:
        pass
    try:
        decoded = ast.literal_eval(candidate)
        if isinstance(decoded, dict):
            return decoded
    except (ValueError, SyntaxError):
        return None
    return None


def _record_tool_metrics(trace: RuntimeTrace, payload: Any) -> None:
    data = _to_mapping(payload)
    if not data:
        return

    summary = data.get("summary")
    if isinstance(summary, dict):
        assets = summary.get("total_assets")
        if isinstance(assets, int):
            trace.discovered_assets = assets
        findings = summary.get("total_findings")
        if isinstance(findings, int):
            trace.vulnerability_findings = (
                findings
                if trace.vulnerability_findings is None
                else max(trace.vulnerability_findings, findings)
            )

    analysis = data.get("analysis")
    if isinstance(analysis, dict):
        analysis_summary = analysis.get("summary")
        if isinstance(analysis_summary, dict):
            total = analysis_summary.get("total")
            if isinstance(total, int):
                trace.anomaly_findings = total
        risk_scores = analysis.get("risk_scores")
        if isinstance(risk_scores, dict):
            overall = risk_scores.get("overall_risk")
            if isinstance(overall, int):
                trace.highest_risk_score = (
                    overall
                    if trace.highest_risk_score is None
                    else max(trace.highest_risk_score, overall)
                )

    missing_tools = data.get("missing_tools")
    if isinstance(missing_tools, list):
        for item in missing_tools:
            if isinstance(item, str) and item.strip():
                trace.missing_tools.add(item.strip())

    warnings = data.get("warnings")
    if isinstance(warnings, list):
        for warning in warnings[:5]:
            if isinstance(warning, str):
                trace.warnings.append(warning)

    notes = data.get("notes")
    if isinstance(notes, list):
        for note in notes[:5]:
            if isinstance(note, str) and "partial" in note.lower():
                trace.warnings.append(note)


def _extract_root_conclusion(trace: RuntimeTrace) -> None:
    for text in reversed(trace.final_text_parts):
        parsed = _parse_json_text(text)
        if not parsed:
            continue
        final_summary = parsed.get("final_summary")
        next_steps = parsed.get("recommended_next_steps")
        if isinstance(final_summary, str) and final_summary.strip():
            trace.root_final_summary = final_summary.strip()
        if isinstance(next_steps, list):
            trace.root_next_steps = [str(step) for step in next_steps if str(step).strip()]
        if trace.root_final_summary or trace.root_next_steps:
            return


def _print_conclusion(trace: RuntimeTrace) -> None:
    summary_rows: list[tuple[str, Any]] = [
        ("Result", "Execution finished"),
        ("Events", trace.total_events),
        ("Steps", trace.total_steps),
        ("Tool Calls", trace.function_calls),
        ("Tool Responses", trace.function_responses),
    ]
    if trace.discovered_assets is not None:
        summary_rows.append(("Discovered Assets", trace.discovered_assets))
    if trace.anomaly_findings is not None:
        summary_rows.append(("Anomaly Findings", trace.anomaly_findings))
    if trace.vulnerability_findings is not None:
        summary_rows.append(("Vulnerability Findings", trace.vulnerability_findings))
    if trace.highest_risk_score is not None:
        summary_rows.append(("Highest Risk Score", trace.highest_risk_score))
    if trace.missing_tools:
        summary_rows.append(("Missing Tools", ", ".join(sorted(trace.missing_tools))))

    if trace.root_final_summary:
        summary_rows.append(("Conclusion", trace.root_final_summary))
    else:
        summary_rows.append(
            ("Conclusion", "No final text summary returned; fallback conclusion generated from tool responses.")
        )
    _print_panel("Conclusion Report", summary_rows, Ansi.GREEN)

    next_steps = trace.root_next_steps or [
        "Review missing scanner tools and install those relevant to each server profile.",
        "Validate high-risk findings and exposed sensitive ports first.",
        "Re-run with ADK_PROMPT scoped to a specific service group for deeper diagnostics.",
    ]
    next_step_rows = [(f"Step {index}", step) for index, step in enumerate(next_steps, start=1)]
    _print_panel("Recommended Next Steps", next_step_rows, Ansi.CYAN)

    if trace.warnings:
        warning_rows = [(f"Warning {index}", warning) for index, warning in enumerate(trace.warnings[:6], start=1)]
        _print_panel("Warnings", warning_rows, Ansi.YELLOW)


async def demo() -> None:
    for logger_name in (
        "httpx",
        "google_adk.google.adk.models.google_llm",
        "google_adk.google.adk.sessions.database_session_service",
        "google_genai.types",
    ):
        logging.getLogger(logger_name).setLevel(logging.ERROR)

    db_url = env_value("ADK_SESSION_DB_URL")
    if not db_url:
        db_path = Path(
            env_value("ADK_SESSION_DB_PATH", "./data/adk_sessions.db")
            or "./data/adk_sessions.db"
        )
        if not db_path.is_absolute():
            db_path = ROOT_DIR / db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite+aiosqlite:///{db_path.resolve()}"
    session_service = DatabaseSessionService(db_url=db_url)

    memory_service = build_memory_service()
    runner = Runner(
        app_name=app_name(),
        agent=root_agent,
        session_service=session_service,
        memory_service=memory_service,
    )

    user_id = env_value("ADK_USER_ID", "local-user") or "local-user"
    session_id = env_value("ADK_SESSION_ID", "local-session") or "local-session"

    try:
        await session_service.create_session(
            app_name=app_name(),
            user_id=user_id,
            session_id=session_id,
        )
    except AlreadyExistsError:
        # Allow idempotent local reruns with the same session id.
        pass

    prompt = (
        env_value("ADK_PROMPT", "Run a quick health check and summarize any risks.")
        or "Run a quick health check and summarize any risks."
    )
    user_message = Content(role="user", parts=[Part(text=prompt)])
    trace = RuntimeTrace()
    _print_run_configuration(prompt=prompt, user_id=user_id, session_id=session_id)

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=user_message,
    ):
        trace.total_events += 1
        content = _extract_field(event, "content")
        parts = _extract_field(content, "parts") if content else None
        if not isinstance(parts, list):
            continue

        for part in parts:
            text = _extract_field(part, "text")
            function_call = _extract_field(part, "function_call")
            function_response = _extract_field(part, "function_response")

            if function_call:
                trace.total_steps += 1
                trace.function_calls += 1
                continue

            if function_response:
                trace.total_steps += 1
                trace.function_responses += 1
                response_payload = _extract_field(function_response, "response")
                _record_tool_metrics(trace, response_payload)
                continue

            if isinstance(text, str) and text.strip():
                trace.total_steps += 1
                trace.text_messages += 1
                clean_text = text.strip()
                if event.is_final_response():
                    trace.final_text_parts.append(clean_text)

    _extract_root_conclusion(trace)
    _print_conclusion(trace)


if __name__ == "__main__":
    setup_logging()
    asyncio.run(demo())
