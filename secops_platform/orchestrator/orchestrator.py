"""
0VRW4TCH SecOps Orchestrator — thin CLI entry point.

Wires the ADK runner, sends a single prompt through the SecOps pipeline,
and prints a conclusion report from session state.
"""
from __future__ import annotations
# ruff: noqa: E402

import asyncio
import logging
from pathlib import Path

from dotenv import load_dotenv
from google.genai.types import Content, Part

ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")

from config.settings import app_name
from shared.utils.logging import setup_logging
from secops_platform.orchestrator.runner_factory import (
    create_runner,
    ensure_session,
    get_user_config,
)
from secops_platform.orchestrator.cli import print_config_banner, print_conclusion


async def run() -> None:
    """Execute the SecOps pipeline end-to-end."""
    # Silence noisy loggers
    for logger_name in (
        "httpx",
        "google_adk.google.adk.models.google_llm",
        "google_adk.google.adk.sessions.database_session_service",
        "google_genai.types",
    ):
        logging.getLogger(logger_name).setLevel(logging.ERROR)

    runner, session_service = await create_runner()
    user_id, session_id, prompt = get_user_config()
    await ensure_session(session_service, user_id, session_id)

    print_config_banner(prompt=prompt, user_id=user_id, session_id=session_id)

    # Run the pipeline — per-step UI is handled by observability callbacks
    event_count = 0
    async for _event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=Content(role="user", parts=[Part(text=prompt)]),
    ):
        event_count += 1

    # Read final results from session state
    session = await session_service.get_session(
        app_name=app_name(),
        user_id=user_id,
        session_id=session_id,
    )
    state = session.state if session else {}
    print_conclusion(state, event_count=event_count)


if __name__ == "__main__":
    setup_logging()
    asyncio.run(run())
