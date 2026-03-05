"""
Standalone runner for the network_monitor agent.

Usage:
    python -m scripts.run_network_monitor
    python -m scripts.run_network_monitor --prompt "Check for C2 or exfiltration activity."

Environment variables (via .env or Docker env):
    GOOGLE_API_KEY   — required when MODEL_PROVIDER=gemini
    ZAI_API_KEY      — required when MODEL_PROVIDER=zai
    MODEL_PROVIDER   — "gemini" (default) or "zai"
    DEFAULT_MODEL    — model name, e.g. gemini-2.5-flash-lite
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from dotenv import load_dotenv
load_dotenv()

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from agents.analysis.network_monitor.agent import agent as network_monitor_agent
from config.settings import app_name
from shared.utils.terminal_ui import Ansi, print_panel

APP = app_name()
USER_ID = "network-monitor"
SESSION_ID = "standalone-run"

DEFAULT_PROMPT = (
    "Perform a comprehensive network threat assessment on this host. "
    "Check for data exfiltration, C2 communications, ARP spoofing, DNS hijacking, "
    "and any suspicious outbound connections."
)


async def run(prompt: str) -> None:
    session_service = InMemorySessionService()
    runner = Runner(
        app_name=APP,
        agent=network_monitor_agent,
        session_service=session_service,
    )

    await session_service.create_session(
        app_name=APP,
        user_id=USER_ID,
        session_id=SESSION_ID,
        state={
            "perception_scope": "(not yet available)",
            "perception_health": "(not yet available)",
        },
    )

    print_panel(
        "Network Monitor — Standalone Run",
        [
            ("Agent", network_monitor_agent.name),
            ("Prompt", prompt),
        ],
        Ansi.BLUE,
    )

    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    async for _ in runner.run_async(
        user_id=USER_ID, session_id=SESSION_ID, new_message=message
    ):
        pass  # observability callbacks render progress in real-time

    session = await session_service.get_session(
        app_name=APP, user_id=USER_ID, session_id=SESSION_ID
    )
    output = session.state.get("analysis_network", "")

    print_panel(
        "Network Monitor — Output",
        [("analysis_network", output[:2000] if output else "(no output captured)")],
        Ansi.GREEN,
    )

    # Pretty-print if the output looks like JSON
    if output and output.strip().startswith("["):
        try:
            findings = json.loads(output)
            print(f"\nFindings ({len(findings)} total):")
            for i, f in enumerate(findings, 1):
                print(
                    f"  [{i}] [{f.get('signal_type','?')}] "
                    f"{f.get('description','')[:120]}"
                )
        except json.JSONDecodeError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the network_monitor agent standalone.")
    parser.add_argument(
        "--prompt", default=DEFAULT_PROMPT, help="Override the default assessment prompt."
    )
    args = parser.parse_args()
    asyncio.run(run(args.prompt))


if __name__ == "__main__":
    main()
