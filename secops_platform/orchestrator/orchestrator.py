from __future__ import annotations
# ruff: noqa: E402

import asyncio
from pathlib import Path

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


async def demo() -> None:
    db_url = env_value("ADK_SESSION_DB_URL")
    if not db_url:
        db_path = Path(env_value("ADK_SESSION_DB_PATH", "./data/adk_sessions.db") or "./data/adk_sessions.db")
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

    prompt = env_value("ADK_PROMPT", "Run a quick health check and summarize any risks.") or "Run a quick health check and summarize any risks."
    user_message = Content(role="user", parts=[Part(text=prompt)])

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=user_message,
    ):
        if event.is_final_response() and event.content and event.content.parts:
            print(event.content.parts[0].text)


if __name__ == "__main__":
    setup_logging()
    asyncio.run(demo())
