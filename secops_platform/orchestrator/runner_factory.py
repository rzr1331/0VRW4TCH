"""
ADK runner factory — reusable wiring for Runner, SessionService, MemoryService.

Separates infrastructure setup from the CLI entry point so the same runner
can be reused from tests, web endpoints, or scheduled jobs.
"""
from __future__ import annotations

from pathlib import Path

from google.adk.errors.already_exists_error import AlreadyExistsError
from google.adk.runners import Runner
from google.adk.sessions import DatabaseSessionService

from agents.stages import secops_pipeline
from shared.adk.memory import build_memory_service
from config.settings import app_name
from shared.utils.env import env_value

ROOT_DIR = Path(__file__).resolve().parents[2]


async def create_runner() -> tuple[Runner, DatabaseSessionService]:
    """Build a fully-wired ADK Runner with session and memory services."""
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
        agent=secops_pipeline,
        session_service=session_service,
        memory_service=memory_service,
    )
    return runner, session_service


async def ensure_session(
    session_service: DatabaseSessionService,
    user_id: str,
    session_id: str,
) -> None:
    """Create a session, ignoring if it already exists (idempotent reruns)."""
    try:
        await session_service.create_session(
            app_name=app_name(),
            user_id=user_id,
            session_id=session_id,
        )
    except AlreadyExistsError:
        pass


def get_user_config() -> tuple[str, str, str]:
    """Return (user_id, session_id, prompt) from env with sensible defaults."""
    user_id = env_value("ADK_USER_ID", "local-user") or "local-user"
    session_id = env_value("ADK_SESSION_ID", "local-session") or "local-session"
    prompt = (
        env_value("ADK_PROMPT", "Run a quick health and security check and fix any issues.")
        or "Run a quick health and security check and fix any issues."
    )
    return user_id, session_id, prompt
