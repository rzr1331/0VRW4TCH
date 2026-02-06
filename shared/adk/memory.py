from __future__ import annotations

from typing import List

from google.adk.memory import InMemoryMemoryService, VertexAiMemoryBankService
from google.adk.tools import load_memory
from google.adk.tools.preload_memory_tool import PreloadMemoryTool
from shared.utils.env import env_value


def build_memory_service():
    backend = (env_value("ADK_MEMORY_BACKEND", "in_memory") or "in_memory").lower()
    if backend in {"none", "disabled", "off"}:
        return None
    if backend in {"vertex", "vertex_ai", "memory_bank"}:
        project = env_value("GOOGLE_CLOUD_PROJECT")
        location = env_value("GOOGLE_CLOUD_LOCATION")
        agent_engine_id = env_value("ADK_AGENT_ENGINE_ID")
        if not project or not location or not agent_engine_id:
            raise ValueError(
                "Vertex AI Memory Bank requires GOOGLE_CLOUD_PROJECT, "
                "GOOGLE_CLOUD_LOCATION, and ADK_AGENT_ENGINE_ID."
            )
        return VertexAiMemoryBankService(
            project=project,
            location=location,
            agent_engine_id=agent_engine_id,
        )
    return InMemoryMemoryService()


def memory_tools() -> List:
    tools: List = [load_memory]
    if (env_value("ADK_PRELOAD_MEMORY", "") or "").lower() in {"1", "true", "yes"}:
        tools.append(PreloadMemoryTool())
    return tools


async def auto_save_session_to_memory_callback(callback_context) -> None:
    memory_service = getattr(callback_context._invocation_context, "memory_service", None)
    session = getattr(callback_context._invocation_context, "session", None)
    if memory_service is None or session is None:
        return
    await memory_service.add_session_to_memory(session)
