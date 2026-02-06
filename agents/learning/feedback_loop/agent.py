from __future__ import annotations

from google.adk.agents import Agent
from shared.adk.memory import auto_save_session_to_memory_callback
from shared.adk.settings import default_model
from .prompts import DESCRIPTION, INSTRUCTION
from .tools import TOOLS


agent = Agent(
    name='feedback_loop',
    description=DESCRIPTION,
    model=default_model(),
    instruction=INSTRUCTION,
    tools=TOOLS,
    after_agent_callback=auto_save_session_to_memory_callback,
)
