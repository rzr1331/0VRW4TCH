from __future__ import annotations

from google.adk.agents import Agent
from shared.adk.settings import default_model
from .prompts import DESCRIPTION, INSTRUCTION
from .tools import TOOLS


agent = Agent(
    name='root_cause_analyzer',
    description=DESCRIPTION,
    model=default_model(),
    instruction=INSTRUCTION,
    tools=TOOLS,
)
